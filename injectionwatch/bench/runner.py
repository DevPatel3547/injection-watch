"""Build the IW-Bench page list deterministically and score every page with the detector.

Page kinds:
  positive        a payload planted into a carrier with one technique           -> tp / fn
  benign_planted  a benign text planted the same way (hard negative)            -> fp / tn (on the planted text)
  carrier         an unmodified real page                                        -> fp / tn (page verdict)
  discussion      a page that discusses prompt injection (OWASP LLM Top 10)      -> fp / tn (page verdict)

A positive counts as detected only when a *flagged* finding is about the planted text: the finding's payload hash
must belong to an extracted candidate that contains the planted text. Something else flagged on the same page
does not count.

Extraction results can be cached (``cache/bench/cand``) keyed by the page, the mode and a fingerprint of the
extractor source, so re-scoring after a scorer-only change does not re-parse thousands of pages.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import random
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from importlib import resources as pkg_resources
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..detector import merge_rendered, scan_candidates
from ..extract import Candidate, extract_candidates
from ..textutil import normalize_payload, payload_hash
from .carriers import Carrier, load_carriers, load_discussions
from .datasets import Item, load_benign, load_payloads
from .plant import TECHNIQUES, plant, planted_text
from .sources import cache_root

MODES = ("static", "static_css", "rendered")
BASE_URL = "https://bench.invalid/page"
QUICK_MAX_CARRIER_BYTES = 80_000


@dataclass(frozen=True)
class PageSpec:
    id: str
    kind: str                 # positive | benign_planted | carrier | discussion
    split: str
    source: str
    family: str
    technique: str
    carrier_id: str
    carrier_path: str
    text: str = ""            # planted text ("" for carrier / discussion)
    label: int = 0
    lang: str = "en"
    synthetic: bool = False
    inline_html: str = ""     # discussion pages are generated, not read from disk


def _h(*parts: str) -> int:
    return int.from_bytes(hashlib.sha256("|".join(parts).encode()).digest()[:8], "big")


def _assign(items: list[Item], per_item: int, techniques: list[str], pools: dict[str, list[Carrier]],
            kind: str, seed: str) -> list[PageSpec]:
    """Spread each family's items over the techniques round-robin (balanced, seeded) and pick carriers."""
    out: list[PageSpec] = []
    fams: dict[str, list[Item]] = {}
    for it in items:
        fams.setdefault(it.family, []).append(it)
    nt = len(techniques)
    for fam, its in sorted(fams.items()):
        its = sorted(its, key=lambda i: _h(seed, i.id))
        off = _h(seed, fam) % nt
        for idx, it in enumerate(its):
            for j in range(min(per_item, nt)):
                tech = techniques[(off + idx * per_item + j) % nt]
                pool = pools.get(it.split) or [c for v in pools.values() for c in v]
                if not pool:
                    raise ValueError("no carrier pages available")
                car = pool[_h(seed, it.id, tech) % len(pool)]
                out.append(PageSpec(f"{kind}:{it.id}:{tech}", kind, it.split, it.source, it.family, tech, car.id,
                                    car.path, it.text, it.label, it.lang, it.synthetic))
    return out


def build_specs(split: str = "all", per_payload: int = 3, per_benign: int = 2, quick: bool = False,
                seed: str = "iwbench-v1", root: Path | None = None, techniques: Iterable[str] | None = None,
                max_benign_per_split: int = 90) -> list[PageSpec]:
    techs = list(techniques or TECHNIQUES)
    payloads = load_payloads(root)
    benign = load_benign(root)
    carriers = load_carriers(root)
    discussions = load_discussions(root)
    splits = ("dev", "test") if split == "all" else (split,)
    payloads = [p for p in payloads if p.split in splits]
    # cap the (large) BIPIA benign pool per split; synthetic and PINT items are always all kept
    capped: list[Item] = []
    for sp in splits:
        bipia_fams = sorted({b.family for b in benign if b.source == "bipia"})
        for fam in bipia_fams:
            pool = sorted([b for b in benign if b.split == sp and b.family == fam], key=lambda i: _h(seed, i.id))
            capped += pool[: max_benign_per_split // len(bipia_fams)]
        capped += [b for b in benign if b.split == sp and b.source != "bipia"]
    benign = capped
    carriers = [c for c in carriers if c.split in splits]
    discussions = [d for d in discussions if d.split in splits]
    if quick:
        keep = 10
        payloads = [p for p in payloads if _h(seed, "q", p.id) % keep == 0]
        benign = [b for b in benign if _h(seed, "q", b.id) % keep == 0]
        small = [c for c in carriers if os.path.getsize(c.path) <= QUICK_MAX_CARRIER_BYTES or c.path.endswith(".gz")]
        small = [c for c in small if len(c.read()) <= QUICK_MAX_CARRIER_BYTES]
        carriers = [c for c in small if _h(seed, "q", c.id) % 4 == 0]
        discussions = discussions[::4]
        per_payload, per_benign = 1, 1
        pools = {sp: [c for c in small if c.split == sp] for sp in splits}
    else:
        pools = {sp: [c for c in carriers if c.split == sp] for sp in splits}
    specs = _assign(payloads, per_payload, techs, pools, "positive", seed)
    specs += _assign(benign, per_benign, techs, pools, "benign_planted", seed)
    specs += [PageSpec(f"carrier:{c.id}", "carrier", c.split, c.source, "unmodified", "none", c.id, c.path)
              for c in carriers]
    specs += [PageSpec(f"discussion:{d.id}", "discussion", d.split, "owasp_llm", "discussion", "none", d.id, "",
                       lang=d.lang, inline_html=d.html) for d in discussions]
    return specs


def materialise(spec: PageSpec) -> tuple[str, dict[str, str], str]:
    """-> (html, resources, expected_location)."""
    if spec.kind == "discussion":
        return spec.inline_html, {}, ""
    base = Carrier(spec.carrier_id, spec.source, spec.split, spec.carrier_path).read()
    if spec.kind == "carrier":
        return base, {}, ""
    p = plant(base, spec.text, spec.technique, spec.id)
    return p.html, p.resources, p.location


# ------------------------------------------------------------------ extraction (+ cache)

_EXTRACTOR_FILES = ("extract.py", "css.py", "textutil.py")
_RENDER_FILES = ("render.py", "js/hidden_text.js")


def extractor_fingerprint(mode: str) -> str:
    h = hashlib.sha256(mode.encode())
    pkg = pkg_resources.files("injectionwatch")
    for f in _EXTRACTOR_FILES + (_RENDER_FILES if mode == "rendered" else ()):
        try:
            h.update(pkg.joinpath(f).read_bytes())
        except FileNotFoundError:  # pragma: no cover - partial installs
            h.update(f.encode())
    return h.hexdigest()[:16]


def _cand_cache_path(mode: str, html: str, resources: dict[str, str], fp: str) -> Path:
    k = hashlib.sha256((mode + "\0" + fp + "\0" + json.dumps(resources, sort_keys=True) + "\0" + html)
                       .encode("utf-8", "surrogatepass")).hexdigest()
    return cache_root() / "cand" / mode / k[:2] / f"{k}.json.gz"


def _load_cands(p: Path) -> list[Candidate] | None:
    try:
        data = json.loads(gzip.decompress(p.read_bytes()))
    except (OSError, ValueError):
        return None
    return [Candidate(d["text"], d["location"], list(d["techniques"]), d["path"], bool(d["in_code"])) for d in data]


def _save_cands(p: Path, cands: list[Candidate]) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(f".tmp{os.getpid()}")
    tmp.write_bytes(gzip.compress(json.dumps([c.to_dict() for c in cands]).encode("utf-8", "surrogatepass"), 5))
    tmp.replace(p)


class RenderPool:
    """One Chromium for a whole run; restarted when it crashes (shared, memory-tight machines). A page that fails
    twice falls back to the static candidates and is counted in ``failures``, which the report publishes."""

    def __init__(self) -> None:
        self.renderer: Any = None
        self.failures = 0
        self.restarts = 0

    def candidates(self, html: str, resources: dict[str, str]) -> list[Candidate] | None:
        for attempt in range(2):
            try:
                if self.renderer is None:
                    self.renderer = make_renderer()
                return list(self.renderer.candidates_from_html(html, resources=resources))
            except Exception:
                self.close()
                self.restarts += 1
                if attempt:
                    self.failures += 1
        return None

    def close(self) -> None:
        if self.renderer is not None:
            try:
                self.renderer.close()
            except Exception:  # browser already gone
                pass
            self.renderer = None


def extract_page(html: str, resources: dict[str, str], mode: str, renderer: Any = None) -> list[Candidate]:
    def resolver(u: str) -> str | None:
        return resources.get(urlsplit(u).path)

    cands = extract_candidates(html, None, css_resolver=resolver if mode in ("static_css", "rendered") else None,
                               base_url=BASE_URL)
    if mode == "rendered":
        if isinstance(renderer, RenderPool):
            rc = renderer.candidates(html, resources)
            if rc is None:
                raise RenderFailed()
        else:
            rc = renderer.candidates_from_html(html, resources=resources)
        cands = merge_rendered(cands, rc)
    return cands


class RenderFailed(Exception):
    pass


def planted_key(text: str, technique: str) -> str:
    k = normalize_payload(planted_text(text, technique))
    return k[:80]


# ------------------------------------------------------------------ scoring one page

def evaluate_spec(spec: PageSpec, mode: str, scan_kwargs: dict[str, Any] | None = None, use_cache: bool = True,
                  renderer: Any = None, fp: str = "") -> dict[str, Any]:
    html, res, expected = materialise(spec)
    cands: list[Candidate] | None = None
    cpath = _cand_cache_path(mode, html, res, fp) if (use_cache and fp) else None
    if cpath is not None and cpath.exists():
        cands = _load_cands(cpath)
    render_failed = False
    if cands is None:
        try:
            cands = extract_page(html, res, mode, renderer)
            if cpath is not None:
                _save_cands(cpath, cands)
        except RenderFailed:
            render_failed = True
            cands = extract_page(html, res, "static_css")
    t0 = time.perf_counter()
    result = scan_candidates(cands, BASE_URL, **(scan_kwargs or {}))
    scan_ms = (time.perf_counter() - t0) * 1000
    flagged = [f for f in result.findings if f.flagged]
    row: dict[str, Any] = {k: v for k, v in asdict(spec).items() if k not in ("text", "carrier_path", "inline_html")}
    row.update({"mode": mode, "page_flagged": bool(flagged), "n_candidates": len(cands), "scan_ms": round(scan_ms, 2),
                "render_failed": render_failed})
    if spec.kind in ("positive", "benign_planted"):
        key = planted_key(spec.text, spec.technique)
        planted = [c for c in cands if key and key in normalize_payload(c.text)]
        hashes = {payload_hash(c.text) for c in planted}
        hit = [f for f in flagged if f.payload_hash in hashes]
        row["expected_location"] = expected
        row["extracted"] = [c.location for c in planted]
        row["hidden_extracted"] = any(c.location != "visible" for c in planted)
        row["finding_locations"] = sorted({f.location for f in hit})
        row["located"] = any(f.location == expected for f in hit)
        row["classifiers"] = sorted({f.classifier for f in hit})
        if spec.kind == "positive":
            row["outcome"] = "tp" if hit else "fn"
        else:
            row["outcome"] = "fp" if hit else "tn"
    else:
        row["outcome"] = "fp" if flagged else "tn"
        row["finding_locations"] = sorted({f.location for f in flagged})
    return row


# ------------------------------------------------------------------ whole runs

def make_renderer() -> Any:
    """render.Renderer (honours ``INJECTIONWATCH_CHROMIUM`` for the browser binary)."""
    from ..render import Renderer

    return Renderer()


_WORKER: dict[str, Any] = {}


def _worker_init(mode: str, scan_kwargs: dict[str, Any], use_cache: bool, fp: str) -> None:
    try:
        os.nice(5)
    except OSError:  # pragma: no cover
        pass
    _WORKER.update(mode=mode, scan_kwargs=scan_kwargs, use_cache=use_cache, fp=fp)


def _worker_eval(spec: PageSpec) -> dict[str, Any]:
    return evaluate_spec(spec, _WORKER["mode"], _WORKER["scan_kwargs"], _WORKER["use_cache"], None, _WORKER["fp"])


def run_specs(specs: list[PageSpec], mode: str = "static", scan_kwargs: dict[str, Any] | None = None,
              jobs: int = 1, use_cache: bool = True,
              progress: Callable[[int, int], None] | None = None) -> list[dict[str, Any]]:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    scan_kwargs = dict(scan_kwargs or {})
    fp = extractor_fingerprint(mode) if use_cache else ""
    rows: list[dict[str, Any]] = []
    if mode == "rendered" or jobs <= 1:
        rpool = RenderPool() if mode == "rendered" else None
        try:
            for i, s in enumerate(specs):
                rows.append(evaluate_spec(s, mode, scan_kwargs, use_cache, rpool, fp))
                if progress:
                    progress(i + 1, len(specs))
        finally:
            if rpool is not None:
                rpool.close()
    else:
        import multiprocessing as mp

        ctx = mp.get_context("spawn")
        with ctx.Pool(jobs, initializer=_worker_init, initargs=(mode, scan_kwargs, use_cache, fp)) as pool:
            for i, row in enumerate(pool.imap(_worker_eval, specs, chunksize=4)):
                rows.append(row)
                if progress:
                    progress(i + 1, len(specs))
    return sorted(rows, key=lambda r: r["id"])


def shuffle_for_balance(specs: list[PageSpec], seed: str = "iwbench-v1") -> list[PageSpec]:
    """Interleave big and small pages so parallel workers finish together (order does not affect results)."""
    out = list(specs)
    random.Random(seed).shuffle(out)
    return out
