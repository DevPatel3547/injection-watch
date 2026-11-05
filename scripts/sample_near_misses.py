"""Near-miss sampling (for a real-web recall estimate) and a public-safe export of scan output.

Why: precision alone says nothing about what the detector misses. To estimate recall on real pages we label a
**stratified uniform random sample of the candidates the detector did NOT flag**, then scale each stratum's
injection rate by its population (``scripts/label_stats.py --near-misses``).

Population (one stratum per extraction location: comment, hidden_css, meta, attribute, ...): every non-visible
candidate of >= ``MIN_CHARS`` characters that did not produce a finding (on any scanned page). Visible text and
candidates that produced a finding are excluded.

Sampling is bottom-k: each candidate gets ``key = sha256(seed | page_key | candidate index)``; the sample of a
stratum is the k candidates with the smallest keys. That is an exact uniform sample without replacement, it is
deterministic for a seed, and it merges across worker processes (each page returns only its k smallest keys per
stratum).

Usage (stand-alone, on local WARC files or a directory of saved .html/.html.gz pages):

    python scripts/sample_near_misses.py --warc a.warc.gz b.warc.gz --k 25 --out out/nm
    python scripts/sample_near_misses.py --html-dir saved_pages/ --k 25 --out out/nm
    python scripts/sample_near_misses.py --public-out out/ public/ [--redact-hosts private/redact.json]

``scripts/scan_cc.py --near-miss-sample K`` does the same during a Common Crawl scan.

Outputs: ``near_misses.jsonl`` (one sampled candidate per line, ``nm_id`` is what labels refer to) and
``near_miss_strata.json`` (population and sample size per stratum). Both may contain WARC locators and real URLs:
**never commit them directly**; commit only what ``--public-out`` writes.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import heapq
import json
import os
import re
from collections import Counter
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

MIN_CHARS = 20
TEXT_CAP = 600

# ------------------------------------------------------------------ sampling


def nm_key(seed: int | str, page_key: str, idx: int) -> str:
    return hashlib.sha256(f"{seed}|{page_key}|{idx}".encode()).hexdigest()


def page_near_misses(cands: list[Any], fired_hashes: set[str], page_key: str, seed: int | str, k: int,
                     min_chars: int = MIN_CHARS) -> tuple[dict[str, int], list[dict[str, Any]]]:
    """-> (population count per stratum, this page's k smallest-key candidates per stratum)."""
    from injectionwatch.scorer import score_text
    from injectionwatch.textutil import clean_for_scoring, payload_hash

    pop: Counter[str] = Counter()
    per: dict[str, list[tuple[int, int, Any]]] = {}   # max-heap of the k smallest keys: (-key, idx, cand)
    for i, c in enumerate(cands):
        if c.location == "visible":
            continue
        text = clean_for_scoring(c.text)
        if len(text) < min_chars or payload_hash(c.text) in fired_hashes:
            continue
        pop[c.location] += 1
        kv = int(nm_key(seed, page_key, i), 16)
        heap = per.setdefault(c.location, [])
        if len(heap) < k:
            heapq.heappush(heap, (-kv, i, c))
        elif kv < -heap[0][0]:
            heapq.heapreplace(heap, (-kv, i, c))
    out: list[dict[str, Any]] = []
    for loc, heap in per.items():
        for negk, i, c in sorted(heap, reverse=True):
            sr = score_text(c.text, c.location, c.in_code, c.techniques)
            out.append({"key": f"{-negk:064x}", "stratum": loc, "cand_index": i, "location": c.location,
                        "techniques": list(c.techniques), "path": c.path, "text": c.text[:TEXT_CAP],
                        "payload_hash": payload_hash(c.text), "score": sr.score,
                        "rules": [h.rule_id for h in sr.hits]})
    return dict(pop), out


class NearMissSampler:
    """Merges per-page results into a global bottom-k sample per stratum."""

    def __init__(self, k: int, seed: int | str):
        self.k, self.seed = k, seed
        self.population: Counter[str] = Counter()
        self.pages = 0
        self._heaps: dict[str, list[tuple[int, int, dict[str, Any]]]] = {}
        self._n = 0

    def add(self, page: dict[str, Any], pop: dict[str, int], sample: Iterable[dict[str, Any]]) -> None:
        """``page``: page-level fields kept with every sampled candidate (url, page_id, warc, offset...)."""
        self.pages += 1
        self.population.update(pop)
        for s in sample:
            self._n += 1
            kv = int(s["key"], 16)
            heap = self._heaps.setdefault(s["stratum"], [])
            entry = (-kv, self._n, {**page, **s})
            if len(heap) < self.k:
                heapq.heappush(heap, entry)
            elif kv < -heap[0][0]:
                heapq.heapreplace(heap, entry)

    def rows(self) -> list[dict[str, Any]]:
        out = []
        for stratum in sorted(self._heaps):
            rows = sorted((r for _, _, r in self._heaps[stratum]), key=lambda r: r["key"])
            out.extend(rows)
        for i, r in enumerate(out):
            r["nm_id"] = f"nm{i:05d}"
        return out

    def strata(self) -> dict[str, Any]:
        sampled = Counter(s for s, h in self._heaps.items() for _ in h)
        return {"seed": self.seed, "k": self.k, "min_chars": MIN_CHARS, "pages": self.pages,
                "definition": "non-visible candidates >= min_chars chars that produced no finding, per location",
                "strata": {s: {"population": self.population[s], "sampled": sampled.get(s, 0)}
                           for s in sorted(self.population)}}

    def write(self, out_dir: str | Path) -> tuple[Path, Path]:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        rows_p, strata_p = out / "near_misses.jsonl", out / "near_miss_strata.json"
        with rows_p.open("w", encoding="utf-8") as fh:
            for r in self.rows():
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        strata_p.write_text(json.dumps(self.strata(), indent=2) + "\n", "utf-8")
        return rows_p, strata_p


# ------------------------------------------------------------------ public-safe export

LOCATOR_KEYS = {"warc", "offset", "warc_offset", "warc_record_id", "warc_filename", "warc_path", "html_saved"}
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
_PHONE = re.compile(r"(?<![\w.])\+?\d[\d \-().]{7,}\d(?![\w])")
_TS = re.compile(r"^(\d{4}-\d{2}-\d{2})T[\d:.]+Z?$")
TEXT_KEYS = ("hidden_text", "payload_excerpt", "text")


def mask_contacts(s: str) -> str:
    s = _EMAIL.sub(lambda m: m.group(0) if m.group(0).endswith(".example") else "[email]", s)
    return _PHONE.sub("[phone]", s)


def load_redactions(path: str | Path | None) -> dict[str, str]:
    """Private file (keep it OUTSIDE the repo): JSON {"real.host": "redacted-site-N.example"}."""
    if not path:
        return {}
    data = json.loads(Path(path).read_text("utf-8"))
    return {str(k).lower(): str(v) for k, v in data.items()}


class PublicExporter:
    """Reduce private scan rows to what may be committed (see tests/test_redaction.py)."""

    def __init__(self, redactions: dict[str, str] | None = None):
        self.redactions = redactions or {}
        self.page_ids: dict[str, str] = {}
        self.paths: dict[str, int] = {}

    def page_id(self, private_id: str) -> str:
        if private_id not in self.page_ids:
            self.page_ids[private_id] = f"p{len(self.page_ids) + 1:04d}"
        return self.page_ids[private_id]

    def _host(self, url: str) -> str:
        m = re.match(r"^[a-z]+://([^/:?#]+)", url or "", re.I)
        return m.group(1).lower() if m else ""

    def row(self, r: dict[str, Any]) -> dict[str, Any]:
        out = {k: v for k, v in r.items() if k not in LOCATOR_KEYS and k != "key"}
        if "page_id" in out:
            out["page_id"] = self.page_id(str(out["page_id"]))
        for k in ("warc_date", "captured_at"):
            if isinstance(out.get(k), str) and (m := _TS.match(out[k])):
                out[k] = m.group(1)
        host = self._host(str(out.get("url", "")))
        red = self.redactions.get(host)
        if red:
            key = str(out.get("url"))
            self.paths.setdefault(key, len(self.paths) + 1)
            out["url"] = f"https://{red}/redacted-path-{self.paths[key]}"
            if isinstance(out.get("path"), str):
                out["path"] = re.match(r"[a-z][a-z0-9-]*", out["path"].lower()).group(0) \
                    if re.match(r"[a-z]", out["path"].lower()) else "div"
            for k in TEXT_KEYS:
                if isinstance(out.get(k), str):
                    out[k] = out[k][:30].rstrip() + " [passage omitted]"
            if isinstance(out.get("reasons"), list):
                out["reasons"] = [re.sub(r"matched '.*?'", "matched [omitted]", x) for x in out["reasons"]]
        for k in TEXT_KEYS:
            if isinstance(out.get(k), str):
                out[k] = mask_contacts(out[k])
        if isinstance(out.get("reasons"), list):
            out["reasons"] = [mask_contacts(x) for x in out["reasons"]]
        return out

    def stats(self, st: dict[str, Any]) -> dict[str, Any]:
        out = dict(st)
        for k in ("warcs_selected", "warcs_scanned"):
            if isinstance(out.get(k), list):
                lst = sorted(out[k])
                out[k] = {"count": len(lst), "sha256_of_sorted_list": hashlib.sha256("\n".join(lst).encode())
                          .hexdigest()}
        if isinstance(out.get("per_warc"), list):
            out["per_warc"] = [{**{k: v for k, v in w.items() if k != "warc"}, "warc_index": i}
                               for i, w in enumerate(out["per_warc"])]
        out.pop("errors_sample", None)  # carries URLs
        return out


def _read_jsonl(p: Path) -> Iterator[dict[str, Any]]:
    with p.open(encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)


def public_out(src: str | Path, dst: str | Path, redact_hosts: str | Path | None = None) -> list[Path]:
    """Write public-safe copies of hits.jsonl / scan_stats.json / near_misses.jsonl / near_miss_strata.json /
    labels*.jsonl found in ``src``. Never copies hit_pages/ or selected_warcs.txt."""
    src, dst = Path(src), Path(dst)
    if src.resolve() == dst.resolve():
        raise ValueError("--public-out must write to a different directory")
    dst.mkdir(parents=True, exist_ok=True)
    ex = PublicExporter(load_redactions(redact_hosts))
    written = []
    for name in ("hits.jsonl", "near_misses.jsonl", *sorted(p.name for p in src.glob("labels*.jsonl")),
                 *sorted(p.name for p in src.glob("near_miss_labels*.jsonl"))):
        p = src / name
        if not p.exists():
            continue
        with (dst / name).open("w", encoding="utf-8") as fh:
            for r in _read_jsonl(p):
                fh.write(json.dumps(ex.row(r), ensure_ascii=False) + "\n")
        written.append(dst / name)
    for name in ("scan_stats.json", "near_miss_strata.json"):
        p = src / name
        if p.exists():
            (dst / name).write_text(json.dumps(ex.stats(json.loads(p.read_text("utf-8"))), indent=2) + "\n",
                                    "utf-8")
            written.append(dst / name)
    return written


# ------------------------------------------------------------------ stand-alone scanning


def _iter_html_dir(d: Path) -> Iterator[tuple[str, str, dict[str, Any]]]:
    for p in sorted(d.rglob("*")):
        if p.suffix == ".gz" and p.name.endswith(".html.gz"):
            raw = gzip.decompress(p.read_bytes())
        elif p.suffix in (".html", ".htm"):
            raw = p.read_bytes()
        else:
            continue
        rel = p.relative_to(d).as_posix()
        yield rel, raw.decode("utf-8", "replace"), {"url": f"file:///{rel}", "page_id": rel}


def _iter_warcs(paths: list[str]) -> Iterator[tuple[str, str, dict[str, Any]]]:
    from warcio.archiveiterator import ArchiveIterator

    for wp in paths:
        name = os.path.basename(wp)
        with open(wp, "rb") as fh:
            it = ArchiveIterator(fh)
            for rec in it:
                if rec.rec_type != "response" or rec.http_headers is None:
                    continue
                if "html" not in (rec.http_headers.get_header("Content-Type") or "").lower():
                    continue
                if (rec.http_headers.get_statuscode() or "") != "200":
                    continue
                body = rec.content_stream().read()
                off = it.get_record_offset()
                url = rec.rec_headers.get_header("WARC-Target-URI") or ""
                pid = hashlib.sha1(f"{name}:{off}".encode()).hexdigest()[:16]
                yield pid, body.decode("utf-8", "replace"), {"url": url, "page_id": pid, "warc": name, "offset": off}


def sample_pages(pages: Iterable[tuple[str, str, dict[str, Any]]], k: int, seed: int | str) -> NearMissSampler:
    from injectionwatch.detector import scan_candidates
    from injectionwatch.extract import extract_candidates

    s = NearMissSampler(k, seed)
    for key, html, meta in pages:
        cands = extract_candidates(html)
        res = scan_candidates(cands, meta.get("url", ""))
        fired = {f.payload_hash for f in res.findings}
        pop, sample = page_near_misses(cands, fired, key, seed, k)
        s.add(meta, pop, sample)
    return s


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--warc", nargs="+", help="local WARC files")
    src.add_argument("--html-dir", type=Path, help="directory of .html / .html.gz pages")
    src.add_argument("--public-out", nargs=2, metavar=("SRC_DIR", "DST_DIR"), help="write public-safe copies")
    ap.add_argument("--redact-hosts", help="private JSON {host: redacted-site-N.example} (keep outside the repo)")
    ap.add_argument("--k", type=int, default=25, help="sample size per location stratum (default 25)")
    ap.add_argument("--seed", default="20261105")
    ap.add_argument("--out", type=Path, default=Path("out/near_misses"))
    a = ap.parse_args(argv)
    if a.public_out:
        for p in public_out(a.public_out[0], a.public_out[1], a.redact_hosts):
            print(f"wrote {p}")
        return 0
    pages = _iter_warcs(a.warc) if a.warc else _iter_html_dir(a.html_dir)
    s = sample_pages(pages, a.k, a.seed)
    rows_p, strata_p = s.write(a.out)
    st = s.strata()
    print(f"{st['pages']} pages; sampled {sum(v['sampled'] for v in st['strata'].values())} near-misses from "
          f"{sum(v['population'] for v in st['strata'].values())} -> {rows_p}, {strata_p}")
    print("label with scripts/label_ui/index.html, then: python scripts/label_stats.py ... --near-misses "
          f"{rows_p} --near-miss-strata {strata_p} --near-miss-labels <labels.jsonl>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
