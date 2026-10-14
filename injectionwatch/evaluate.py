"""Precision/recall over labeled fixture corpora.

Page-level scoring:
  TP  expected flag AND a flagged finding exists at the expected location
  FN  expected flag but no flagged finding at that location
  FP  expected clean but page verdict == flagged
  TN  expected clean and page verdict == clean

Modes:
  static      HTML only; external stylesheets unavailable (what a WARC scan sees)
  static_css  static, plus the page's external stylesheets supplied from the fixture's assets/
  rendered    static + Playwright/Chromium rendered pass, assets served offline

Corpora (see README "Evaluation"):
  fixtures/             dev v1 (rules were written against it)
  fixtures_dev/         dev v2 (paraphrase / multilingual / CSS / educational context; tuned against)
  fixtures_holdout/     held-out v1 - BURNED: its failures were studied while tuning v0.2
  fixtures_holdout_v2/  held-out v2 - written and frozen (MANIFEST.sha256) BEFORE v0.2 tuning
  fixtures_realweb/     real-web regression (v0.3): anonymised true positives and false-positive templates from
                        the first Common Crawl scan. IN-SAMPLE for v0.3 - the v0.3 fixes were written against it
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .detector import scan_html

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FIXTURES = ROOT / "fixtures"
CORPORA = {
    "dev_v1": ROOT / "fixtures",
    "dev_v2": ROOT / "fixtures_dev",
    "holdout_v1_burned": ROOT / "fixtures_holdout",
    "holdout_v2": ROOT / "fixtures_holdout_v2",
    "realweb_regression": ROOT / "fixtures_realweb",
}
MODES = ("static", "static_css", "rendered")


def _empty() -> dict[str, int]:
    return {"tp": 0, "fp": 0, "fn": 0, "tn": 0}


def _assets(fixtures_dir: Path, lab: dict[str, Any]) -> dict[str, str]:
    out = {}
    for url_path, fname in (lab.get("assets") or {}).items():
        out[url_path] = (fixtures_dir / "assets" / fname).read_text("utf-8")
    return out


def run_eval(fixtures_dir: Path | str = DEFAULT_FIXTURES, rendered: bool = False, classifier: Any = None,
             mode: str | None = None, renderer: Any = None) -> dict[str, Any]:
    fixtures_dir = Path(fixtures_dir)
    mode = mode or ("rendered" if rendered else "static")
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    labels = json.loads((fixtures_dir / "labels.json").read_text("utf-8"))
    per_tech: dict[str, dict[str, int]] = defaultdict(_empty)
    per_lang: dict[str, dict[str, int]] = defaultdict(_empty)
    details = []
    own_renderer = False
    if mode == "rendered" and renderer is None:
        from .render import Renderer

        renderer = Renderer()
        own_renderer = True
    try:
        for fname, lab in sorted(labels.items()):
            html = (fixtures_dir / "pages" / fname).read_text("utf-8")
            assets = _assets(fixtures_dir, lab)

            def resolver(u: str, _a: dict[str, str] = assets) -> str | None:
                return _a.get(urlsplit(u).path) or _a.get(u)

            rc = renderer.candidates_from_html(html, resources=assets) if mode == "rendered" else None
            res = scan_html(html, url=f"https://fixture.invalid/{fname}", headers=lab.get("headers"),
                            classifier=classifier, rendered_candidates=rc,
                            css_resolver=resolver if mode in ("static_css", "rendered") else None)
            flagged = [f for f in res.findings if f.flagged]
            if lab["expect_flag"]:
                hit = any(f.location == lab["expect_location"] for f in flagged)
                outcome = "tp" if hit else "fn"
            else:
                outcome = "fp" if flagged else "tn"
            per_tech[lab["technique"]][outcome] += 1
            per_lang[lab.get("lang", "en")][outcome] += 1
            details.append({"fixture": fname, "technique": lab["technique"], "lang": lab.get("lang", "en"),
                            "expected": lab["expect_flag"], "outcome": outcome, "verdict": res.verdict,
                            "findings": [(f.location, f.category, f.intent, f.confidence) for f in res.findings]})
    finally:
        if own_renderer and renderer is not None:
            renderer.close()
    total = _empty()
    for v in per_tech.values():
        for k in total:
            total[k] += v[k]
    return {"mode": mode, "corpus": str(fixtures_dir.name), "per_technique": dict(per_tech),
            "per_lang": dict(per_lang), "total": total, "metrics": metrics(total), "details": details}


def metrics(c: dict[str, int]) -> dict[str, float | None]:
    p = c["tp"] / (c["tp"] + c["fp"]) if (c["tp"] + c["fp"]) else None
    r = c["tp"] / (c["tp"] + c["fn"]) if (c["tp"] + c["fn"]) else None
    f1 = 2 * p * r / (p + r) if p and r else None
    return {"precision": p, "recall": r, "f1": f1}


def _pr(c: dict[str, int]) -> tuple[str, str]:
    m = metrics(c)
    p, r = m["precision"], m["recall"]
    return ("n/a" if p is None else f"{p:.2f}", "n/a" if r is None else f"{r:.2f}")


def format_table(result: dict[str, Any], by: str = "per_technique") -> str:
    head = "technique" if by == "per_technique" else "language"
    lines = [f"{head:<20} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3}  {'precision':>9} {'recall':>6}", "-" * 56]
    for key, c in sorted(result[by].items()):
        p, r = _pr(c)
        lines.append(f"{key:<20} {c['tp']:>3} {c['fp']:>3} {c['fn']:>3} {c['tn']:>3}  {p:>9} {r:>6}")
    lines.append("-" * 56)
    c = result["total"]
    p, r = _pr(c)
    lines.append(f"{'TOTAL':<20} {c['tp']:>3} {c['fp']:>3} {c['fn']:>3} {c['tn']:>3}  {p:>9} {r:>6}")
    misses = [d for d in result["details"] if d["outcome"] in ("fp", "fn")]
    if misses:
        lines.append("\nErrors:")
        for d in misses:
            lines.append(f"  {d['outcome'].upper()} {d['fixture']} verdict={d['verdict']} findings={d['findings']}")
    return "\n".join(lines)


def run_matrix(corpora: dict[str, Path] | None = None, modes: tuple[str, ...] = MODES,
               classifier: Any = None) -> dict[str, dict[str, Any]]:
    """Evaluate every corpus in every mode (one shared browser for the rendered mode)."""
    corpora = corpora or {k: v for k, v in CORPORA.items() if (v / "labels.json").exists()}
    out: dict[str, dict[str, Any]] = {}
    renderer = None
    try:
        if "rendered" in modes:
            from .render import Renderer

            renderer = Renderer()
        for name, path in corpora.items():
            out[name] = {}
            for mode in modes:
                out[name][mode] = run_eval(path, mode=mode, classifier=classifier, renderer=renderer)
    finally:
        if renderer is not None:
            renderer.close()
    return out


def summary_table(matrix: dict[str, dict[str, Any]]) -> str:
    lines = ["| corpus | mode | TP | FP | FN | TN | precision | recall |", "|---|---|---:|---:|---:|---:|---:|---:|"]
    for corpus, modes in matrix.items():
        for mode, r in modes.items():
            c = r["total"]
            p, rc = _pr(c)
            lines.append(f"| {corpus} | {mode} | {c['tp']} | {c['fp']} | {c['fn']} | {c['tn']} | {p} | {rc} |")
    return "\n".join(lines)
