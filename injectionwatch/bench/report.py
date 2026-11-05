"""Aggregate per-page bench rows into the ``reports/bench/*.json`` summary (schema: SCHEMA.md)."""
from __future__ import annotations

import json
import math
import time
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .plant import HIDDEN_TECHNIQUES, STATIC_BLIND_V03
from .sources import SOURCES

SCHEMA_VERSION = "iwbench/1"


def wilson(k: int, n: int, z: float = 1.96) -> list[float] | None:
    if n == 0:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def cell(pos: Iterable[dict[str, Any]], neg: Iterable[dict[str, Any]] = ()) -> dict[str, Any]:
    pos, neg = list(pos), list(neg)
    tp = sum(r["outcome"] == "tp" for r in pos)
    fn = len(pos) - tp
    fp = sum(r["outcome"] == "fp" for r in neg)
    tn = len(neg) - fp
    out: dict[str, Any] = {"tp": tp, "fn": fn, "fp": fp, "tn": tn,
                           "recall": round(tp / len(pos), 4) if pos else None, "recall_ci": wilson(tp, len(pos)),
                           "fp_rate": round(fp / len(neg), 4) if neg else None, "fp_ci": wilson(fp, len(neg))}
    if pos:
        ext = sum(bool(r.get("hidden_extracted")) for r in pos)
        out["extracted_hidden"] = round(ext / len(pos), 4)
        out["located"] = round(sum(bool(r.get("located")) for r in pos) / len(pos), 4)
    return out


def _group(rows: list[dict[str, Any]], key: str) -> dict[str, list[dict[str, Any]]]:
    g: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        g[str(r[key])].append(r)
    return dict(sorted(g.items()))


def summarise(rows: list[dict[str, Any]], *, detector: dict[str, Any], split: str, config: dict[str, Any],
              version: str) -> dict[str, Any]:
    pos = [r for r in rows if r["kind"] == "positive"]
    hidden = [r for r in pos if r["technique"] in HIDDEN_TECHNIQUES]
    visible = [r for r in pos if r["technique"] == "visible"]
    benign = [r for r in rows if r["kind"] == "benign_planted"]
    benign_hidden = [r for r in benign if r["technique"] in HIDDEN_TECHNIQUES]
    carriers = [r for r in rows if r["kind"] == "carrier"]
    disc = [r for r in rows if r["kind"] == "discussion"]
    used_sources = {r["source"] for r in rows} | {"readability", "scrapinghub"} & {r["source"] for r in carriers}
    sources = []
    for s in SOURCES:
        n = sum(1 for r in rows if r["source"] == s.id and r["kind"] in ("positive", "benign_planted"))
        n += sum(1 for r in rows if r["source"] == s.id and r["kind"] in ("carrier", "discussion"))
        if s.id in used_sources or n:
            sources.append({"id": s.id, "repo": s.repo, "commit": s.commit, "license": s.license, "n": n,
                            "role": s.role})
    by_tech: dict[str, Any] = {}
    pos_t, ben_t = _group(pos, "technique"), _group(benign, "technique")
    for t in sorted(set(pos_t) | set(ben_t)):
        by_tech[t] = cell(pos_t.get(t, []), ben_t.get(t, []))
    by_src: dict[str, Any] = {}
    for sid, rs in _group(hidden, "source").items():
        by_src[sid] = cell(rs)
    by_fam: dict[str, Any] = {}
    for f, rs in _group(hidden, "family").items():
        by_fam[f] = cell(rs)
    for f, rs in _group(benign_hidden, "family").items():
        by_fam.setdefault(f, {}).update({k: v for k, v in cell([], rs).items() if k.startswith(("fp", "tn"))})
    by_lang: dict[str, Any] = {}
    for lang in sorted({r["lang"] for r in hidden + disc}):
        by_lang[lang] = cell([r for r in hidden if r["lang"] == lang], [r for r in disc if r["lang"] == lang])
    static_blind = [r for r in hidden if r["technique"] in STATIC_BLIND_V03]
    covered = [r for r in hidden if r["technique"] not in STATIC_BLIND_V03]
    return {
        "schema": SCHEMA_VERSION,
        "version": version,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "detector": detector,
        "split": split,
        "config": config,
        "synthetic_planting": True,
        "sources": sources,
        "carriers": {"n": len({r["carrier_id"] for r in rows if r["kind"] != "discussion"}),
                     "sources": sorted({r["source"] for r in carriers}) or ["readability", "scrapinghub"]},
        "counts": {"pages": len(rows), "positive_hidden": len(hidden), "positive_visible": len(visible),
                   "benign_planted": len(benign), "carriers_unmodified": len(carriers), "discussion_pages": len(disc)},
        # headline: hidden-technique payloads vs unmodified real pages
        "overall": cell(hidden, carriers),
        "hidden_covered_techniques": cell(covered),
        "hidden_static_blind_techniques": cell(static_blind),
        "visible_control": cell(visible),
        "benign_hidden_text": cell([], benign_hidden),
        "discussion_pages": cell([], disc),
        "by_technique": by_tech,
        "by_payload_source": by_src,
        "by_payload_family": by_fam,
        "by_language": by_lang,
        "timing": {"scan_ms_mean": round(sum(r["scan_ms"] for r in rows) / max(1, len(rows)), 2)},
    }


def write_summary(summary: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=1, sort_keys=False) + "\n", "utf-8")


def update_index(out_dir: Path) -> Path:
    items = []
    for p in sorted(out_dir.glob("*.json")):
        if p.name == "index.json":
            continue
        try:
            d = json.loads(p.read_text("utf-8"))
        except ValueError:
            continue
        if d.get("schema") != SCHEMA_VERSION:
            continue
        o = d.get("overall", {})
        items.append({"file": p.name, "version": d.get("version"), "split": d.get("split"),
                      "detector": d.get("detector"), "generated_at": d.get("generated_at"),
                      "recall": o.get("recall"), "fp_rate": o.get("fp_rate"),
                      "quick": bool(d.get("config", {}).get("quick"))})
    idx = out_dir / "index.json"
    idx.write_text(json.dumps({"schema": SCHEMA_VERSION, "runs": items}, indent=1) + "\n", "utf-8")
    return idx


def _pct(v: float | None) -> str:
    return "n/a" if v is None else f"{100 * v:.1f}%"


def _ci(ci: list[float] | None) -> str:
    return "" if not ci else f" [{100 * ci[0]:.1f}, {100 * ci[1]:.1f}]"


def markdown(summary: dict[str, Any]) -> str:
    d = summary["detector"]
    lines = [f"### IW-Bench {summary['version']} - {d.get('name')} mode={d.get('mode')} ml={d.get('ml')} "
             f"split={summary['split']}", ""]
    o = summary["overall"]
    lines += [f"* hidden-payload recall: **{_pct(o['recall'])}**{_ci(o['recall_ci'])} ({o['tp']}/{o['tp'] + o['fn']})",
              f"* FP rate, unmodified real pages: **{_pct(o['fp_rate'])}**{_ci(o['fp_ci'])} "
              f"({o['fp']}/{o['fp'] + o['tn']})"]
    b, ds, v = summary["benign_hidden_text"], summary["discussion_pages"], summary["visible_control"]
    lines += [f"* FP rate, benign hidden text planted: {_pct(b['fp_rate'])}{_ci(b['fp_ci'])} "
              f"({b['fp']}/{b['fp'] + b['tn']})",
              f"* FP rate, pages discussing prompt injection: {_pct(ds['fp_rate'])} ({ds['fp']}/{ds['fp'] + ds['tn']})",
              f"* visible-text control recall: {_pct(v['recall'])} ({v['tp']}/{v['tp'] + v['fn']})", ""]
    lines += ["| technique | recall | 95% CI | n | benign FP |", "|---|---:|---:|---:|---:|"]
    for t, c in summary["by_technique"].items():
        n = c["tp"] + c["fn"]
        lines.append(f"| {t} | {_pct(c['recall'])} | {_ci(c['recall_ci']).strip()} | {n} | "
                     f"{c['fp']}/{c['fp'] + c['tn']} |")
    lines += ["", "| payload family (hidden) | recall | 95% CI | n |", "|---|---:|---:|---:|"]
    for f, c in summary["by_payload_family"].items():
        if c.get("recall") is None:
            continue
        lines.append(f"| {f} | {_pct(c['recall'])} | {_ci(c['recall_ci']).strip()} | {c['tp'] + c['fn']} |")
    return "\n".join(lines)
