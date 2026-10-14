"""Precision and prevalence from a hand-labelled sample of real-web hits (Wilson 95% intervals).

Inputs
    hits.jsonl        one detector finding per line (scripts/scan_cc.py output); line number = hit index
    labels.jsonl      one line per labelled hit: {"hit": <index>, "label": "true_injection" | "benign",
                      "severity": <true severity if true_injection>, "note": "..."}
                      For ai_optout hits the label is "optout_ok" (a genuine opt-out signal) or "optout_wrong".
    scan_stats.json   pages_scanned etc. (scripts/scan_cc.py output)

Precision is per finding: share of labelled detector findings a human judged to be text that instructs an AI
system. If only a random subset of a detector-severity stratum was labelled, page prevalence for that stratum
is scaled by (stratum size / labelled in stratum); the report says when that happened.

    python scripts/label_stats.py --hits out/hits.jsonl --labels out/labels.jsonl --stats out/scan_stats.json
"""
from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict
from typing import Any

SEVERITIES = ["ai_optout", "defensive", "promotional", "manipulative", "malicious"]


def wilson(k: float, n: float, z: float = 1.959964) -> tuple[float, float]:
    if n <= 0:
        return (0.0, 1.0)
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (max(0.0, centre - half), min(1.0, centre + half))


def prop(k: float, n: float, scale: float = 1.0) -> dict[str, Any]:
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "p": round(k / n * scale, 4) if n else None,
            "ci95": [round(lo * scale, 4), round(hi * scale, 4)]}


def compute(hits: list[dict[str, Any]], labels: list[dict[str, Any]], stats: dict[str, Any]) -> dict[str, Any]:
    pages = int(stats["totals"]["pages_scanned"])
    lab = {int(x["hit"]): x for x in labels}
    strata = Counter(h["severity"] for h in hits)
    labelled = Counter(hits[i]["severity"] for i in lab)
    out: dict[str, Any] = {
        "pages_scanned": pages, "findings": len(hits),
        "pages_with_finding": len({h["page_id"] for h in hits}),
        "detector_findings_by_severity": dict(strata),
        "detector_pages_by_severity": {s: len({h["page_id"] for h in hits if h["severity"] == s}) for s in strata},
        "labelled_by_detector_severity": dict(labelled),
    }
    # precision (injection-like hits only; ai_optout handled separately)
    inj = [i for i in lab if hits[i]["severity"] != "ai_optout"]
    tp = [i for i in inj if lab[i]["label"] == "true_injection"]
    out["precision_overall"] = prop(len(tp), len(inj))
    flagged = [i for i in inj if hits[i]["severity"] in ("manipulative", "malicious")]
    out["precision_flagged"] = prop(sum(lab[i]["label"] == "true_injection" for i in flagged), len(flagged))
    out["precision_by_detector_severity"] = {
        s: prop(sum(lab[i]["label"] == "true_injection" for i in inj if hits[i]["severity"] == s),
                sum(1 for i in inj if hits[i]["severity"] == s))
        for s in SEVERITIES[1:] if any(hits[i]["severity"] == s for i in inj)}
    exact = [i for i in tp if lab[i].get("severity") == hits[i]["severity"]]
    out["severity_agreement_among_tp"] = prop(len(exact), len(tp))
    conf: dict[str, Counter[str]] = defaultdict(Counter)
    for i in inj:
        conf[hits[i]["severity"]][lab[i].get("severity") if lab[i]["label"] == "true_injection" else "benign"] += 1
    out["confusion_detector_vs_label"] = {k: dict(v) for k, v in conf.items()}
    # unique payloads / hosts among TPs
    out["tp_unique_hosts"] = len({hits[i]["url"].split("/")[2] for i in tp})
    out["tp_unique_payloads"] = len({hits[i]["payload_hash"] for i in tp})
    # prevalence per 100k pages by labelled severity (pages with >= 1 TP of that severity)
    prev: dict[str, Any] = {}
    scaled = False
    for s in SEVERITIES[1:]:
        pg_by_stratum: dict[str, set[str]] = defaultdict(set)
        for i in tp:
            if lab[i].get("severity") == s:
                pg_by_stratum[hits[i]["severity"]].add(hits[i]["page_id"])
        est = 0.0
        for st, pgs in pg_by_stratum.items():
            f = strata[st] / labelled[st] if labelled[st] else 1.0
            scaled |= f > 1.0
            est += len(pgs) * f
        prev[s] = prop(est, pages, 1e5)
    any_pages: set[str] = {hits[i]["page_id"] for i in tp}
    prev["any_true_injection"] = prop(len(any_pages), pages, 1e5)
    flag_pages = {hits[i]["page_id"] for i in tp if lab[i].get("severity") in ("manipulative", "malicious")}
    prev["manipulative_or_malicious"] = prop(len(flag_pages), pages, 1e5)
    opt_pages = out["detector_pages_by_severity"].get("ai_optout", 0)
    prev["ai_optout_signal (detector)"] = prop(opt_pages, pages, 1e5)
    out["prevalence_per_100k_pages"] = prev
    out["prevalence_scaled_from_subsample"] = scaled
    opt = [i for i in lab if hits[i]["severity"] == "ai_optout"]
    if opt:
        out["ai_optout_spot_check"] = prop(sum(lab[i]["label"] == "optout_ok" for i in opt), len(opt))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hits", required=True)
    ap.add_argument("--labels", required=True)
    ap.add_argument("--stats", required=True)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    with open(a.hits, encoding="utf-8") as f:
        hits = [json.loads(line) for line in f if line.strip()]
    with open(a.labels, encoding="utf-8") as f:
        labels = [json.loads(line) for line in f if line.strip()]
    with open(a.stats, encoding="utf-8") as f:
        stats = json.load(f)
    res = compute(hits, labels, stats)
    txt = json.dumps(res, indent=2)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(txt + "\n")
    print(txt)


if __name__ == "__main__":
    main()
