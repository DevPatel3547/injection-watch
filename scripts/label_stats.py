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

Recall (v0.4): label a near-miss sample (``scripts/sample_near_misses.py`` or ``scan_cc.py --near-miss-sample``)
and pass ``--near-misses near_misses.jsonl --near-miss-strata near_miss_strata.json --near-miss-labels nm.jsonl``
(near-miss labels: ``{"nm": "nm00012", "label": "true_injection" | "benign" | "unsure"}``). The estimate is

    missed  = sum over location strata of  population_s x (true injections_s / labelled_s)
    recall  = detected / (detected + missed)

where ``detected`` counts non-visible detector findings labelled true_injection (scaled like prevalence). It is a
**candidate-level recall over non-visible extracted text**: injections the extractor never sees (images, scripts,
JS-inserted text in a static scan) are outside both terms. The 95% interval is a Monte Carlo interval from
independent Jeffreys Beta(k+1/2, n-k+1/2) posteriors per stratum (``detected`` held fixed). Strata with a
population but no labels are reported, not imputed.

Agreement: ``--kappa A.jsonl B.jsonl`` prints Cohen's kappa between two annotators' label files (matched on
``hit`` or ``nm``), with a seeded bootstrap 95% interval.
"""
from __future__ import annotations

import argparse
import json
import math
import random
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


def detected_nonvisible_tp(hits: list[dict[str, Any]], labels: list[dict[str, Any]]) -> float:
    """Non-visible findings labelled true_injection, scaled up when a detector-severity stratum was subsampled."""
    lab = {int(x["hit"]): x for x in labels if "hit" in x}
    strata = Counter(h["severity"] for h in hits)
    labelled = Counter(hits[i]["severity"] for i in lab)
    est = 0.0
    for i, x in lab.items():
        if x.get("label") == "true_injection" and hits[i].get("location") != "visible":
            st = hits[i]["severity"]
            est += strata[st] / labelled[st] if labelled[st] else 1.0
    return est


def near_miss_recall(nm_rows: list[dict[str, Any]], strata: dict[str, Any], nm_labels: list[dict[str, Any]],
                     detected: float, draws: int = 20000, seed: int = 20261105) -> dict[str, Any]:
    by_id = {r["nm_id"]: r for r in nm_rows}
    lab = {x["nm"]: x["label"] for x in nm_labels if x.get("nm") in by_id}
    unknown = sorted({x.get("nm") for x in nm_labels} - set(by_id))
    per: dict[str, dict[str, Any]] = {}
    for st, info in sorted(strata["strata"].items()):
        ids = [r["nm_id"] for r in nm_rows if r["stratum"] == st]
        ls = [lab[i] for i in ids if i in lab and lab[i] != "unsure"]
        k = sum(x == "true_injection" for x in ls)
        per[st] = {"population": int(info["population"]), "sampled": len(ids), "labelled": len(ls),
                   "unsure": sum(1 for i in ids if lab.get(i) == "unsure"), "true_injections": k,
                   "rate": prop(k, len(ls)) if ls else None,
                   "missed_estimate": round(info["population"] * k / len(ls), 2) if ls else None}
    lab_strata = {s: v for s, v in per.items() if v["labelled"]}
    missed = sum(v["missed_estimate"] for v in lab_strata.values())
    out: dict[str, Any] = {"detected_nonvisible_tp": round(detected, 2), "missed_estimate": round(missed, 2),
                           "strata": per, "unlabelled_population": sum(v["population"] for v in per.values()
                                                                       if not v["labelled"]),
                           "labels_for_unknown_nm_ids": len(unknown)}
    if detected + missed <= 0:
        out["recall"] = None
        out["recall_ci95"] = None
        out["note"] = "no true injections detected or found among near-misses; recall undefined"
        return out
    rng = random.Random(seed)
    sims = []
    for _ in range(draws):
        m = sum(v["population"] * rng.betavariate(v["true_injections"] + 0.5,
                                                  v["labelled"] - v["true_injections"] + 0.5)
                for v in lab_strata.values())
        sims.append(detected / (detected + m) if detected + m > 0 else 0.0)
    sims.sort()
    out["recall"] = round(detected / (detected + missed), 4)
    out["recall_ci95"] = [round(sims[int(0.025 * draws)], 4), round(sims[int(0.975 * draws) - 1], 4)]
    out["interval"] = "Monte Carlo, Jeffreys Beta posterior per stratum, detected fixed"
    return out


def _label_key(x: dict[str, Any]) -> str:
    return f"nm:{x['nm']}" if "nm" in x else f"hit:{x['hit']}"


def cohen_kappa(a: list[dict[str, Any]], b: list[dict[str, Any]], draws: int = 2000,
                seed: int = 20261105) -> dict[str, Any]:
    da = {_label_key(x): str(x["label"]) for x in a}
    db = {_label_key(x): str(x["label"]) for x in b}
    common = sorted(set(da) & set(db))

    def kappa(ids: list[str]) -> float | None:
        n = len(ids)
        if not n:
            return None
        po = sum(da[i] == db[i] for i in ids) / n
        ca, cb = Counter(da[i] for i in ids), Counter(db[i] for i in ids)
        pe = sum(ca[c] * cb[c] for c in set(ca) | set(cb)) / (n * n)
        return 1.0 if pe >= 1.0 else (po - pe) / (1 - pe)

    k = kappa(common)
    out: dict[str, Any] = {"n_common": len(common), "only_in_a": len(set(da) - set(db)),
                           "only_in_b": len(set(db) - set(da)),
                           "observed_agreement": round(sum(da[i] == db[i] for i in common) / len(common), 4)
                           if common else None,
                           "kappa": None if k is None else round(k, 4)}
    if len(common) >= 2:
        rng = random.Random(seed)
        sims = sorted(v for v in (kappa([rng.choice(common) for _ in common]) for _ in range(draws))
                      if v is not None)
        out["kappa_ci95"] = [round(sims[int(0.025 * len(sims))], 4), round(sims[int(0.975 * len(sims)) - 1], 4)]
        out["interval"] = "bootstrap over items"
    out["confusion"] = {f"{x}|{y}": n for (x, y), n in sorted(Counter((da[i], db[i]) for i in common).items())}
    return out


def _jsonl(path: str) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hits")
    ap.add_argument("--labels")
    ap.add_argument("--stats")
    ap.add_argument("--near-misses", help="near_misses.jsonl (private sampler output)")
    ap.add_argument("--near-miss-strata", help="near_miss_strata.json")
    ap.add_argument("--near-miss-labels", help="labels for the near-miss sample")
    ap.add_argument("--kappa", nargs=2, metavar=("A", "B"), help="Cohen's kappa between two label files")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    if a.kappa and not a.hits:
        res: dict[str, Any] = {"agreement": cohen_kappa(_jsonl(a.kappa[0]), _jsonl(a.kappa[1]))}
    else:
        if not (a.hits and a.labels and a.stats):
            ap.error("--hits, --labels and --stats are required (or use --kappa A B alone)")
        hits, labels = _jsonl(a.hits), _jsonl(a.labels)
        with open(a.stats, encoding="utf-8") as f:
            stats = json.load(f)
        res = compute(hits, labels, stats)
        if a.near_misses or a.near_miss_labels or a.near_miss_strata:
            if not (a.near_misses and a.near_miss_labels and a.near_miss_strata):
                ap.error("--near-misses, --near-miss-strata and --near-miss-labels go together")
            with open(a.near_miss_strata, encoding="utf-8") as f:
                strata = json.load(f)
            res["recall_estimate"] = near_miss_recall(_jsonl(a.near_misses), strata, _jsonl(a.near_miss_labels),
                                                      detected_nonvisible_tp(hits, labels))
        if a.kappa:
            res["agreement"] = cohen_kappa(_jsonl(a.kappa[0]), _jsonl(a.kappa[1]))
    txt = json.dumps(res, indent=2)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(txt + "\n")
    print(txt)


if __name__ == "__main__":
    main()
