"""Train the learned second stage (injectionwatch/ml.py) from the IW-Bench **dev** split only.

Pure Python (no numpy / scikit-learn needed): logistic regression with AdaGrad SGD and L2 regularisation (positive
class weight 1: on dev, higher weights raised the val-page FP rate faster than LODO recall), on hashed n-gram
features. Deterministic for a seed.

Data (all from the pinned public sources; run ``injectionwatch bench data`` first):

* positives: dev-split payloads of every payload source (InjecAgent, BIPIA train split, AgentDojo, OPI, greshake,
  PINT examples);
* negatives: every extracted candidate (hidden AND visible, >= 20 chars) of the dev carrier pages (Mozilla
  Readability test pages), dev-split benign texts (synthetic hidden UI, BIPIA e-mails and tables, PINT benign),
  and the candidates of dev-split OWASP pages that discuss prompt injection.

Model selection never sees the test split (Zyte carrier pages, BIPIA test split, test-hash payload groups):

* carriers are split again into ``fit`` / ``val`` by a hash of the page id (val = 30%);
* **leave-one-dataset-out**: for every payload source, a model trained without that source scores its items, so
  the recall used to pick the threshold is recall on an unseen dataset, not memorisation;
* the threshold is the lowest one that keeps the page-level FP rate on the **val** carriers (non-visible
  candidates, the only ones the detector sends to the model) at or below ``--max-fp`` (default 1%) and the FP rate
  on dev benign hidden text at or below ``--max-benign-fp`` (default 2%).

    python scripts/train_ml.py --out injectionwatch/data/ml_model.json [--report reports/bench/ml_training.json]
"""
from __future__ import annotations

import argparse
import array
import hashlib
import json
import math
import random
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from injectionwatch.bench import carriers as bench_carriers
from injectionwatch.bench import datasets
from injectionwatch.extract import extract_candidates
from injectionwatch.ml import FeatureConfig, Model, features, sigmoid
from injectionwatch.textutil import clean_for_scoring

MIN_CHARS = 20

Example = tuple[list[tuple[int, float]], int, str, str]  # features, label, group, source


def vec(text: str, cfg: FeatureConfig) -> tuple[array.array, array.array]:
    """Compact feature storage (a few KB per example instead of tens of KB of tuples)."""
    f = features(text, cfg)
    return array.array("l", (b for b, _ in f)), array.array("d", (v for _, v in f))


def _h(s: str) -> float:
    return int(hashlib.sha256(s.encode()).hexdigest()[:8], 16) / 0xFFFFFFFF


def build_data(cfg: FeatureConfig, val_frac: float = 0.3, per_page: int = 30,
               log: Any = print) -> dict[str, list[dict[str, Any]]]:
    """-> {"pos": [...], "neg_fit": [...], "neg_val": [...], "benign_hidden": [...]} (dev split only)."""
    pos = [i for i in datasets.load_payloads() if i.split == "dev"]
    ben = [i for i in datasets.load_benign() if i.split == "dev"]
    out: dict[str, list[dict[str, Any]]] = {"pos": [], "neg_fit": [], "neg_val": [], "benign_hidden": []}
    for it in pos:
        out["pos"].append({"x": vec(it.text, cfg), "y": 1, "source": it.source, "group": it.group})
    for it in ben:
        row = {"x": vec(it.text, cfg), "y": 0, "source": it.source, "group": it.group}
        out["neg_fit"].append(row)
        out["benign_hidden"].append(row)
    t = time.time()
    cars = [c for c in bench_carriers.load_carriers() if c.split == "dev"]
    for c in cars:
        bucket = "neg_val" if _h("val|" + c.id) < val_frac else "neg_fit"
        seen: set[str] = set()
        page: list[Any] = []
        for cand in extract_candidates(c.read()):
            txt = clean_for_scoring(cand.text)
            if len(txt) < MIN_CHARS or txt in seen:
                continue
            seen.add(txt)
            page.append(cand)
        # keep EVERY non-visible candidate (exactly what the detector sends to the model: short link titles, alt
        # texts, comments...) and a seeded sample of visible blocks. v1 capped the hidden ones and learned
        # "short text = injection"; see reports/bench/README.md.
        hidden = [x for x in page if x.location != "visible"]
        vis = sorted((x for x in page if x.location == "visible"), key=lambda x: _h(c.id + x.text))
        if bucket == "neg_fit":
            vis = vis[:per_page]
        else:
            vis = []  # val pages: only non-visible candidates matter for the page FP rate
        for cand in hidden + vis:
            out[bucket].append({"x": vec(cand.text, cfg), "y": 0, "source": "carrier", "group": c.id,
                                "visible": cand.location == "visible"})
    for d in bench_carriers.load_discussions():
        if d.split != "dev":
            continue
        for cand in extract_candidates(d.html):
            if len(clean_for_scoring(cand.text)) >= MIN_CHARS:
                out["neg_fit"].append({"x": vec(cand.text, cfg), "y": 0, "source": "owasp_llm", "group": d.id})
    log(f"data: {len(out['pos'])} positives, {len(out['neg_fit'])} fit negatives, {len(out['neg_val'])} val "
        f"negatives from {len(cars)} dev carriers ({time.time() - t:.0f}s)")
    return out


def train(rows: list[dict[str, Any]], epochs: int = 5, lr: float = 0.5, l2: float = 1e-5, seed: int = 1,
          pos_weight: float | None = 1.0, bits: int = 18) -> tuple[float, dict[int, float]]:
    """AdaGrad logistic regression on dense arrays of 2**bits weights (fast, bounded memory)."""
    rng = random.Random(seed)
    npos = sum(r["y"] for r in rows)
    nneg = len(rows) - npos
    pw = pos_weight if pos_weight is not None else (nneg / max(1, npos))
    n = 1 << bits
    w = array.array("d", bytes(8 * n))
    g2 = array.array("d", [1e-8]) * n
    b, gb = 0.0, 1e-8
    order = list(range(len(rows)))
    sqrt = math.sqrt
    for _ in range(epochs):
        rng.shuffle(order)
        for i in order:
            r = rows[i]
            ks, vs = r["x"]
            y = r["y"]
            z = b
            for k, v in zip(ks, vs, strict=True):
                z += w[k] * v
            gr = (sigmoid(z) - y) * (pw if y else 1.0)
            gb += gr * gr
            b -= lr * gr / sqrt(gb)
            for k, v in zip(ks, vs, strict=True):
                g = gr * v + l2 * w[k]
                g2[k] += g * g
                w[k] -= lr * g / sqrt(g2[k])
    return b, {k: w[k] for k in range(n) if w[k] != 0.0}


def predict(b: float, w: dict[int, float], x: tuple[array.array, array.array]) -> float:
    ks, vs = x
    return sigmoid(b + sum(w.get(k, 0.0) * v for k, v in zip(ks, vs, strict=True)))


def prune(w: dict[int, float], keep: int, digits: int = 6) -> dict[int, float]:
    top = sorted(w.items(), key=lambda kv: -abs(kv[1]))[:keep]
    return {k: float(f"{v:.{digits}g}") for k, v in top if abs(v) >= 1e-6}


def wilson(k: int, n: int, z: float = 1.96) -> list[float] | None:
    if not n:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0, c - h), 4), round(min(1, c + h), 4)]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=ROOT / "injectionwatch" / "data" / "ml_model.json")
    ap.add_argument("--report", type=Path, default=None, help="write the training report (JSON) here")
    ap.add_argument("--epochs", type=int, default=5)
    ap.add_argument("--keep", type=int, default=40000, help="non-zero weights to keep (file size)")
    ap.add_argument("--max-fp", type=float, default=0.01, help="max page FP rate on val carriers")
    ap.add_argument("--max-benign-fp", type=float, default=0.02, help="max FP rate on dev benign hidden text")
    ap.add_argument("--bits", type=int, default=18)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--default-on", action="store_true", help="mark the model as on by default")
    a = ap.parse_args(argv)
    cfg = FeatureConfig(bits=a.bits)
    t0 = time.time()
    data = build_data(cfg)
    pos, fit, val, ben = data["pos"], data["neg_fit"], data["neg_val"], data["benign_hidden"]

    # leave-one-dataset-out scores for every positive
    lodo: dict[int, float] = {}
    sources = sorted({r["source"] for r in pos})
    per_source: dict[str, Any] = {}
    for s in sources:
        tr = [r for r in pos if r["source"] != s] + fit
        b, w = train(tr, a.epochs, seed=a.seed, bits=a.bits)
        for i, r in enumerate(pos):
            if r["source"] == s:
                lodo[i] = predict(b, w, r["x"])
        print(f"  LODO without {s:<11} trained in {time.time() - t0:5.0f}s", flush=True)
    b, w = train(pos + fit, a.epochs, seed=a.seed, bits=a.bits)
    w = prune(w, a.keep)

    # page-level FP on val carriers: a page is an FP when any NON-VISIBLE candidate reaches the threshold
    val_pages: dict[str, float] = defaultdict(float)
    for r in val:
        if not r.get("visible"):
            val_pages[r["group"]] = max(val_pages[r["group"]], predict(b, w, r["x"]))
    for r in val:
        val_pages.setdefault(r["group"], 0.0)
    ben_scores = [predict(b, w, r["x"]) for r in ben]  # in-sample for the final model: optimistic, reported
    grid = sorted({round(x / 200, 3) for x in range(20, 200)})
    chosen = None
    table = []
    for t in grid:
        fp_pages = sum(s >= t for s in val_pages.values())
        ben_fp = sum(s >= t for s in ben_scores)
        rec = sum(s >= t for s in lodo.values())
        table.append({"threshold": t, "val_page_fp": fp_pages, "val_pages": len(val_pages),
                      "benign_fp": ben_fp, "benign_n": len(ben_scores), "lodo_recall": round(rec / len(lodo), 4)})
        if chosen is None and fp_pages <= a.max_fp * len(val_pages) and ben_fp <= a.max_benign_fp * len(ben_scores):
            chosen = t
    if chosen is None:
        chosen = grid[-1]
    for s in sources:
        idx = [i for i, r in enumerate(pos) if r["source"] == s]
        k = sum(lodo[i] >= chosen for i in idx)
        per_source[s] = {"n": len(idx), "lodo_recall": round(k / len(idx), 4), "ci95": wilson(k, len(idx))}
    k_all = sum(v >= chosen for v in lodo.values())
    fp_pages = sum(s >= chosen for s in val_pages.values())
    meta = {"trained_on": "IW-Bench dev split (see scripts/train_ml.py)", "seed": a.seed, "epochs": a.epochs,
            "n_pos": len(pos), "n_neg": len(fit), "threshold_rule":
            f"lowest t with val-carrier page FP <= {a.max_fp} and dev benign FP <= {a.max_benign_fp}",
            "lodo_recall": round(k_all / len(lodo), 4), "lodo_recall_ci95": wilson(k_all, len(lodo)),
            "val_page_fp": fp_pages, "val_pages": len(val_pages), "default_on": bool(a.default_on)}
    model = Model(cfg, round(b, 9), w, chosen, MIN_CHARS, meta)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(model.to_json(), separators=(",", ":")) + "\n", "utf-8")
    report = {"model": str(a.out.name), "threshold": chosen, "meta": meta, "lodo_by_source": per_source,
              "threshold_table": table, "elapsed_s": round(time.time() - t0, 1),
              "size_bytes": a.out.stat().st_size, "nonzero_weights": len(w)}
    if a.report:
        a.report.parent.mkdir(parents=True, exist_ok=True)
        a.report.write_text(json.dumps(report, indent=1) + "\n", "utf-8")
    print(json.dumps({k: report[k] for k in ("threshold", "lodo_by_source", "size_bytes", "nonzero_weights")},
                     indent=1))
    print(f"val carriers: {fp_pages}/{len(val_pages)} pages over threshold; LODO recall "
          f"{meta['lodo_recall']} {meta['lodo_recall_ci95']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
