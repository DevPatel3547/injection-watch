# IW-Bench result schema (`iwbench/1`)

One JSON file per detector configuration under `reports/bench/`, plus `index.json` listing them.

```
{
  "schema": "iwbench/1",
  "version": "0.3.0",                 # detector/package version the run measured
  "generated_at": "2026-11-05T12:00:00Z",
  "detector": {"name", "rules_version", "ml": bool, "mode": "static|static_css|rendered"},
  "split": "dev|test|all",            # dev while tuning, test only for reporting
  "config": {"quick", "per_payload", "per_benign", "seed", "elapsed_s"},
  "synthetic_planting": true,         # payloads are planted into real pages; not a real-web prevalence
  "sources": [{"id", "repo", "commit", "license", "n", "role"}],
  "carriers": {"n", "sources"},
  "counts": {"pages", "positive_hidden", "positive_visible", "benign_planted",
             "carriers_unmodified", "discussion_pages"},
  "overall": CELL,                    # headline: hidden-technique payloads (recall) vs unmodified real pages (FP)
  "hidden_covered_techniques": CELL,  # techniques the v0.3 static extractor has an extractor for
  "hidden_static_blind_techniques": CELL,
  "visible_control": CELL,            # payload as an ordinary paragraph (never mixed into hidden recall)
  "benign_hidden_text": CELL,         # benign text planted with hidden techniques (fp/tn only)
  "discussion_pages": CELL,           # pages that discuss prompt injection (fp/tn only)
  "by_technique": {technique: CELL},  # recall from payloads, fp from benign text planted the same way
  "by_payload_source": {source: CELL},
  "by_payload_family": {family: CELL},
  "by_language": {lang: CELL},
  "timing": {"scan_ms_mean"}
}
CELL = {"tp", "fn", "fp", "tn", "recall", "recall_ci", "fp_rate", "fp_ci",
        "extracted_hidden"?, "located"?}       # *_ci: Wilson 95% interval [lo, hi], null when n = 0
```

A positive is a true positive only when a flagged finding is about the planted text itself (its payload hash
belongs to an extracted candidate containing that text). `located` additionally requires the expected location.
