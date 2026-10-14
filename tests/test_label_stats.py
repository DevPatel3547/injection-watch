"""scripts/label_stats.py: Wilson intervals, precision and prevalence arithmetic."""
import importlib.util

from .conftest import ROOT

_spec = importlib.util.spec_from_file_location("label_stats", ROOT / "scripts" / "label_stats.py")
assert _spec and _spec.loader
ls = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ls)


def test_wilson_matches_known_values():
    lo, hi = ls.wilson(20, 24)
    assert round(lo, 2) == 0.64 and round(hi, 2) == 0.93
    assert ls.wilson(0, 0) == (0.0, 1.0)
    lo, hi = ls.wilson(0, 10)
    assert lo == 0.0 and 0.27 < hi < 0.29


def test_compute_precision_and_prevalence():
    def hit(i, sev, page, host="a.example"):
        return {"severity": sev, "page_id": page, "url": f"https://{host}/{i}", "payload_hash": str(i)}

    hits = [hit(0, "ai_optout", "p0"), hit(1, "manipulative", "p1"), hit(2, "manipulative", "p2", "b.example"),
            hit(3, "defensive", "p3"), hit(4, "malicious", "p4")]
    labels = [{"hit": 0, "label": "optout_ok"}, {"hit": 1, "label": "true_injection", "severity": "manipulative"},
              {"hit": 2, "label": "benign"}, {"hit": 3, "label": "true_injection", "severity": "defensive"},
              {"hit": 4, "label": "true_injection", "severity": "manipulative"}]
    r = ls.compute(hits, labels, {"totals": {"pages_scanned": 100_000}})
    assert r["precision_overall"]["k"] == 3 and r["precision_overall"]["n"] == 4
    assert r["precision_flagged"]["k"] == 2 and r["precision_flagged"]["n"] == 3
    assert r["severity_agreement_among_tp"]["k"] == 2
    assert r["confusion_detector_vs_label"]["malicious"] == {"manipulative": 1}
    prev = r["prevalence_per_100k_pages"]
    assert prev["manipulative"]["p"] == 2.0 and prev["defensive"]["p"] == 1.0
    assert prev["manipulative_or_malicious"]["k"] == 2 and prev["any_true_injection"]["k"] == 3
    assert prev["ai_optout_signal (detector)"]["k"] == 1
    assert r["ai_optout_spot_check"]["k"] == 1 and not r["prevalence_scaled_from_subsample"]
    assert r["tp_unique_hosts"] == 1
