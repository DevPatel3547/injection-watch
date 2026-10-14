import csv
import io
import json

from injectionwatch import export
from injectionwatch.db import DB, normalize_url
from injectionwatch.detector import scan_html

from .conftest import load_fixture


def test_normalize_url():
    assert normalize_url("HTTPS://Example.COM:443/a?b=2&a=1&utm_source=x#frag") == "https://example.com/a?a=1&b=2"
    assert normalize_url("http://example.com") == "http://example.com/"
    assert normalize_url("https://e.com/p?token=1", keep_query=False) == "https://e.com/p"


def test_dedupe_first_last_seen_and_removal(tmp_path):
    db = DB(str(tmp_path / "t.db"))
    res = scan_html(load_fixture("06_hidden_display_none.html"))
    db.store_scan("https://a.example/", res, "ev1", "2026-10-01T00:00:00+00:00")
    db.store_scan("https://A.example/#x", res, "ev2", "2026-10-05T00:00:00+00:00")
    rows = db.feed()
    assert len(rows) == 1
    e = rows[0]
    assert e["first_seen"].startswith("2026-10-01") and e["last_seen"].startswith("2026-10-05")
    assert e["seen_count"] == 2 and e["evidence_hash"] == "ev2"
    obs = db.conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
    assert obs == 2
    # re-crawl without the payload -> removed, not in default feed
    clean = scan_html("<p>nothing</p>")
    db.store_scan("https://a.example/", clean, "ev3", "2026-10-06T00:00:00+00:00")
    assert db.feed() == [] and len(db.feed(include_inactive=True)) == 1
    # appeal upheld -> suppressed hides even from include_inactive
    db.set_status(e["id"], "suppressed", "owner removed test content")
    assert db.feed(include_inactive=True) == []


def _db_with_data(tmp_path):
    db = DB(str(tmp_path / "f.db"))
    for name in ("06_hidden_display_none.html", "27_hiring_bot_injection.html", "30_ai_optout_defensive.html"):
        db.store_scan(f"https://{name.split('_')[0]}.example/page", scan_html(load_fixture(name)), "ev",
                      "2026-10-10T00:00:00+00:00")
    return db


def test_exports(tmp_path):
    db = _db_with_data(tmp_path)
    entries = db.feed()
    j = json.loads(export.to_json(entries))
    assert j["license"] == "CC-BY-4.0" and "UNTRUSTED" in j["warning"] and j["count"] == len(entries)
    assert any(e["flagged"] for e in j["entries"]) and any(not e["flagged"] for e in j["entries"])
    for e in j["entries"]:
        assert "https://" not in e["payload_excerpt"] and len(e["payload_excerpt"]) <= 200
    rows = list(csv.DictReader(io.StringIO(export.to_csv(entries))))
    assert len(rows) == len(entries) and rows[0]["payload_hash"]
    bundle = json.loads(export.to_stix(entries))
    assert bundle["type"] == "bundle"
    inds = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(inds) == len(entries) and inds[0]["pattern"].startswith("[url:value = '")


def test_stix_validates_with_stix2_if_available(tmp_path):
    import pytest

    stix2 = pytest.importorskip("stix2")
    db = _db_with_data(tmp_path)
    parsed = stix2.parse(export.to_stix(db.feed()), allow_custom=True)
    assert len(parsed.objects) >= 2


def test_csv_formula_neutralized():
    out = export.to_csv([{"id": 1, "url": "=HYPERLINK(1)", "host": "h", "category": "c", "intent": "malicious",
                          "location": "l", "techniques": [], "target": "t", "confidence": 0.9, "first_seen": "x",
                          "last_seen": "x", "seen_count": 1, "status": "active", "payload_hash": "h",
                          "evidence_hash": "e", "payload_excerpt": "@SUM(A1)", "reasons": []}])
    assert "'=HYPERLINK" in out and "'@SUM" in out
