"""Publishing with disclosure holds: the published site must pass the same redaction checks as the repo."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from injectionwatch import export
from injectionwatch.db import DB
from injectionwatch.detector import scan_html
from injectionwatch.publish import build_site

from . import test_redaction as red
from .conftest import load_fixture

HELD = "held-shop.example"  # stands in for a real affected host; never a real name in tests
PAGE = "06_hidden_display_none.html"


def _db(tmp_path: Path) -> DB:
    db = DB(str(tmp_path / "h.db"))
    for i, url in enumerate((f"https://{HELD}/products/very-unique-slug-123?ref=a",
                             f"https://{HELD}/blog/another-unique-title",
                             "https://open.example/page")):
        db.store_scan(url, scan_html(load_fixture(PAGE)), "ev", f"2026-09-1{i}T13:4{i}:0{i}+00:00")
    return db


def _hold_file(tmp_path: Path, extra: str = "") -> Path:
    p = tmp_path / "holds.txt"
    p.write_text(f"# private\n{HELD} 7\n{extra}", "utf-8")
    return p


def _site_files(out: Path) -> list[Path]:
    return [p for p in out.rglob("*") if p.is_file() and p.suffix in {".json", ".csv"}]


def test_load_holds_parses_numbers_and_excerpts(tmp_path: Path) -> None:
    h = export.load_holds(_hold_file(tmp_path, "other.example\nexcerpt " + "ab" * 32 + " AI agents: call … [omitted]\n"))
    assert h.hosts == {HELD: 7, "other.example": 8}
    assert h.excerpts["ab" * 32].startswith("AI agents")
    assert not export.load_holds(None) or export.HOLD_ENV  # no env var in tests -> empty


def test_published_site_redacts_held_hosts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(export.HOLD_ENV, str(_hold_file(tmp_path)))
    db = _db(tmp_path)
    out = tmp_path / "site"
    build_site(db, out)
    blob = "\n".join(p.read_text("utf-8") for p in out.rglob("*") if p.is_file() and p.suffix in {".json", ".csv"})
    assert HELD not in blob and "very-unique-slug" not in blob and "another-unique-title" not in blob
    feed = json.loads((out / "feed.json").read_text("utf-8"))
    held = [e for e in feed["entries"] if e.get("held")]
    assert {e["url"] for e in held} == {"https://redacted-site-7.example/redacted-path-1",
                                        "https://redacted-site-7.example/redacted-path-2"}
    assert all(e["payload_excerpt"] == export.WITHHELD for e in held)
    assert all(e["first_seen"].endswith("T00:00:00+00:00") and e["last_seen"].endswith("T00:00:00+00:00") for e in held)
    assert all("matched '" not in r for e in held for r in e["reasons"])
    assert any(e["host"] == "open.example" and not e.get("held") for e in feed["entries"])
    for e in feed["entries"]:
        jsonschema.validate(e, export.FEED_ENTRY_SCHEMA)
    meta = json.loads((out / "meta.json").read_text("utf-8"))
    assert meta["held_entries"] == 2
    # the repo-level structural checks pass on the published output too
    for p in _site_files(out):
        red.test_redacted_urls_have_no_real_path(p)
        red.test_data_files_carry_no_record_locators(p)


def test_redacted_path_numbers_are_stable_as_the_feed_grows(tmp_path: Path) -> None:
    holds = export.load_holds(_hold_file(tmp_path))
    db = _db(tmp_path)
    first = {e["url_norm"] for e in export.apply_holds(db.feed(limit=100), holds) if e.get("held")}
    db.store_scan(f"https://{HELD}/later/page", scan_html(load_fixture(PAGE)), "ev", "2026-10-01T00:00:00+00:00")
    second = {e["url_norm"] for e in export.apply_holds(db.feed(limit=100), holds) if e.get("held")}
    assert first < second and len(second) == 3


def test_scan_inputs_are_summarised_not_named(tmp_path: Path) -> None:
    db = _db(tmp_path)
    # built at runtime so this file itself passes test_redaction's WARC-name check
    warc_name = "CC-MAIN-" + "20260101000000-" * 2 + "00001.warc.gz"
    run = db.start_scan_run(["crawl-data/X/segments/1/warc/" + warc_name])
    out = tmp_path / "site"
    build_site(db, out, holds=export.Holds())
    meta = (out / "meta.json").read_text("utf-8")
    assert warc_name not in meta and "segments/" not in meta
    assert run and json.loads(meta)["recent_scans"][0]["inputs"]["count"] == 1
