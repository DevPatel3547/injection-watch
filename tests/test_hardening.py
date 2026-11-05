"""Hostile-input hardening: rule regexes stay linear-ish on adversarial text, and the dashboard never
turns feed text into markup."""
from __future__ import annotations

import json
import threading
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from injectionwatch.db import DB
from injectionwatch.detector import Finding, ScanResult
from injectionwatch.publish import build_site
from injectionwatch.scorer import load_rules, score_text

from .conftest import chromium_available, chromium_launch_kwargs

# Inputs shaped to trigger catastrophic backtracking in typical rule shapes: long runs of rule vocabulary
# without the closing token, nested quotes, whitespace/punctuation floods, and mixed scripts.
ADVERSARIAL = [
    "ignore " * 4000,
    "if you are an ai " * 1500,
    "AI assistant, " * 3000 + "x",
    "\"'«「" * 3000,
    " \t\n." * 6000,
    "a" * 30000,
    "previous instructions " * 2000 + "!",
    "忘记" * 8000,
    "ignore previous " + "and " * 8000 + "instructions",
]


def test_every_rule_is_fast_on_adversarial_text() -> None:
    _, rules = load_rules()
    slow = []
    for r in rules:
        for s in ADVERSARIAL:
            t0 = time.perf_counter()
            r.pattern.search(s.lower())
            dt = time.perf_counter() - t0
            if dt > 0.25:
                slow.append((r.id, round(dt, 3), s[:20]))
    assert not slow, f"rules with super-linear behaviour: {slow}"


def test_scoring_whole_adversarial_candidates_is_bounded() -> None:
    t0 = time.perf_counter()
    for s in ADVERSARIAL:
        for loc in ("visible", "hidden_css", "comment"):
            score_text(s, loc)
    assert time.perf_counter() - t0 < 10.0


XSS = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script>"><svg onload="window.__pwned=3">'


@pytest.mark.skipif(not chromium_available(), reason="Playwright/Chromium unavailable")
def test_dashboard_renders_hostile_feed_text_as_text(tmp_path: Path) -> None:
    from playwright.sync_api import sync_playwright

    db = DB(str(tmp_path / "x.db"))
    f = Finding(payload_excerpt=XSS, payload_hash="f" * 64, location="comment", techniques=["html_comment"],
                category="instruction_override", intent="manipulative", target="agents", confidence=0.9,
                heuristic_score=6.0, reasons=[XSS], path="<!-- -->")
    db.store_scan('https://xss.example/"><img src=x onerror=1>', ScanResult(url="", findings=[f]), "ev",
                  "2026-09-01T00:00:00+00:00")
    out = tmp_path / "site"
    build_site(db, out)
    assert XSS[:20] in (out / "feed.json").read_text("utf-8").replace('\\"', '"')
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), partial(SimpleHTTPRequestHandler, directory=str(out)))
    SimpleHTTPRequestHandler.log_message = lambda *a: None  # type: ignore[method-assign]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        with sync_playwright() as p:
            b = p.chromium.launch(**chromium_launch_kwargs())
            pg = b.new_page()
            dialogs: list[str] = []
            pg.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
            pg.goto(f"http://127.0.0.1:{httpd.server_address[1]}/index.html")
            pg.wait_for_selector("#rows tr")
            assert XSS[:15] in pg.inner_text("#rows")  # shown as text
            assert pg.evaluate("window.__pwned === undefined")
            assert pg.locator("#rows img, #rows svg, #rows script").count() == 0
            assert not dialogs
            b.close()
    finally:
        httpd.shutdown()
    json.loads((out / "meta.json").read_text("utf-8"))
