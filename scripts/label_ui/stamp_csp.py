"""Recompute the Content-Security-Policy of label_ui/index.html from its inline <script> and <style>.

Run after editing the page: ``python scripts/label_ui/stamp_csp.py`` (tests/test_bench_realweb.py checks it).
"""
from __future__ import annotations

import base64
import hashlib
import re
import sys
from pathlib import Path

PAGE = Path(__file__).with_name("index.html")
_META = re.compile(r'(<meta http-equiv="Content-Security-Policy" content=")[^"]*(">)')


def _h(body: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode() + "'"


def policy(html: str) -> str:
    script = re.search(r"<script>(.*?)</script>", html, re.S)
    style = re.search(r"<style>(.*?)</style>", html, re.S)
    assert script and style, "page needs exactly one inline <script> and <style>"
    return (f"default-src 'none'; script-src {_h(script.group(1))}; style-src {_h(style.group(1))}; "
            "img-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'")


def stamp(html: str) -> str:
    return _META.sub(lambda m: m.group(1) + policy(html) + m.group(2), html, count=1)


if __name__ == "__main__":
    text = PAGE.read_text("utf-8")
    new = stamp(text)
    if "--check" in sys.argv:
        sys.exit(0 if new == text else 1)
    PAGE.write_text(new, "utf-8")
    print("stamped", PAGE)
