"""Carrier pages (real saved web pages the payloads are planted into) and discussion pages.

* ``readability``: Mozilla Readability's test pages (real articles saved by its maintainers) -> **dev** split.
* ``scrapinghub``: the Zyte article-extraction benchmark (181 real article pages) -> **test** split.
  Splitting carriers by source means test-split numbers are on pages from a collection never seen while tuning.
* ``owasp_llm``: OWASP Top 10 for LLM Applications 2025 pages (English + 9 translations of LLM01), converted from
  Markdown to plain HTML. These *discuss* prompt injection and quote attack strings: hard negatives.

Pages larger than ``MAX_CARRIER_BYTES`` are skipped (a handful of >600 KB pages would dominate runtime).
"""
from __future__ import annotations

import gzip
import html as html_lib
import re
from dataclasses import dataclass
from pathlib import Path

from .datasets import hash_split
from .sources import source_dir

MAX_CARRIER_BYTES = 600_000


@dataclass(frozen=True)
class Carrier:
    id: str
    source: str
    split: str
    path: str
    lang: str = "en"

    def read(self) -> str:
        p = Path(self.path)
        raw = gzip.decompress(p.read_bytes()) if p.suffix == ".gz" else p.read_bytes()
        return raw.decode("utf-8", "replace")


def load_carriers(root: Path | None = None, max_bytes: int = MAX_CARRIER_BYTES) -> list[Carrier]:
    out: list[Carrier] = []
    for p in sorted((source_dir("readability", root) / "test" / "test-pages").glob("*/source.html")):
        if p.stat().st_size <= max_bytes:
            out.append(Carrier(f"readability:{p.parent.name}", "readability", "dev", str(p)))
    for p in sorted((source_dir("scrapinghub", root) / "html").glob("*.html.gz")):
        size = len(gzip.decompress(p.read_bytes()))
        if size <= max_bytes:
            out.append(Carrier(f"scrapinghub:{p.name.split('.')[0]}", "scrapinghub", "test", str(p)))
    return out


# ------------------------------------------------------------------ discussion pages (Markdown -> HTML)

def md_to_html(md: str, title: str = "") -> str:
    """Tiny Markdown subset -> HTML: headings, fenced code, lists, block quotes, paragraphs. Inline markup is
    escaped, not interpreted (good enough: the detector only needs the text and the code/visible structure)."""
    out = [f"<!doctype html><html><head><meta charset='utf-8'><title>{html_lib.escape(title)}</title></head><body>"]
    lines = md.splitlines()
    i = 0
    para: list[str] = []

    def flush() -> None:
        if para:
            out.append("<p>" + html_lib.escape(" ".join(para)) + "</p>")
            para.clear()

    while i < len(lines):
        ln = lines[i]
        if ln.strip().startswith("```"):
            flush()
            i += 1
            code = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code.append(lines[i])
                i += 1
            out.append("<pre><code>" + html_lib.escape("\n".join(code)) + "</code></pre>")
        elif m := re.match(r"^(#{1,6})\s+(.*)", ln):
            flush()
            n = len(m.group(1))
            out.append(f"<h{n}>{html_lib.escape(m.group(2))}</h{n}>")
        elif m := re.match(r"^\s*(?:[-*+]|\d+\.)\s+(.*)", ln):
            flush()
            out.append("<ul><li>" + html_lib.escape(m.group(1)) + "</li></ul>")
        elif ln.startswith(">"):
            flush()
            out.append("<blockquote>" + html_lib.escape(ln.lstrip("> ")) + "</blockquote>")
        elif not ln.strip():
            flush()
        else:
            para.append(ln.strip())
        i += 1
    flush()
    out.append("</body></html>")
    return "\n".join(out)


@dataclass(frozen=True)
class Discussion:
    id: str
    split: str
    lang: str
    html: str


_LANG = {"de-DE": "de", "el-GR": "el", "es-ES": "es", "hi-IN": "hi", "ja-JP": "ja", "ko-KR": "ko",
         "pt-BR": "pt", "ru-RU": "ru", "zh-CN": "zh"}


def load_discussions(root: Path | None = None) -> list[Discussion]:
    base = source_dir("owasp_llm", root) / "2_0_vulns"
    out: list[Discussion] = []
    for p in sorted(base.glob("LLM*.md")):
        g = f"owasp:{p.stem}"
        out.append(Discussion(g, hash_split(g), "en", md_to_html(p.read_text("utf-8", "replace"), p.stem)))
    for p in sorted(base.glob("translations/*/LLM01*.md")):
        loc = p.parent.name
        g = f"owasp:{loc}:{p.stem}"
        page = md_to_html(p.read_text("utf-8", "replace"), p.stem)
        out.append(Discussion(g, hash_split(g), _LANG.get(loc, loc), page))
    return out
