"""Deterministic planting of one text into one carrier page with one hiding technique.

Each technique returns the modified page, any extra resources (an external stylesheet for ``external_css``)
and the detector ``location`` a correct detection would report. The planted text is located again after
extraction by containment of its normalised form (see ``runner.planted_key``), so a finding counts only if it
is *about the planted text*, never because the carrier already had something flagged.

``visible`` is a control (the text as an ordinary paragraph); it is reported separately and never mixed into
"hidden" recall.
"""
from __future__ import annotations

import hashlib
import html as html_lib
import json
import random
import re
from collections.abc import Callable
from dataclasses import dataclass, field

STYLESHEET_PATH = "/iwbench/site.css"
_GIF = "data:image/gif;base64,R0lGODlhAQABAAAAACw="
ZWSP = "\u200b"


@dataclass
class Planted:
    html: str
    location: str
    resources: dict[str, str] = field(default_factory=dict)


def _esc(t: str) -> str:
    return html_lib.escape(t, quote=False)


def _attr(t: str) -> str:
    return html_lib.escape(t, quote=True)


def _cls(seed: str) -> str:
    return "c" + hashlib.sha256(seed.encode()).hexdigest()[:8]


_P_CLOSE = re.compile(r"</p\s*>", re.I)
_BODY_OPEN = re.compile(r"<body\b[^>]*>", re.I)
_BODY_CLOSE = re.compile(r"</body\s*>", re.I)
_HEAD_OPEN = re.compile(r"<head\b[^>]*>", re.I)


_OPAQUE = re.compile(r"<!--.*?(?:-->|$)|<(script|style|template|noscript|textarea|iframe|title|svg|math|xmp)\b"
                     r"[^>]*>.*?(?:</\1\s*>|$)", re.I | re.S)


def opaque_spans(page: str) -> list[tuple[int, int]]:
    """Comments and raw-text / non-rendered elements: a fragment inserted there would not be what it claims."""
    return [m.span() for m in _OPAQUE.finditer(page)]


def insert_body(page: str, fragment: str, rng: random.Random) -> str:
    """Insert ``fragment`` after a randomly chosen ``</p>`` inside <body> (else just before </body>), never inside
    a comment (IE conditional comments contain ``</p>``), script, style, template, noscript, textarea or iframe."""
    b = _BODY_OPEN.search(page)
    start = b.end() if b else 0
    spans = opaque_spans(page)

    def free(pos: int) -> bool:
        return not any(s < pos < e for s, e in spans)

    ends = [m.end() for m in _P_CLOSE.finditer(page, start) if free(m.start()) and free(m.end())]
    if ends:
        pos = rng.choice(ends)
        return page[:pos] + fragment + page[pos:]
    for m in _BODY_CLOSE.finditer(page, start):
        if free(m.start()):
            return page[: m.start()] + fragment + page[m.start():]
    return page + fragment


def insert_head(page: str, fragment: str) -> str:
    m = _HEAD_OPEN.search(page)
    if m:
        return page[: m.end()] + fragment + page[m.end():]
    b = _BODY_OPEN.search(page)
    if b:
        return page[: b.start()] + "<head>" + fragment + "</head>" + page[b.start():]
    return "<head>" + fragment + "</head>" + page


def zero_width_split(text: str) -> str:
    """Insert a zero-width space inside every word of 4+ letters (classic keyword-filter evasion)."""
    return re.sub(r"\b([A-Za-z]{2})([A-Za-z]{2,})", lambda m: m.group(1) + ZWSP + m.group(2), text)


def to_unicode_tags(text: str) -> str:
    """ASCII -> Unicode tag characters (U+E0020..U+E007E); non-ASCII characters are dropped."""
    return "".join(chr(0xE0000 + ord(c)) for c in text if 0x20 <= ord(c) <= 0x7E)


def _css_string(t: str) -> str:
    return '"' + t.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\A ").replace("<", "\\3C ") + '"'


def _js_string(t: str) -> str:
    return json.dumps(t).replace("</", "<\\/")


def _div(style: str) -> Callable[[str, str, random.Random], Planted]:
    def f(page: str, text: str, rng: random.Random) -> Planted:
        return Planted(insert_body(page, f'<div style="{style}">{_esc(text)}</div>', rng), "hidden_css")
    return f


def _comment(page: str, text: str, rng: random.Random) -> Planted:
    safe = text.replace("-->", "-- >").replace("--!>", "-- !>")
    return Planted(insert_body(page, f"<!-- {safe} -->", rng), "comment")


def _hidden_attr(page: str, text: str, rng: random.Random) -> Planted:
    return Planted(insert_body(page, f"<div hidden>{_esc(text)}</div>", rng), "hidden_css")


def _meta(page: str, text: str, rng: random.Random) -> Planted:
    return Planted(insert_head(page, f'<meta name="description" content="{_attr(text)}">'), "meta")


def _jsonld(page: str, text: str, rng: random.Random) -> Planted:
    doc = json.dumps({"@context": "https://schema.org", "@type": "Article", "description": text})
    return Planted(insert_head(page, '<script type="application/ld+json">' + doc.replace("</", "<\\/") + "</script>"),
                   "jsonld")


def _img_alt(page: str, text: str, rng: random.Random) -> Planted:
    return Planted(insert_body(page, f'<img src="{_GIF}" width="1" height="1" alt="{_attr(text)}">', rng),
                   "attribute")


def _aria_label(page: str, text: str, rng: random.Random) -> Planted:
    return Planted(insert_body(page, f'<button type="button" aria-label="{_attr(text)}">&#215;</button>', rng),
                   "attribute")


def _data_attr(page: str, text: str, rng: random.Random) -> Planted:
    return Planted(insert_body(page, f'<div class="widget" data-note="{_attr(text)}"></div>', rng), "attribute")


def _noscript(page: str, text: str, rng: random.Random) -> Planted:
    return Planted(insert_body(page, f"<noscript><p>{_esc(text)}</p></noscript>", rng), "non_rendered")


def _template(page: str, text: str, rng: random.Random) -> Planted:
    return Planted(insert_body(page, f"<template><p>{_esc(text)}</p></template>", rng), "non_rendered")


def _hidden_input(page: str, text: str, rng: random.Random) -> Planted:
    return Planted(insert_body(page, f'<form><input type="hidden" name="note" value="{_attr(text)}"></form>', rng),
                   "hidden_css")


def _unicode_tags(page: str, text: str, rng: random.Random) -> Planted:
    return Planted(insert_body(page, f"<p>Thanks for reading.{to_unicode_tags(text)}</p>", rng), "invisible_unicode")


def _zero_width(page: str, text: str, rng: random.Random) -> Planted:
    return Planted(insert_body(page, f'<div style="display:none">{_esc(zero_width_split(text))}</div>', rng),
                   "hidden_css")


def _external_css(page: str, text: str, rng: random.Random) -> Planted:
    cls = _cls(text)
    page = insert_head(page, f'<link rel="stylesheet" href="{STYLESHEET_PATH}">')
    page = insert_body(page, f'<div class="{cls}">{_esc(text)}</div>', rng)
    return Planted(page, "hidden_css", {STYLESHEET_PATH: f".{cls} {{ display: none; }}\n"})


def _js_inserted(page: str, text: str, rng: random.Random) -> Planted:
    js = ("(function(){var d=document.createElement('div');d.style.display='none';"
          f"d.textContent={_js_string(text)};document.body.appendChild(d);}})();")
    return Planted(insert_body(page, f"<script>{js}</script>", rng), "hidden_css")


def _script_literal(page: str, text: str, rng: random.Random) -> Planted:
    js = f'window.__siteConfig = {{"assistantNote": {_js_string(text)}, "theme": "light"}};'
    return Planted(insert_body(page, f"<script>{js}</script>", rng), "script")


def _css_content(page: str, text: str, rng: random.Random) -> Planted:
    cls = _cls(text)
    css = f".{cls} {{ display: none; }} .{cls}::before {{ content: {_css_string(text)}; }}"
    return Planted(insert_body(page, f'<style>{css}</style><span class="{cls}"></span>', rng), "css_content")


def _iframe_srcdoc(page: str, text: str, rng: random.Random) -> Planted:
    inner = f"<p>{_esc(text)}</p>"
    return Planted(insert_body(page, f'<iframe title="widget" style="display:none" srcdoc="{_attr(inner)}"></iframe>',
                               rng), "hidden_css")


def _svg_desc(page: str, text: str, rng: random.Random) -> Planted:
    svg = f'<svg width="16" height="16" role="img"><title>Logo</title><desc>{_esc(text)}</desc></svg>'
    return Planted(insert_body(page, svg, rng), "svg")


def _visible(page: str, text: str, rng: random.Random) -> Planted:
    return Planted(insert_body(page, f"<p>{_esc(text)}</p>", rng), "visible")


TECHNIQUES: dict[str, Callable[[str, str, random.Random], Planted]] = {
    "html_comment": _comment,
    "display_none": _div("display:none"),
    "visibility_hidden": _div("visibility:hidden;position:absolute"),
    "opacity_zero": _div("opacity:0"),
    "zero_font": _div("font-size:0"),
    "offscreen": _div("position:absolute;left:-9999px"),
    "clip_sr_only": _div("position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0)"),
    "color_match": _div("color:#ffffff;background-color:#ffffff"),
    "hidden_attr": _hidden_attr,
    "hidden_input": _hidden_input,
    "meta_description": _meta,
    "jsonld": _jsonld,
    "img_alt": _img_alt,
    "aria_label": _aria_label,
    "data_attribute": _data_attr,
    "noscript": _noscript,
    "template": _template,
    "unicode_tags": _unicode_tags,
    "zero_width_split": _zero_width,
    "external_css": _external_css,
    "js_inserted": _js_inserted,
    "script_literal": _script_literal,
    "css_content": _css_content,
    "iframe_srcdoc": _iframe_srcdoc,
    "svg_desc": _svg_desc,
    "visible": _visible,
}
HIDDEN_TECHNIQUES = tuple(t for t in TECHNIQUES if t != "visible")
# Techniques whose text a static (no-browser) scan of v0.3 had no extractor for. Kept in the bench on purpose.
STATIC_BLIND_V03 = ("js_inserted", "script_literal", "css_content", "iframe_srcdoc", "svg_desc")


def plant(page: str, text: str, technique: str, seed: str) -> Planted:
    rng = random.Random(hashlib.sha256(seed.encode()).hexdigest())
    return TECHNIQUES[technique](page, text, rng)


def planted_text(text: str, technique: str) -> str:
    """The text an extractor would recover for this technique (unicode tags drop non-ASCII)."""
    if technique == "unicode_tags":
        return "".join(c for c in text if 0x20 <= ord(c) <= 0x7E)
    return text
