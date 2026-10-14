"""Stage 1a: deterministic extraction of candidate machine-targeted text.

Pulls out text that a human visitor would NOT normally see but an AI agent
reading raw HTML / the DOM / the accessibility tree might:

  comment       HTML comments
  meta          <meta content>, <title>
  hidden_css    text hidden via inline style, `hidden` attr, or simple <style> rules
                (display:none, visibility, opacity:0, zero size/font, off-screen,
                clip, color matching background)
  aria_hidden   aria-hidden="true" subtrees
  attribute     alt / title / aria-label / aria-description / placeholder / data-*
  jsonld        string values inside application/ld+json
  non_rendered  <noscript>, <template>
  invisible_unicode  Unicode tag-character runs (decoded)
  http_header   non-standard response headers
  visible       ordinary visible text blocks (scored with a lower factor)

This is a static approximation. External stylesheets are applied only when the caller
passes a ``css_resolver`` (the static pass never fetches anything itself); JS-driven hiding
is only caught by the optional rendered pass (render.py).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from bs4 import BeautifulSoup, Comment, Doctype, NavigableString, Tag
from bs4.element import CData, Declaration, ProcessingInstruction

from .css import CssResolver, StyleIndex, attr_str, build_index, collect_css, parse_decls
from .textutil import clean_for_scoring, find_unicode_tag_runs, has_zero_width_obfuscation

__all__ = ["Candidate", "extract_candidates", "hidden_reason", "parse_color", "parse_decls", "visible_text"]

BLOCK_TAGS = {
    "p", "div", "li", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6", "section", "article",
    "header", "footer", "nav", "aside", "main", "blockquote", "pre", "figcaption", "dd", "dt",
    "form", "fieldset", "table", "ul", "ol", "dl", "body", "address", "details", "summary",
}
SKIP_TAGS = {"script", "style", "svg", "math", "iframe", "object", "canvas", "head"}
NON_RENDERED_TAGS = {"noscript", "template"}
CODE_TAGS = {"code", "pre", "kbd", "samp", "blockquote", "q"}
# Agent-markup tags that HTML parsers treat as unknown elements; keep a textual marker
AGENT_MARKUP_TAGS = {"function_calls", "invoke", "tool_use", "tool_call", "tool_calls", "system", "system_prompt"}
TEXT_ATTRS = ("alt", "title", "aria-label", "aria-description", "placeholder")

STANDARD_HEADERS = {
    "accept-ranges", "access-control-allow-origin", "access-control-allow-credentials",
    "access-control-allow-headers", "access-control-allow-methods", "access-control-expose-headers",
    "access-control-max-age", "age", "alt-svc", "cache-control", "connection", "content-encoding",
    "content-language", "content-length", "content-security-policy", "content-security-policy-report-only",
    "content-type", "cross-origin-embedder-policy", "cross-origin-opener-policy",
    "cross-origin-resource-policy", "date", "etag", "expect-ct", "expires", "keep-alive",
    "last-modified", "link", "location", "nel", "permissions-policy", "pragma", "referrer-policy",
    "report-to", "reporting-endpoints", "server", "server-timing", "set-cookie",
    "strict-transport-security", "timing-allow-origin", "transfer-encoding", "vary", "via",
    "x-content-type-options", "x-frame-options", "x-xss-protection", "x-cache", "x-cache-hits",
    "x-served-by", "x-timer", "x-request-id", "x-amz-cf-id", "x-amz-cf-pop", "cf-ray",
    "cf-cache-status", "x-powered-by", "x-dns-prefetch-control", "origin-agent-cluster",
    "x-download-options", "x-permitted-cross-domain-policies", "priority", "x-runtime",
}

NAMED_COLORS = {
    "white": (255, 255, 255), "black": (0, 0, 0), "red": (255, 0, 0), "green": (0, 128, 0),
    "blue": (0, 0, 255), "gray": (128, 128, 128), "grey": (128, 128, 128),
    "silver": (192, 192, 192), "yellow": (255, 255, 0), "whitesmoke": (245, 245, 245),
    "snow": (255, 250, 250), "ivory": (255, 255, 240), "navy": (0, 0, 128),
}
DEFAULT_FG = (0, 0, 0)
DEFAULT_BG = (255, 255, 255)
COLOR_MATCH_DIST = 40.0


@dataclass
class Candidate:
    text: str
    location: str
    techniques: list[str] = field(default_factory=list)
    path: str = ""
    in_code: bool = False

    def to_dict(self) -> dict:
        return {"text": self.text, "location": self.location, "techniques": self.techniques,
                "path": self.path, "in_code": self.in_code}


# ---------------------------------------------------------------- CSS helpers

RGB = tuple[int, int, int]


def parse_color(v: str | None) -> RGB | None:
    if not v:
        return None
    v = v.strip().lower()
    for tok in v.split():
        if tok in NAMED_COLORS:
            return NAMED_COLORS[tok]
    m = re.search(r"#([0-9a-f]{6}|[0-9a-f]{3})\b", v)
    if m:
        h = m.group(1)
        if len(h) == 3:
            h = "".join(c * 2 for c in h)
        return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))
    m = re.search(r"rgba?\(\s*(\d+)[\s,]+(\d+)[\s,]+(\d+)(?:[\s,/]+(\d*\.?\d+))?", v)
    if m:
        if m.group(4) is not None and float(m.group(4)) == 0:
            return None  # fully transparent
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None


def _is_transparent(v: str | None) -> bool:
    if not v:
        return False
    v = v.strip().lower()
    if v == "transparent":
        return True
    if re.search(r"rgba?\(\s*[\d.]+%?[\s,]+[\d.]+%?[\s,]+[\d.]+%?\s*[,/]\s*(?:0(?:\.0+)?|\.0+)%?\s*\)", v):
        return True
    m = re.fullmatch(r"#[0-9a-f]{8}", v)
    return bool(m and v.endswith("00"))


def _px(v: str | None) -> float | None:
    if v is None:
        return None
    m = re.match(r"^\s*(-?\d*\.?\d+)\s*(px|em|rem|pt|%)?\s*$", v)
    if not m:
        return None
    num = float(m.group(1))
    unit = m.group(2) or "px"
    return num * 16 if unit in ("em", "rem") else num


def hidden_reason(d: dict[str, str]) -> str | None:
    if d.get("display") == "none":
        return "display:none"
    if d.get("visibility") in ("hidden", "collapse"):
        return "visibility:hidden"
    op = d.get("opacity")
    if op is not None:
        try:
            if float(op) <= 0.01:
                return "opacity:0"
        except ValueError:
            pass
    fs = _px(d.get("font-size"))
    if fs is not None and fs < 2:
        return "zero_font"
    overflow_hidden = "hidden" in d.get("overflow", "") or "clip" in d.get("overflow", "")
    for p in ("width", "height", "max-height", "max-width"):
        val = _px(d.get(p))
        if val is not None and val <= 1 and overflow_hidden:
            return "zero_size"
    if re.search(r"scale\(\s*0(?:\.0+)?\s*[,)]", d.get("transform", "")):
        return "zero_size"
    if d.get("position") in ("absolute", "fixed"):
        for p in ("left", "top", "right"):
            val = _px(d.get(p))
            if val is not None and val <= -500:
                return "offscreen"
    ti = _px(d.get("text-indent"))
    if ti is not None and ti <= -500:
        return "offscreen"
    if re.search(r"rect\(\s*0", d.get("clip", "")) or re.search(
            r"inset\(\s*(?:50|100)%|circle\(\s*0(?:px|%)?\s*[)a]", d.get("clip-path", "")):
        return "clip"
    if d.get("content-visibility") == "hidden":
        return "content-visibility:hidden"
    if _is_transparent(d.get("color")) or _is_transparent(d.get("-webkit-text-fill-color")):
        return "transparent_text"
    return None


def _bg_from(d: dict[str, str]) -> RGB | None:
    return parse_color(d.get("background-color")) or parse_color(d.get("background"))


def _el_path(el: Tag) -> str:
    s = el.name
    if el.get("id"):
        s += "#" + attr_str(el, "id")
    cls = el.get("class")
    if cls:
        s += "." + ".".join(cls[:2])
    return s


def _color_dist(a: RGB, b: RGB) -> float:
    return sum((x - y) ** 2 for x, y in zip(a, b, strict=False)) ** 0.5


# ---------------------------------------------------------------- main extractor

def extract_candidates(html: str, headers: dict[str, str] | None = None,
                       css_resolver: CssResolver | None = None, base_url: str = "") -> list[Candidate]:
    """Extract every machine-readable-but-not-human-visible text candidate from ``html``.

    ``css_resolver(url) -> css_text | None`` lets callers supply external stylesheets (for example
    from the same WARC, a cache, or a polite same-origin fetch). Without it only inline CSS applies.
    """
    soup = BeautifulSoup(html, "lxml")
    cands: list[Candidate] = []
    styles = build_index(soup, collect_css(soup, css_resolver, base_url))

    # 1. Comments (anywhere in the doc)
    for com in soup.find_all(string=lambda s: isinstance(s, Comment)):
        if clean_for_scoring(str(com)):
            cands.append(Candidate(str(com).strip(), "comment", ["html_comment"], "<!-- -->"))

    # 2. Meta + title
    for m in soup.find_all("meta"):
        content = attr_str(m, "content")
        key = (attr_str(m, "name") or attr_str(m, "property") or attr_str(m, "http-equiv")
               or attr_str(m, "itemprop") or "?")
        if content and clean_for_scoring(content):
            cands.append(Candidate(content, "meta", [f"meta[{key.lower()}]"], f"meta[{key}]"))
    if soup.title and soup.title.string:
        cands.append(Candidate(str(soup.title.string), "meta", ["title"], "title"))

    # 3. JSON-LD
    for sc in soup.find_all("script", attrs={"type": re.compile("ld\\+json", re.I)}):
        raw = sc.string or sc.get_text() or ""
        try:
            data = json.loads(raw)
            for keypath, val in _json_strings(data, ""):
                if len(val) >= 20:
                    cands.append(Candidate(val, "jsonld", ["json-ld"], f"ld+json{keypath}"))
        except (ValueError, RecursionError):
            if clean_for_scoring(raw):
                cands.append(Candidate(raw, "jsonld", ["json-ld", "unparseable"], "ld+json"))

    # 4. Attributes
    for el in soup.find_all(True):
        if el.name in ("script", "style", "meta"):
            continue
        for a in TEXT_ATTRS:
            v = el.get(a)
            if isinstance(v, str) and len(v.strip()) >= 12:
                loc_tech = f"{el.name}@{a}"
                cands.append(Candidate(v, "attribute", [loc_tech], _el_path(el)))
        for a, v in el.attrs.items():
            if a.startswith("data-") and isinstance(v, str) and " " in v.strip() and len(v) >= 30:
                cands.append(Candidate(v, "attribute", [f"{el.name}@{a}"], _el_path(el)))
        if el.name == "input" and attr_str(el, "type").lower() == "hidden":
            v = el.get("value")
            if isinstance(v, str) and " " in v.strip() and len(v) >= 20:
                cands.append(Candidate(v, "hidden_css", ["input[type=hidden]"], _el_path(el)))

    # 5. Text walk with inherited visibility state
    cands.extend(_walk_text(soup, styles))

    # 6. Unicode tag smuggling anywhere in the raw document
    for decoded in find_unicode_tag_runs(html):
        if decoded.strip():
            cands.append(Candidate(decoded, "invisible_unicode", ["unicode_tags"], "U+E00xx"))

    # 7. HTTP headers
    for k, v in (headers or {}).items():
        if k.lower() not in STANDARD_HEADERS and v and len(v) >= 8:
            cands.append(Candidate(v, "http_header", [f"header:{k.lower()}"], f"header:{k}"))

    # Zero-width obfuscation tagging
    for c in cands:
        if has_zero_width_obfuscation(c.text) and "zero_width" not in c.techniques:
            c.techniques.append("zero_width")
    return cands


def _json_strings(obj: object, path: str, depth: int = 0):
    if depth > 20:
        return
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _json_strings(v, f"{path}.{k}", depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _json_strings(v, f"{path}[{i}]", depth + 1)


@dataclass
class _State:
    hidden: str | None = None          # technique if hidden
    hidden_root: int | None = None
    hidden_path: str = ""
    aria_root: int | None = None
    aria_path: str = ""
    nonrender: str | None = None
    nonrender_root: int | None = None
    fg: RGB = DEFAULT_FG
    bg: RGB = DEFAULT_BG
    block_root: int | None = None
    block_path: str = ""
    in_code: bool = False


def _walk_text(soup: BeautifulSoup, styles: StyleIndex | None = None) -> list[Candidate]:
    if styles is None:
        styles = build_index(soup, collect_css(soup))
    root = soup.body or soup
    groups: dict[tuple, dict] = {}
    order: list[tuple] = []

    def add(key: tuple, text: str, loc: str, tech: str | None, path: str, in_code: bool) -> None:
        if key not in groups:
            groups[key] = {"parts": [], "loc": loc, "tech": tech, "path": path, "in_code": in_code}
            order.append(key)
        else:
            # a group counts as "code" only if every part of it is inside a code element
            groups[key]["in_code"] = groups[key]["in_code"] and in_code
        groups[key]["parts"].append(text)

    # body/html background
    base = _State(block_root=id(root), block_path=getattr(root, "name", "doc") or "doc")
    for anc in (soup.find("html"), soup.body):
        if isinstance(anc, Tag):
            d = styles.computed(anc)
            base.bg = _bg_from(d) or base.bg
            base.fg = parse_color(d.get("color")) or base.fg

    stack: list[tuple] = [(child, base) for child in reversed(list(root.children))]
    while stack:
        node, st = stack.pop()
        if isinstance(node, (Comment, Doctype, CData, Declaration, ProcessingInstruction)):
            continue
        if isinstance(node, NavigableString):
            raw = str(node)
            if not raw.strip():
                continue
            _emit(add, raw, st)
            continue
        if not isinstance(node, Tag):
            continue
        name = node.name
        if name in SKIP_TAGS:
            continue
        d = styles.computed(node)
        ns = _State(**st.__dict__)
        if name in NON_RENDERED_TAGS and not ns.nonrender:
            ns.nonrender, ns.nonrender_root = name, id(node)
        if not ns.hidden:
            r = hidden_reason(d)
            if r is None and node.has_attr("hidden"):
                r = "hidden_attr"
            if r is None and (name == "input" and attr_str(node, "type").lower() == "hidden"):
                r = "input[type=hidden]"
            if r:
                ns.hidden, ns.hidden_root, ns.hidden_path = r, id(node), _el_path(node)
        if ns.aria_root is None and attr_str(node, "aria-hidden").lower() == "true":
            ns.aria_root, ns.aria_path = id(node), _el_path(node)
        fg = parse_color(d.get("color"))
        bg = _bg_from(d)
        if fg:
            ns.fg = fg
        if bg:
            ns.bg = bg
        if name in BLOCK_TAGS:
            ns.block_root, ns.block_path = id(node), _el_path(node)
        if name in CODE_TAGS:
            ns.in_code = True
        if name in AGENT_MARKUP_TAGS:
            # Preserve the tag as text so the scorer can see tool-call markup
            add(_key(ns), f"<{name}>", *_loc(ns), ns.in_code)
        for child in reversed(list(node.children)):
            stack.append((child, ns))

    out = []
    for key in order:
        g = groups[key]
        text = " ".join(p.strip() for p in g["parts"] if p.strip())
        if not text:
            continue
        out.append(Candidate(text, g["loc"], [g["tech"]] if g["tech"] else [], g["path"], g["in_code"]))
    return out


def _loc(st: _State) -> tuple[str, str | None, str]:
    if st.nonrender:
        return "non_rendered", st.nonrender, st.nonrender
    if st.hidden:
        return "hidden_css", st.hidden, st.hidden_path
    if st.aria_root is not None:
        return "aria_hidden", "aria-hidden", st.aria_path
    if _color_dist(st.fg, st.bg) < COLOR_MATCH_DIST:
        return "hidden_css", "color_match", st.block_path
    return "visible", None, st.block_path


def _key(st: _State) -> tuple:
    loc, tech, _ = _loc(st)
    if loc == "non_rendered":
        return (loc, st.nonrender_root)
    if loc == "hidden_css" and tech != "color_match":
        return (loc, st.hidden_root)
    if loc == "aria_hidden":
        return (loc, st.aria_root)
    return (loc, tech, st.block_root, st.in_code)


def _emit(add, raw: str, st: _State) -> None:
    loc, tech, path = _loc(st)
    add(_key(st), raw, loc, tech, path, st.in_code)


def visible_text(html: str) -> str:
    """Text a human would plausibly see (static approximation)."""
    return "\n".join(c.text for c in _walk_text(BeautifulSoup(html, "lxml")) if c.location == "visible")
