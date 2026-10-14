"""Small, bounded CSS cascade for the static extractor.

Supports:
  * inline ``<style>`` blocks and (optionally) external ``<link rel=stylesheet>`` sheets fetched
    through a caller-supplied resolver (the static pass never fetches anything by itself);
  * ``@media`` blocks (applied, except ``print``/``speech``); ``@font-face``/``@keyframes``/etc. skipped;
  * simple compound selectors (``tag.class#id``) through a fast index, and complex selectors
    (descendant/child/attribute/``:not()``...) through soupsieve, but only for rules that set a
    visibility-relevant property and only up to a budget (pages with huge stylesheets stay fast);
  * specificity + source order + ``!important``.

It is an approximation of the browser cascade: no inheritance of ``visibility`` overrides,
no pseudo-elements, no state pseudo-classes (``:hover``), no layout. The rendered pass
(render.py) is the ground truth when it matters.
"""
from __future__ import annotations

import re
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag

CssResolver = Callable[[str], "str | None"]

# Properties that can make text invisible (or set colours used by colour-match detection).
HIDING_PROPS = {
    "display", "visibility", "opacity", "font-size", "width", "height", "max-width", "max-height",
    "overflow", "transform", "position", "left", "top", "right", "text-indent", "clip", "clip-path",
    "content-visibility", "-webkit-text-fill-color",
}
COLOR_PROPS = {"color", "background", "background-color"}
RELEVANT_PROPS = HIDING_PROPS | COLOR_PROPS
# Hard limits that keep the static pass bounded on hostile or giant pages.
MAX_CSS_BYTES = 1_500_000
MAX_COMPLEX_SELECTORS = 400
SELECT_BUDGET_S = 0.75

_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
_SIMPLE_SEL_RE = re.compile(r"^([a-z][a-z0-9-]*|\*)?((?:[.#][\w-]+)*)$", re.I)
_UNSUPPORTED_PSEUDO_RE = re.compile(
    r"::|:(?:hover|focus|focus-within|focus-visible|active|visited|link|target|before|after|"
    r"first-line|first-letter|selection|placeholder|checked|disabled|enabled|invalid|valid|"
    r"focus-visible|placeholder-shown|autofill|fullscreen|popover-open|modal|open|defined)\b", re.I)


@dataclass(frozen=True)
class CssRule:
    selector: str
    decls: dict[str, str]
    important: frozenset[str]
    specificity: tuple[int, int, int]
    order: int


def attr_str(el: Tag, name: str) -> str:
    """An attribute as a plain string (multi-valued attributes such as class are space-joined)."""
    v = el.get(name)
    if isinstance(v, list):
        return " ".join(str(x) for x in v)
    return str(v) if v is not None else ""


def parse_decls(style: str | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if not style:
        return out
    for part in style.split(";"):
        if ":" in part:
            k, v = part.split(":", 1)
            out[k.strip().lower()] = v.strip().lower().replace("!important", "").strip()
    return out


def _important_props(body: str) -> frozenset[str]:
    imp = set()
    for part in body.split(";"):
        if ":" in part and "!important" in part.lower():
            imp.add(part.split(":", 1)[0].strip().lower())
    return frozenset(imp)


def specificity(sel: str) -> tuple[int, int, int]:
    s = re.sub(r"\"[^\"]*\"|'[^']*'", "", sel)
    ids = len(re.findall(r"#[\w-]+", s))
    classes = len(re.findall(r"\.[\w-]+|\[[^\]]*\]|:(?!not\b|is\b|where\b)[\w-]+", s))
    tags = len(re.findall(r"(?:^|[\s>+~(])([a-z][a-z0-9-]*)", s, re.I))
    return ids, classes, tags


def _blocks(css: str):
    """Yield (selector_text, body) for style rules, descending into @media/@supports."""
    i, n = 0, len(css)
    while i < n:
        brace = css.find("{", i)
        if brace < 0:
            return
        prelude = css[i:brace].strip()
        # find the matching close brace
        depth, j = 1, brace + 1
        while j < n and depth:
            if css[j] == "{":
                depth += 1
            elif css[j] == "}":
                depth -= 1
            j += 1
        inner = css[brace + 1:j - 1]
        # a stray ';' terminated statement (e.g. @import / @charset) can precede the prelude
        if ";" in prelude and prelude.lstrip().startswith("@"):
            prelude = prelude.rsplit(";", 1)[-1].strip()
        low = prelude.lower()
        if low.startswith("@media"):
            if not re.search(r"\b(?:print|speech)\b", low) or re.search(r"\b(?:screen|all)\b", low):
                yield from _blocks(inner)
        elif low.startswith(("@supports", "@layer", "@container", "@document")):
            yield from _blocks(inner)
        elif low.startswith("@"):
            pass  # @font-face, @keyframes, @page, ...
        elif prelude:
            yield prelude, inner
        i = j


def parse_css(css: str, start_order: int = 0) -> list[CssRule]:
    css = _COMMENT_RE.sub("", css[:MAX_CSS_BYTES])
    rules: list[CssRule] = []
    order = start_order
    for sel_text, body in _blocks(css):
        decls = {k: v for k, v in parse_decls(body).items() if k in RELEVANT_PROPS}
        if not decls:
            continue
        imp = _important_props(body)
        for sel in sel_text.split(","):
            sel = sel.strip()
            if not sel:
                continue
            rules.append(CssRule(sel, decls, imp, specificity(sel), order))
            order += 1
    return rules


def collect_css(soup: BeautifulSoup, resolver: CssResolver | None = None, base_url: str = "") -> list[str]:
    """Inline <style> text plus resolved external sheets, in document order."""
    sheets: list[str] = []
    for el in soup.find_all(["style", "link"]):
        if el.name == "style":
            media = attr_str(el, "media").lower()
            if "print" in media and "screen" not in media:
                continue
            sheets.append(el.get_text() or "")
        elif resolver is not None:
            rel = " ".join(el.get("rel") or []).lower() if isinstance(el.get("rel"), list) else str(
                el.get("rel") or "").lower()
            href = el.get("href")
            media = attr_str(el, "media").lower()
            if "stylesheet" not in rel or not href or "alternate" in rel:
                continue
            if "print" in media and "screen" not in media:
                continue
            try:
                text = resolver(urljoin(base_url, str(href)) if base_url else str(href))
            except Exception:  # resolver failures must never break extraction
                text = None
            if text:
                sheets.append(text)
    return sheets


@dataclass
class StyleIndex:
    """Pre-computed rule matches for one document."""

    by_id: dict[str, list[CssRule]] = field(default_factory=lambda: defaultdict(list))
    by_class: dict[str, list[CssRule]] = field(default_factory=lambda: defaultdict(list))
    by_tag: dict[str, list[CssRule]] = field(default_factory=lambda: defaultdict(list))
    universal: list[CssRule] = field(default_factory=list)
    complex_matches: dict[int, list[CssRule]] = field(default_factory=lambda: defaultdict(list))
    complex_skipped: int = 0

    def __bool__(self) -> bool:
        return bool(self.by_id or self.by_class or self.by_tag or self.universal or self.complex_matches)

    def computed(self, el: Tag) -> dict[str, str]:
        cands: list[CssRule] = []
        eid = el.get("id")
        if isinstance(eid, str) and eid in self.by_id:
            cands += self.by_id[eid]
        classes: list[str] = list(el.get("class") or [])
        for c in classes:
            cands += self.by_class.get(c, [])
        cands += self.by_tag.get(el.name, [])
        cands += self.universal
        cands += self.complex_matches.get(id(el), [])
        if not cands:
            return parse_decls(attr_str(el, "style"))
        matched = [r for r in {id(r): r for r in cands}.values() if _simple_match(r, el)]
        matched.sort(key=lambda r: (r.specificity, r.order))
        out: dict[str, str] = {}
        important: dict[str, str] = {}
        for r in matched:
            for k, v in r.decls.items():
                if k in r.important:
                    important[k] = v
                else:
                    out[k] = v
        out.update(parse_decls(attr_str(el, "style")))
        out.update(important)
        return out


def _simple_parts(sel: str):
    m = _SIMPLE_SEL_RE.match(sel)
    if not m:
        return None
    tag = m.group(1).lower() if m.group(1) and m.group(1) != "*" else None
    parts = re.findall(r"([.#])([\w-]+)", m.group(2) or "")
    classes = frozenset(n for k, n in parts if k == ".")
    ids = [n for k, n in parts if k == "#"]
    return tag, classes, (ids[0] if ids else None)


def _simple_match(r: CssRule, el: Tag) -> bool:
    parts = _simple_parts(r.selector)
    if parts is None:
        return True  # complex rule: matched by soupsieve already
    tag, classes, rid = parts
    if tag and tag != el.name:
        return False
    if classes and not classes <= set(el.get("class") or []):
        return False
    return not (rid and rid != el.get("id"))


def build_index(soup: BeautifulSoup, sheets: list[str]) -> StyleIndex:
    idx = StyleIndex()
    order = 0
    rules: list[CssRule] = []
    for css in sheets:
        parsed = parse_css(css, order)
        order += len(parsed) + 1
        rules += parsed
    complex_rules = []
    for r in rules:
        parts = _simple_parts(r.selector)
        if parts is None:
            if _UNSUPPORTED_PSEUDO_RE.search(r.selector):
                continue
            # complex selectors only matter if they can hide text
            if set(r.decls) & HIDING_PROPS:
                complex_rules.append(r)
            continue
        tag, classes, rid = parts
        if rid:
            idx.by_id[rid].append(r)
        elif classes:
            idx.by_class[next(iter(sorted(classes)))].append(r)
        elif tag:
            idx.by_tag[tag].append(r)
        else:
            idx.universal.append(r)
    if complex_rules:
        deadline = time.monotonic() + SELECT_BUDGET_S
        for n, r in enumerate(complex_rules):
            if n >= MAX_COMPLEX_SELECTORS or time.monotonic() > deadline:
                idx.complex_skipped = len(complex_rules) - n
                break
            try:
                for el in soup.select(r.selector):
                    idx.complex_matches[id(el)].append(r)
            except Exception:  # soupsieve raises on selectors it can't parse
                continue
    return idx
