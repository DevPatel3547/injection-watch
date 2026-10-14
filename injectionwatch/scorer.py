"""Stage 1b: rule scorer for instruction-like text aimed at AI systems.

Precision-first design. A candidate *fires* only if

    score = (sum of rule weights [+ combo bonus]) x context factor >= threshold

AND (a ``standalone`` rule matched OR at least two rules from *counting* categories matched;
the weak ``imperative`` category never counts on its own).

Context factor (all values live in ``data/rules.json`` so the browser extension computes the
exact same numbers):

* location: visible text 0.6, hidden / non-rendered / machine-only locations 1.0;
* code: visible text inside ``<code>/<pre>/<blockquote>/<q>`` 0.25; hidden code 0.5;
* discussion: pages whose *visible* text discusses prompt injection (multilingual) x0.5 for
  visible candidates and x0.6 for hidden ones (quiz answers, spoilers, collapsed examples);
* quoted mention: if *every* rule match sits inside a quotation (``"..."``, ``'...'``, ``«...»``,
  ``「...」`` ...) and there is real framing text outside the quotes, x0.3. This is the
  "use vs. mention" distinction: *the attacker wrote "ignore previous instructions"* is a mention;
* zero-width keyword splitting raises the factor to at least 0.9 (obfuscation is a signal).

v0.3 real-web false-positive controls (from labelling Common Crawl hits):

* **agent context**: rules marked ``needs_context`` (credential / "send your data" phrasing, refund and
  verification policy text, "use the X plugin", hiring phrases...) only count when the same candidate also
  matched a rule from ``context_categories`` (addressing an AI, an override, a role token, concealment).
  Hidden login/sign-up modals and privacy or shipping tabs use exactly this vocabulary, but talk to humans;
* **single-count categories**: several ``ai_addressing`` phrases ("if you're an AI", "AI parsing this")
  count once toward the two-rule minimum, so a greeting to AI readers is not an instruction;
* **state blobs**: JSON app state (Inertia ``data-page``, job-board configs) and spintax SEO templates only
  fire when they address an AI.

Every firing records which rules matched, the matched snippet and the context adjustments.
"""
from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import Any

from .textutil import clean_for_scoring


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    weight: float
    standalone: bool
    pattern: re.Pattern[str]
    desc: str
    lang: str = "en"
    needs_context: bool = False
    # Literal prefilter: at least one of these (lower-cased) strings must occur in the text for
    # ``pattern`` to be able to match. None = no usable requirement (always evaluate).
    required: tuple[str, ...] | None = None

    def may_match(self, lowered: str) -> bool:
        return self.required is None or any(lit in lowered for lit in self.required)


def required_literals(pattern: str) -> tuple[str, ...] | None:
    """Derive a necessary-literal set from a regex (the RE2/Hyperscan "prefilter" idea).

    Returns strings such that any text the pattern matches (case-insensitively) contains at least one
    of them, lower-cased; or None when no such set can be derived. Pure speed optimisation: the
    test-suite checks that gated and ungated scoring agree on every fixture candidate.
    """
    try:
        import re._parser as sre  # type: ignore[import-not-found]  # CPython >= 3.11
        from re import _constants as c  # type: ignore[attr-defined]
    except ImportError:  # pragma: no cover - non-CPython
        return None

    def seq(items: Any) -> frozenset[str] | None:
        best: frozenset[str] | None = None
        run: list[str] = []

        def rarity(cand: frozenset[str]) -> int:
            # longer literals are rarer; non-ASCII literals (CJK, Cyrillic...) are much rarer on
            # the mostly-Latin web than short ASCII ones like "ai"
            return min(len(x) + (4 if any(ord(ch) > 127 for ch in x) else 0) for x in cand)

        def consider(cand: frozenset[str] | None) -> None:
            nonlocal best
            if cand and (best is None or rarity(cand) > rarity(best)):
                best = cand

        for op, av in items:
            if op is c.LITERAL:
                run.append(chr(av))
                continue
            if run:
                consider(frozenset({"".join(run)}))
                run = []
            consider(node(op, av))
        if run:
            consider(frozenset({"".join(run)}))
        return best

    def node(op: Any, av: Any) -> frozenset[str] | None:
        if op is c.SUBPATTERN:
            return seq(av[-1])
        if op is c.BRANCH:
            out: set[str] = set()
            for alt in av[1]:
                r = seq(alt)
                if not r:
                    return None
                out |= r
            return frozenset(out)
        if op in (c.MAX_REPEAT, c.MIN_REPEAT):
            lo, _hi, body = av
            return seq(body) if lo >= 1 else None
        return None  # IN, ANY, AT, ASSERT, NOT_LITERAL, ...

    try:
        req = seq(sre.parse(pattern, re.I))
    except Exception:  # pragma: no cover - defensive
        return None
    if not req or min(len(x) + (4 if any(ord(ch) > 127 for ch in x) else 0) for x in req) < 2:
        return None
    return tuple(sorted({x.lower() for x in req}))


@dataclass
class RuleHit:
    rule_id: str
    category: str
    weight: float
    match: str
    quoted: bool = False


@dataclass
class ScoreResult:
    score: float
    raw_score: float
    factor: float
    fired: bool
    hits: list[RuleHit] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    mention: bool = False
    suppressed: list[RuleHit] = field(default_factory=list)  # needs_context hits without agent context
    blob: bool = False

    @property
    def categories(self) -> list[str]:
        seen: list[str] = []
        for h in self.hits:
            if h.category not in seen:
                seen.append(h.category)
        return seen


def _nfkc(pattern: str) -> str:
    # Patterns are NFKC-normalised exactly like the text they are matched against.
    return unicodedata.normalize("NFKC", pattern)


def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(_nfkc(pattern), re.I)


@lru_cache(maxsize=1)
def load_rules() -> tuple[dict[str, Any], tuple[Rule, ...]]:
    cfg: dict[str, Any] = json.loads(
        resources.files("injectionwatch").joinpath("data/rules.json").read_text("utf-8"))
    rules = tuple(
        Rule(r["id"], r["category"], float(r["weight"]), bool(r["standalone"]), _compile(r["pattern"]),
             r.get("desc", ""), r.get("lang", "en"), bool(r.get("needs_context", False)),
             required_literals(_nfkc(r["pattern"])))
        for r in cfg["rules"]
    )
    return cfg, rules


@lru_cache(maxsize=1)
def _context_patterns() -> tuple[re.Pattern[str], re.Pattern[str]]:
    cfg, _ = load_rules()
    return _compile(cfg["discussion_pattern"]), _compile(cfg["quote_pattern"])


_SPINTAX_RE = re.compile(r"\{[^{}|\n]{1,60}\|[^{}\n]{1,200}\}")
_JSON_PAIR_RE = re.compile(r'"[^"\n]{1,80}"\s*:')


def is_state_blob(text: str) -> bool:
    """JSON app state or spintax template (mirrors iwIsBlob in extension/src/scorer.ts)."""
    cfg, _ = load_rules()
    t = text.lstrip()
    if t[:1] in ("{", "[") and len(_JSON_PAIR_RE.findall(t)) >= int(cfg.get("blob_min_json_pairs", 3)):
        return True
    return len(_SPINTAX_RE.findall(t)) >= int(cfg.get("blob_min_spintax", 3))


def location_factor(location: str, in_code: bool, techniques: list[str], page_is_discussion: bool) -> float:
    cfg, _ = load_rules()
    f = float(cfg["location_factors"].get(location, 1.0))
    if location == "visible":
        if in_code:
            f = float(cfg["in_code_factor"])
        elif page_is_discussion:
            f *= float(cfg["discussion_factor"])
    else:
        if in_code:
            f *= float(cfg["hidden_in_code_factor"])
        if page_is_discussion:
            f *= float(cfg["hidden_discussion_factor"])
    if "zero_width" in techniques:
        f = max(f, float(cfg["zero_width_min_factor"]))
    return f


def quoted_spans(text: str) -> list[tuple[int, int]]:
    _, quote_re = _context_patterns()
    return [m.span() for m in quote_re.finditer(text)]


def _all_inside(pattern: re.Pattern[str], text: str, spans: list[tuple[int, int]]) -> bool:
    for m in pattern.finditer(text):
        s, e = m.span()
        if not any(qs <= s and e <= qe for qs, qe in spans):
            return False
    return True


def _outside_len(text: str, spans: list[tuple[int, int]]) -> int:
    keep, pos = [], 0
    for s, e in spans:
        keep.append(text[pos:s])
        pos = e
    keep.append(text[pos:])
    return len(re.sub(r"\s+", "", "".join(keep)))


def score_text(text: str, location: str = "hidden_css", in_code: bool = False,
               techniques: list[str] | None = None, page_is_discussion: bool = False,
               use_prefilter: bool = True) -> ScoreResult:
    cfg, rules = load_rules()
    techniques = techniques or []
    t = clean_for_scoring(text)
    lowered = t.lower()
    found: list[tuple[Rule, re.Match[str]]] = []
    for r in rules:
        if use_prefilter and not r.may_match(lowered):
            continue
        m = r.pattern.search(t)
        if m:
            found.append((r, m))
    # Agent context (v0.3): needs_context rules only count when a rule from a context category
    # (addressing an AI, override, role token, concealment) matched the same candidate.
    context_cats = set(cfg.get("context_categories", []))
    has_context = any(not r.needs_context and r.category in context_cats for r, _ in found)
    suppressed = [RuleHit(r.id, r.category, r.weight, m.group(0).strip()[:80])
                  for r, m in found if r.needs_context and not has_context]
    if suppressed:
        found = [(r, m) for r, m in found if not r.needs_context]
    # One phrase is one signal: when several rules of the SAME category match overlapping text
    # (e.g. the English and French "ignore ... instructions" rules), keep only the heaviest.
    # Ties keep rule-file order. Mirrors iwScore() in extension/src/scorer.ts.
    order = sorted(range(len(found)), key=lambda i: (-found[i][0].weight, i))
    kept_idx: list[int] = []
    for i in order:
        r, m = found[i]
        s0, e0 = m.span()
        if any(found[k][0].category == r.category and s0 < found[k][1].end() and found[k][1].start() < e0
               for k in kept_idx):
            continue
        kept_idx.append(i)
    kept_idx.sort()
    hits: list[RuleHit] = []
    matched_rules: list[Rule] = []
    for i in kept_idx:
        r, m = found[i]
        hits.append(RuleHit(r.id, r.category, r.weight, m.group(0).strip()[:80]))
        matched_rules.append(r)
    raw = sum(h.weight for h in hits)
    cats = {h.category for h in hits}
    non_counting = set(cfg.get("non_counting_categories", ["imperative"]))
    if "ai_addressing" in cats and cats - {"ai_addressing"} - non_counting:
        raw += float(cfg["combo_bonus"])
    factor = location_factor(location, in_code, techniques, page_is_discussion)

    mention = False
    if hits:
        spans = quoted_spans(t)
        if spans:
            for h, r in zip(hits, matched_rules, strict=False):
                h.quoted = _all_inside(r.pattern, t, spans)
            if all(h.quoted for h in hits) and _outside_len(t, spans) >= int(cfg["mention_min_outside_chars"]):
                mention = True
                factor *= float(cfg["mention_factor"])

    score = round(raw * factor, 3)
    standalone = any(r.standalone for r in matched_rules)
    single = set(cfg.get("single_count_categories", []))
    counting = sum(1 for h in hits if h.category not in non_counting and h.category not in single)
    counting += sum(1 for c in single if c in cats)
    blob = bool(hits) and "ai_addressing" not in cats and is_state_blob(t)
    fired = score >= float(cfg["threshold"]) and (standalone or counting >= 2) and not blob
    reasons = [f"rule {h.rule_id} ({h.category}, +{h.weight:g}) matched '{h.match}'"
               + (" [inside quotes]" if h.quoted else "") for h in hits]
    reasons += [f"rule {h.rule_id} ({h.category}) matched '{h.match}' but ignored: no agent context"
                for h in suppressed]
    if hits:
        ctx = [f"location={location}", f"factor={factor:g}"]
        if in_code:
            ctx.append("in_code")
        if page_is_discussion:
            ctx.append("page_discusses_injection")
        if mention:
            ctx.append("quoted_mention")
        if "zero_width" in techniques:
            ctx.append("zero_width_obfuscation")
        if blob:
            ctx.append("state_blob_without_ai_addressing")
        reasons.append(" ".join(ctx))
    return ScoreResult(score, raw, factor, fired, hits, reasons, mention, suppressed, blob)


def page_is_discussion(visible_texts: list[str]) -> bool:
    discussion_re, _ = _context_patterns()
    return bool(discussion_re.search(clean_for_scoring(" ".join(visible_texts))))
