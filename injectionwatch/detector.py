"""Two-stage detector: extract -> rule score -> (LLM) classify -> findings."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from .classify import FLAG_INTENTS, Classifier, HeuristicClassifier, severity_of
from .css import CssResolver
from .extract import Candidate, extract_candidates
from .scorer import page_is_discussion, score_text
from .textutil import clean_for_scoring, excerpt, normalize_payload, payload_hash

MIN_FLAG_CONFIDENCE = 0.4
RECALL_MIN_CHARS = 40
RECALL_MAX_CALLS = 25
RECALL_MIN_CONFIDENCE = 0.6
# Gate for llm_recall_mode: a near-miss is only worth an LLM call if it mentions an AI system
# (any of the supported languages) or already matched at least one rule.
_AI_TERM_RE = re.compile(
    r"\b(?:ai|a\.i\.|llms?|gpt|chatgpt|claude|gemini|copilot|chatbots?|bots?|assistants?|agents?|"
    r"(?:language|ai)\s+models?|ia|ki|ki-\w+)\b|ии|нейросет|ассистент|人工智能|人工智慧|语言模型|語言模型|助手|"
    r"言語モデル|アシスタント|エージェント|एआई|सहायक|ذكاء|مساعد|نموذج", re.I)


@dataclass
class Finding:
    payload_excerpt: str
    payload_hash: str
    location: str
    techniques: list[str]
    category: str
    intent: str
    target: str
    confidence: float
    heuristic_score: float
    reasons: list[str]
    path: str = ""
    classifier: str = "heuristic"

    @property
    def flagged(self) -> bool:
        return self.intent in FLAG_INTENTS and self.confidence >= MIN_FLAG_CONFIDENCE

    @property
    def severity(self) -> str:
        """ai_optout | defensive | promotional | manipulative | malicious | benign (see classify.SEVERITIES)."""
        return severity_of(self.category, self.intent)

    @property
    def is_signal(self) -> bool:
        """AI opt-out tokens are recorded as signals, not injections."""
        return self.severity == "ai_optout"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["flagged"] = self.flagged
        d["severity"] = self.severity
        return d


@dataclass
class ScanResult:
    url: str
    findings: list[Finding] = field(default_factory=list)
    candidates_examined: int = 0
    llm_calls: int = 0

    @property
    def verdict(self) -> str:
        return "flagged" if any(f.flagged for f in self.findings) else "clean"

    @property
    def signals(self) -> list[Finding]:
        return [f for f in self.findings if f.is_signal]

    def to_dict(self) -> dict[str, Any]:
        return {"url": self.url, "verdict": self.verdict, "candidates_examined": self.candidates_examined,
                "findings": [f.to_dict() for f in self.findings]}


def _recall_eligible(c: Candidate, has_hits: bool) -> bool:
    if c.location == "visible" or len(c.text) < RECALL_MIN_CHARS:
        return False
    return has_hits or bool(_AI_TERM_RE.search(clean_for_scoring(c.text)))


def scan_candidates(cands: list[Candidate], url: str = "", classifier: Classifier | None = None,
                    llm_recall_mode: bool = False, max_recall_calls: int = RECALL_MAX_CALLS) -> ScanResult:
    """``llm_recall_mode``: also send gated near-misses (non-visible, >=40 chars, mentions an AI system
    or matched a rule, at most ``max_recall_calls`` per page) to a non-heuristic classifier. Catches
    paraphrased payloads the rules miss, at extra (local) inference cost."""
    classifier = classifier or HeuristicClassifier()
    discussion = page_is_discussion([c.text for c in cands if c.location == "visible"])
    res = ScanResult(url=url, candidates_examined=len(cands))
    seen: set[tuple[str, str]] = set()
    recall_calls = 0
    for c in cands:
        sr = score_text(c.text, c.location, c.in_code, c.techniques, discussion)
        if not sr.fired:
            if not (llm_recall_mode and classifier.name != "heuristic" and recall_calls < max_recall_calls
                    and _recall_eligible(c, bool(sr.hits))):
                continue
            h = payload_hash(c.text)
            if (h, c.location) in seen:
                continue
            recall_calls += 1
            res.llm_calls += 1
            cl = classifier.classify(c.text, c.location, sr)
            if cl.intent not in FLAG_INTENTS or cl.confidence < RECALL_MIN_CONFIDENCE or "llm_error" in cl.source:
                continue
            seen.add((h, c.location))
            res.findings.append(Finding(
                payload_excerpt=excerpt(c.text), payload_hash=h, location=c.location,
                techniques=list(c.techniques), category=cl.category, intent=cl.intent, target=cl.target,
                confidence=round(cl.confidence * 0.8, 3), heuristic_score=sr.score,
                reasons=[*sr.reasons,
                         f"no rule fired; llm_recall_mode classifier[{cl.source}]: "
                         f"{cl.category}/{cl.intent} - {cl.rationale}",
                         f"placement: {', '.join(c.techniques) or c.location}"],
                path=c.path, classifier=cl.source))
            continue
        h = payload_hash(c.text)
        if (h, c.location) in seen:
            continue
        seen.add((h, c.location))
        if classifier.name != "heuristic":
            res.llm_calls += 1
        cl = classifier.classify(c.text, c.location, sr)
        heur_conf = min(0.99, sr.score / 8.0)
        conf = cl.confidence if cl.source.startswith("heuristic") else round(0.5 * heur_conf + 0.5 * cl.confidence, 3)
        reasons = list(sr.reasons)
        if c.techniques:
            reasons.append(f"hidden/placement technique: {', '.join(c.techniques)} at {c.path or c.location}")
        reasons.append(f"classifier[{cl.source}]: {cl.category}/{cl.intent} - {cl.rationale}")
        res.findings.append(Finding(
            payload_excerpt=excerpt(c.text), payload_hash=h, location=c.location,
            techniques=list(c.techniques), category=cl.category, intent=cl.intent, target=cl.target,
            confidence=round(conf, 3), heuristic_score=sr.score, reasons=reasons, path=c.path,
            classifier=cl.source,
        ))
    return res


def scan_html(html: str, url: str = "", headers: dict[str, str] | None = None,
              classifier: Classifier | None = None, rendered_candidates: list[Candidate] | None = None,
              llm_recall_mode: bool = False, css_resolver: CssResolver | None = None) -> ScanResult:
    """Full pipeline for one page. ``css_resolver`` optionally supplies external stylesheets
    (never fetched by the detector itself); ``rendered_candidates`` come from render.Renderer."""
    cands = extract_candidates(html, headers, css_resolver=css_resolver, base_url=url)
    if rendered_candidates:
        cands = merge_rendered(cands, rendered_candidates)
    return scan_candidates(cands, url, classifier, llm_recall_mode)


def merge_rendered(static: list[Candidate], rendered: list[Candidate]) -> list[Candidate]:
    """Rendered hidden text overrides a static 'visible' reading of the same text."""
    rendered_hidden = {normalize_payload(r.text): r for r in rendered if r.location != "visible"}
    out = []
    for c in static:
        r = rendered_hidden.get(normalize_payload(c.text))
        if c.location == "visible" and r is not None:
            out.append(Candidate(c.text, r.location, [*r.techniques, "rendered"] if "rendered" not in r.techniques
                                 else list(r.techniques), r.path or c.path, c.in_code))
            rendered_hidden.pop(normalize_payload(c.text))
        else:
            out.append(c)
    known = {normalize_payload(c.text) for c in out}
    for k, r in rendered_hidden.items():
        if k not in known:
            out.append(r)
    return out
