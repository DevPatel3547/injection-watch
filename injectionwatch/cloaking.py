"""Cloaking checker: does a page show AI-agent user-agents different content than browsers?

Method
  1. fetch twice with a normal browser UA -> baseline; text blocks that differ between the
     two baseline fetches are 'dynamic noise' (timestamps, rotating ads, CSRF tokens) and ignored;
  2. fetch once per AI-agent UA (config.AGENT_UAS);
  3. agent_only = blocks in the agent version not present in either baseline, minus noise,
     minus short/numeric blocks; run the injection scorer over agent_only blocks.

Limitations: UA-only. Sites that verify bots by IP range / reverse DNS (see AgentUA.verification)
will NOT be fooled, so IP-verified cloaking is invisible to this check. Browser-based agents that
use ordinary Chrome UAs cannot be distinguished by UA at all. Run only on candidate URLs, at low
volume, honoring robots.txt for the impersonated token.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .config import BROWSER_UA, AgentUA, fetchable_agents
from .detector import Finding, scan_candidates
from .extract import Candidate, extract_candidates
from .textutil import normalize_payload

MIN_BLOCK_CHARS = 25


_VOLATILE = re.compile(r"\b[0-9a-f]{8,}\b|\d+")


def _blocks(html: str) -> dict[str, Candidate]:
    """Keyed by normalized text with numbers/hex tokens masked, so per-request ids, timestamps
    and counters don't register as differences."""
    out = {}
    for c in extract_candidates(html):
        n = normalize_payload(c.text)
        if len(n) < MIN_BLOCK_CHARS or not re.search(r"[a-z]{3}", n):
            continue
        out[_VOLATILE.sub("#", n)] = c
    return out


@dataclass
class AgentDiff:
    agent: str
    operator: str
    ua_status: str
    status: int | None
    error: str | None
    agent_only: list[str] = field(default_factory=list)
    missing_for_agent: int = 0
    findings: list[Finding] = field(default_factory=list)


@dataclass
class CloakReport:
    url: str
    baseline_status: int | None
    noise_blocks: int
    diffs: list[AgentDiff] = field(default_factory=list)

    @property
    def cloaked(self) -> bool:
        return any(d.agent_only for d in self.diffs)

    @property
    def cloaked_injection(self) -> bool:
        return any(f.flagged for d in self.diffs for f in d.findings)

    def to_dict(self) -> dict:
        return {
            "url": self.url, "cloaked": self.cloaked, "cloaked_injection": self.cloaked_injection,
            "baseline_status": self.baseline_status, "noise_blocks": self.noise_blocks,
            "agents": [{"agent": d.agent, "operator": d.operator, "ua_status": d.ua_status, "status": d.status,
                        "error": d.error, "agent_only_blocks": [b[:200] for b in d.agent_only],
                        "missing_for_agent": d.missing_for_agent,
                        "findings": [f.to_dict() for f in d.findings]} for d in self.diffs],
        }


def check_cloaking(url: str, fetcher, agents: list[AgentUA] | None = None, classifier=None) -> CloakReport:
    """`fetcher` is a crawler.PoliteFetcher (or anything with .fetch(url, user_agent=, robots_token=))."""
    agents = agents or fetchable_agents()
    b1 = fetcher.fetch(url, user_agent=BROWSER_UA, robots_token="*")
    b2 = fetcher.fetch(url, user_agent=BROWSER_UA, robots_token="*")
    base1, base2 = _blocks(b1.text), _blocks(b2.text)
    noise = set(base1) ^ set(base2)
    baseline = set(base1) | set(base2)
    rep = CloakReport(url, b1.status, len(noise))
    for a in agents:
        r = fetcher.fetch(url, user_agent=a.user_agent, robots_token=a.name)
        d = AgentDiff(a.name, a.operator, a.ua_status, r.status, r.error)
        if r.text:
            ab = _blocks(r.text)
            only = [k for k in ab if k not in baseline and k not in noise]
            d.agent_only = [ab[k].text for k in only]
            d.missing_for_agent = len([k for k in base1 if k not in ab and k not in noise])
            if only:
                cands = [Candidate(ab[k].text, "cloaked", [f"ua_cloaking:{a.name}", ab[k].location, *ab[k].techniques],
                                   ab[k].path) for k in only]
                d.findings = scan_candidates(cands, url, classifier).findings
        rep.diffs.append(d)
    return rep
