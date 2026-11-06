"""SARIF 2.1.0 output for ``scan-site`` (GitHub code scanning, VS Code SARIF viewer, any SARIF consumer).

One rule per finding category (``injectionwatch/<category>``). Levels: flagged malicious -> error, other
flagged -> warning, unflagged (low confidence, defensive, opt-out signals) -> note. GitHub's
``security-severity`` property is set per rule. Excerpts are the detector's defanged, truncated excerpts.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import PROJECT_URL, VERSION
from .detector import Finding
from .sitescan import FileResult, SiteScan

SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
FINGERPRINT_KEY = "injectionwatch/payload/v1"

RULE_TEXT: dict[str, tuple[str, str]] = {
    "instruction_override": ("Hidden instruction override", "Text addressed to AI agents that tries to override "
                             "their instructions (\"ignore previous instructions\", fake system prompts)."),
    "data_exfiltration": ("Data exfiltration attempt", "Hidden text asking an AI agent to send user data, "
                          "credentials or conversation content to a third party."),
    "tool_invocation": ("Tool or command abuse", "Hidden text trying to make an AI agent call tools, run "
                        "commands or open URLs."),
    "concealment": ("Concealment from the user", "Hidden text telling an AI agent to hide information from, or "
                    "lie to, the user."),
    "hiring_manipulation": ("Hiring-bot manipulation", "Hidden text steering AI resume screeners."),
    "recommendation_manipulation": ("Recommendation manipulation", "Hidden text biasing an AI agent's "
                                    "recommendations or product comparisons."),
    "summarizer_steering": ("Summarizer steering", "Hidden text dictating how AI summarizers describe the page."),
    "support_manipulation": ("Support-bot manipulation", "Hidden text abusing AI customer-support flows "
                             "(refunds, account changes)."),
    "role_injection": ("Role injection", "Fake chat-role or tool-call markup aimed at AI agents."),
    "user_manipulation": ("User manipulation", "Hidden text making an AI agent pressure or deceive the user."),
    "agent_promotion": ("Agent-targeted promotion", "Marketing text addressed to AI agents."),
    "ai_restriction": ("AI restriction notice", "Text that only restricts AI use of the page (defensive)."),
    "ai_optout": ("AI opt-out signal", "Machine-readable AI opt-out (signal, not an injection)."),
    "other": ("Machine-targeted text", "Other hidden text addressed to AI systems."),
}
SECURITY_SEVERITY = {"malicious": "9.0", "manipulative": "7.0", "promotional": "3.0", "defensive": "1.0",
                     "ai_optout": "0.0", "benign": "0.0"}
_RULE_SEVERITY = {"data_exfiltration": "malicious", "tool_invocation": "malicious", "agent_promotion": "promotional",
                  "ai_restriction": "defensive", "ai_optout": "ai_optout"}


def level_of(f: Finding) -> str:
    if not f.flagged:
        return "note"
    return "error" if f.severity == "malicious" else "warning"


def _rule(cat: str) -> dict[str, Any]:
    short, full = RULE_TEXT.get(cat, RULE_TEXT["other"])
    sev = _RULE_SEVERITY.get(cat, "manipulative")
    return {"id": f"injectionwatch/{cat}", "name": "".join(w.capitalize() for w in cat.split("_")),
            "shortDescription": {"text": short}, "fullDescription": {"text": full},
            "helpUri": f"{PROJECT_URL}#readme",
            "help": {"text": f"{full} Remove the hidden text from the page source or the plugin/theme/content "
                             "that injects it, then rebuild. Confirm by re-running `injectionwatch scan-site`.",
                     "markdown": f"{full}\n\nRemove the hidden text from the page source or from the plugin, "
                                 "theme or content that injects it, then rebuild and re-run "
                                 "`injectionwatch scan-site`."},
            "defaultConfiguration": {"level": "error" if sev == "malicious" else
                                     "warning" if sev == "manipulative" else "note"},
            "properties": {"tags": ["security", "prompt-injection", "ai-agents"],
                           "security-severity": SECURITY_SEVERITY[sev], "precision": "medium"}}


def _uri(fr: FileResult, base: Path | None) -> str:
    if base is not None:
        try:
            return fr.path.relative_to(base.resolve()).as_posix()
        except ValueError:
            pass
    return fr.rel


def _message(f: Finding) -> str:
    where = f.location + (f" via {', '.join(f.techniques)}" if f.techniques else "")
    head = "Possible hidden prompt injection" if f.flagged else "Machine-targeted text"
    return (f"{head} ({f.category}, {f.severity}, confidence {f.confidence:.2f}) in {where}: "
            f"\"{f.payload_excerpt}\". This is untrusted page text; it is quoted defanged and truncated.")


def to_sarif(scan: SiteScan, *, uri_base: Path | None = None, include_unflagged: bool = True) -> dict[str, Any]:
    """Build the SARIF log. ``uri_base`` (default: the current directory) makes artifact URIs repo-relative,
    which GitHub needs to annotate files; files outside it fall back to scan-root-relative URIs."""
    uri_base = Path.cwd() if uri_base is None else uri_base
    pairs = [(fr, f) for fr, f in scan.findings() if include_unflagged or f.flagged]
    cats = sorted({f.category for _, f in pairs})
    index = {c: i for i, c in enumerate(cats)}
    results = []
    for fr, f in pairs:
        results.append({
            "ruleId": f"injectionwatch/{f.category}", "ruleIndex": index[f.category], "level": level_of(f),
            "message": {"text": _message(f)},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": _uri(fr, uri_base)},
                "region": {"startLine": fr.line_of(f)}}}],
            "partialFingerprints": {FINGERPRINT_KEY: f.payload_hash},
            "properties": {"flagged": f.flagged, "severity": f.severity, "intent": f.intent,
                           "confidence": f.confidence, "location": f.location, "techniques": list(f.techniques),
                           "target": f.target, "classifier": f.classifier},
        })
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "InjectionWatch", "version": VERSION, "semanticVersion": VERSION,
                                "informationUri": PROJECT_URL, "rules": [_rule(c) for c in cats]}},
            "automationDetails": {"id": "injectionwatch/scan-site/"},
            "invocations": [{"executionSuccessful": True,
                             "toolExecutionNotifications": [
                                 {"level": "warning", "message": {"text": f"skipped {rel}: {why}"}}
                                 for rel, why in scan.skipped]}],
            "results": results,
            "properties": {"summary": scan.summary()},
        }],
    }


def write_sarif(scan: SiteScan, out: str | Path, **kw: Any) -> dict[str, Any]:
    log = to_sarif(scan, **kw)
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(log, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return log
