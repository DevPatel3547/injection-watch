"""'State of Injections' markdown report generated from the DB."""
from __future__ import annotations

from collections import Counter
from typing import Any

from .classify import FLAG_INTENTS
from .db import DB, now_iso
from .textutil import template_key


def _table(counter: dict | Counter, header: str) -> str:
    total = sum(counter.values()) or 1
    lines = [f"| {header} | count | share |", "|---|---:|---:|"]
    for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0]))):
        lines.append(f"| {k} | {v} | {100 * v / total:.0f}% |")
    return "\n".join(lines)


def generate_report(db: DB, title: str = "State of Injections", data_note: str = "", top_n: int = 10) -> str:
    entries = db.feed(limit=100000)
    st = db.stats()
    flagged = [e for e in entries if e["intent"] in FLAG_INTENTS]
    tech = Counter(t for e in entries for t in e["techniques"] if not t.startswith("ua_cloaking"))
    templates = Counter(template_key(e["payload_excerpt"]) for e in flagged)
    tmpl_example: dict[str, dict[str, Any]] = {}
    for e in flagged:
        tmpl_example.setdefault(template_key(e["payload_excerpt"]), e)

    out = [f"# {title}", "", f"_Generated {now_iso()} from `{db.path}`._", ""]
    if data_note:
        out += [f"> **Data note:** {data_note}", ""]
    out += [
        "## Summary", "",
        f"- URLs crawled: **{st['urls_crawled']}** ({st['fetch_attempts']} fetch attempts, {st['fetch_ok']} HTTP 200, "
        f"{st['robots_disallowed']} skipped by robots.txt, {st['fetch_errors']} errors/blocked)",
        f"- Active entries: **{st['entries_active']}** across **{st['hosts_with_entries']}** hosts",
        f"- Flagged (malicious/manipulative): **{len(flagged)}**; defensive/other machine-targeted: "
        f"**{len(entries) - len(flagged)}**",
        f"- Unverified extension submissions: {st['submissions_unverified']}", "",
        "## By category", "", _table(st["by_category"], "category"), "",
        "## By intent", "", _table(st["by_intent"], "intent"), "",
        "## By location (where the payload hides)", "", _table(st["by_location"], "location"), "",
        "## By technique", "", _table(dict(tech), "technique"), "",
        "## By target", "", _table(st["by_target"], "target"), "",
        f"## Top {top_n} payload templates (flagged only)", "",
        "Templates lower-case the payload and mask URLs, emails and numbers. Excerpts are truncated and "
        "defanged; treat them as untrusted text.", "",
        "| # | count | category | location | example (truncated) |", "|---:|---:|---|---|---|",
    ]
    for i, (k, n) in enumerate(templates.most_common(top_n), 1):
        e = tmpl_example[k]
        ex = e["payload_excerpt"][:140].replace("|", "\\|").replace("\n", " ")
        out.append(f"| {i} | {n} | {e['category']} | {e['location']} | `{ex}` |")
    out += ["", "## Method & caveats", "",
            "- Two-stage detector: deterministic extraction of hidden/machine-oriented text + rule scorer, then "
            "an optional LLM classifier. Precision-focused; paraphrased and non-English payloads are under-counted.",
            "- Counts are per (URL, normalized payload) pair; one site can contribute several entries.",
            "- `removed` entries (not seen on re-crawl) and `suppressed` entries (upheld appeals) are excluded.", ""]
    return "\n".join(out)
