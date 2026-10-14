"""Build a static, zero-cost site for GitHub Pages (or any static host).

Output layout (``out/``)::

    index.html, app.js, style.css    dashboard: stats, breakdowns, searchable table, client-side URL check
    feed.json / feed.csv / stix.json the open feed (same formats as the API)
    meta.json                        generation metadata + aggregate stats
    lookup/<xx>.json                 per-host shards for client-side /check; xx = sha256(host)[:2]
    schema/feed-entry.schema.json    JSON Schema of one feed entry
    LICENSE-DATA.txt, robots.txt, .nojekyll

The static check can only answer "listed / not listed": the full list of clean URLs observed in a
crawl is far too large to publish, so ``not_listed`` never means "safe".
No inline scripts (CSP-friendly); all attacker-controlled text is rendered with textContent.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from collections import Counter, defaultdict
from importlib import resources
from pathlib import Path
from typing import Any

from . import export
from .classify import SEVERITIES
from .config import FEED_LICENSE, PROJECT_URL, VERSION
from .db import DB, now_iso
from .scorer import load_rules

SITE_ASSETS = ("index.html", "app.js", "style.css")
SHARD_FIELDS = ("url_norm", "payload_hash", "category", "intent", "severity", "review", "flagged", "location",
                "target", "confidence", "first_seen", "last_seen", "status")


def shard_key(host: str) -> str:
    return hashlib.sha256(host.lower().encode("utf-8")).hexdigest()[:2]


def build_shards(entries: list[dict[str, Any]]) -> dict[str, dict[str, list[dict[str, Any]]]]:
    shards: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for e in entries:
        pub = export.public_entry(e)
        pub["url_norm"] = e["url_norm"]
        shards[shard_key(e["host"])][e["host"]].append({k: pub.get(k) for k in SHARD_FIELDS})
    return {k: dict(v) for k, v in shards.items()}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def build_site(db: DB, out: str | Path, data_note: str = "", clean: bool = True,
               severities: list[str] | None = None, reviewed_only: bool = False) -> dict[str, Any]:
    """``severities``: effective severities to publish as feed entries (default: all except ai_optout, which is
    an opt-out *signal* and only appears as aggregate counts). ``reviewed_only``: only entries a human
    labelled true_positive."""
    out = Path(out)
    if clean and out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    sev = severities if severities is not None else [s for s in (*SEVERITIES, "benign") if s != "ai_optout"]
    entries = db.feed(limit=10_000_000, severities=sev, reviewed_only=reviewed_only)
    stats = db.stats()
    cfg, _ = load_rules()
    runs = db.scan_runs(limit=5)

    _write(out / "feed.json", export.to_json(entries))
    _write(out / "feed.csv", export.to_csv(entries))
    _write(out / "stix.json", export.to_stix(entries))
    shards = build_shards(entries)
    for key, hosts in shards.items():
        _write(out / "lookup" / f"{key}.json", json.dumps({"hosts": hosts}, ensure_ascii=False, separators=(",", ":")))
    _write(out / "schema" / "feed-entry.schema.json", json.dumps(export.FEED_ENTRY_SCHEMA, indent=2))
    meta = {
        "feed": "InjectionWatch", "version": VERSION, "rules_version": cfg["version"], "generated_at": now_iso(),
        "license": FEED_LICENSE, "source": PROJECT_URL, "warning": export.WARNING, "data_note": data_note,
        "count": len(entries), "flagged": sum(1 for e in entries if export.public_entry(e)["flagged"]),
        "published_severities": sev, "reviewed_only": reviewed_only,
        "published_by_severity": dict(Counter(export.public_entry(e)["severity"] for e in entries)),
        "published_by_category": dict(Counter(e["category"] for e in entries)),
        "published_by_location": dict(Counter(e["location"] for e in entries)),
        "published_hosts": len({e["host"] for e in entries}),
        "signals": stats.get("signals", {}),
        "stats": stats, "shards": len(shards), "shard_keys": sorted(shards),
        "shard_scheme": "sha256(lowercase host)[:2] -> lookup/<xx>.json",
        "recent_scans": [{"started_at": r["started_at"], "finished_at": r["finished_at"],
                          "inputs": [Path(p).name for p in r["inputs"]],
                          "stats": {k: r["stats"].get(k) for k in ("html_pages", "pages_scanned", "bytes_payload",
                                                                   "errors", "findings", "pages_flagged")}}
                         for r in runs],
    }
    _write(out / "meta.json", json.dumps(meta, indent=2, ensure_ascii=False))
    for name in SITE_ASSETS:
        _write(out / name, resources.files("injectionwatch").joinpath(f"site/{name}").read_text("utf-8"))
    _write(out / "LICENSE-DATA.txt",
           "InjectionWatch feed data (feed.json, feed.csv, stix.json, lookup/, meta.json) is licensed under the\n"
           "Creative Commons Attribution 4.0 International License (CC BY 4.0):\n"
           "https://creativecommons.org/licenses/by/4.0/\n\nAttribution: \"InjectionWatch feed\" + link to the "
           f"project ({PROJECT_URL}).\n\n{export.WARNING}\n")
    _write(out / "robots.txt", "User-agent: *\nAllow: /\n")
    _write(out / ".nojekyll", "")
    return {"out": str(out), "entries": len(entries), "shards": len(shards), "files": sum(1 for _ in out.rglob("*"))}
