"""Feed exports: JSON, CSV, STIX 2.1 bundle.

Every export carries a warning: payload excerpts are attacker-controlled text. They are
truncated and URL-defanged, but consumers must never place them in an LLM context
without isolation - otherwise the feed itself becomes an injection vector.
"""
from __future__ import annotations

import csv
import io
import json
import uuid
from typing import Any

from .classify import CATEGORIES, FEED_SEVERITIES, INTENTS, SEVERITIES, TARGETS, severity_of
from .config import FEED_LICENSE, PROJECT_URL, VERSION
from .db import now_iso
from .detector import MIN_FLAG_CONFIDENCE

WARNING = ("payload_excerpt values are UNTRUSTED attacker-controlled text (truncated, URLs defanged). "
           "Do not insert them into an LLM prompt without isolation.")
CSV_FIELDS = ["id", "url", "host", "category", "intent", "severity", "review", "flagged", "location", "techniques",
              "target",
              "confidence", "first_seen", "last_seen", "seen_count", "status", "payload_hash", "evidence_hash",
              "payload_excerpt"]
NS = uuid.UUID("6f1c1d1e-3b0a-4f2e-9a57-1a2b3c4d5e6f")  # namespace for deterministic STIX ids
IDENTITY_ID = f"identity--{uuid.uuid5(NS, 'injectionwatch-identity')}"


FEED_ENTRY_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "InjectionWatch feed entry",
    "description": "One (normalized URL, normalized payload) observation. " + WARNING,
    "type": "object",
    "required": ["id", "url", "host", "category", "intent", "flagged", "location", "techniques", "target",
                 "confidence", "first_seen", "last_seen", "seen_count", "status", "payload_hash"],
    "properties": {
        "id": {"type": "integer"},
        "url": {"type": "string", "description": "URL where the payload was observed"},
        "host": {"type": "string", "description": "lower-cased (punycode) host[:port]"},
        "category": {"type": "string", "enum": CATEGORIES},
        "intent": {"type": "string", "enum": INTENTS},
        "severity": {"type": "string", "enum": [*SEVERITIES, "benign"],
                     "description": "ai_optout < defensive < promotional < manipulative < malicious; a reviewer's "
                                    "label overrides the detector's"},
        "detector_severity": {"type": ["string", "null"], "enum": [*SEVERITIES, "benign", None]},
        "review": {"type": ["string", "null"], "enum": ["true_positive", "false_positive", None],
                   "description": "human review of this entry (null = not reviewed)"},
        "flagged": {"type": "boolean", "description": "severity in {malicious, manipulative} and confidence >= 0.4"},
        "location": {"type": "string", "description": "where on the page the payload hides"},
        "techniques": {"type": "array", "items": {"type": "string"}},
        "target": {"type": "string", "enum": TARGETS},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "first_seen": {"type": "string", "format": "date-time"},
        "last_seen": {"type": "string", "format": "date-time"},
        "seen_count": {"type": "integer", "minimum": 1},
        "status": {"type": "string", "enum": ["active", "removed", "disputed", "suppressed"]},
        "payload_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "evidence_hash": {"type": ["string", "null"]},
        "payload_excerpt": {"type": "string", "maxLength": 200, "description": "UNTRUSTED, truncated, defanged"},
        "reasons": {"type": "array", "items": {"type": "string"}},
    },
}


def public_entry(e: dict[str, Any]) -> dict[str, Any]:
    out = {k: e.get(k) for k in CSV_FIELDS if k != "flagged"}
    detector_sev = e.get("severity") or severity_of(e.get("category"), e.get("intent"))
    out["severity"] = e.get("review_severity") or detector_sev
    out["detector_severity"] = detector_sev
    # flagged follows the effective severity, so a reviewer can down- or up-grade an entry
    out["flagged"] = out["severity"] in FEED_SEVERITIES and (e.get("confidence") or 0) >= MIN_FLAG_CONFIDENCE
    out["reasons"] = e.get("reasons", [])
    return out


_public = public_entry


def to_json(entries: list[dict[str, Any]]) -> str:
    return json.dumps({
        "feed": "InjectionWatch", "version": VERSION, "generated_at": now_iso(), "license": FEED_LICENSE,
        "source": PROJECT_URL, "warning": WARNING, "count": len(entries),
        "entries": [_public(e) for e in entries],
    }, indent=2, ensure_ascii=False)


def to_csv(entries: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, extrasaction="ignore")
    w.writeheader()
    for e in entries:
        row = _public(e)
        row["techniques"] = ";".join(row.get("techniques") or [])
        # neutralize spreadsheet formula injection
        for k, v in row.items():
            if isinstance(v, str) and v[:1] in ("=", "+", "-", "@"):
                row[k] = "'" + v
        w.writerow(row)
    return buf.getvalue()


def _stix_ts(iso: str) -> str:
    # STIX wants RFC3339 with 'Z'
    return iso.replace("+00:00", "Z") if iso.endswith("+00:00") else (iso if iso.endswith("Z") else iso + "Z")


def to_stix(entries: list[dict[str, Any]]) -> str:
    created = _stix_ts(now_iso())
    objects: list[dict[str, Any]] = [{
        "type": "identity", "spec_version": "2.1", "id": IDENTITY_ID, "created": created, "modified": created,
        "name": "InjectionWatch", "identity_class": "system",
        "description": "Open feed of indirect prompt injections observed on the web.",
    }]
    for e in entries:
        pub = _public(e)
        url = (e["url"] or "").replace("\\", "\\\\").replace("'", "\\'")
        ind_id = f"indicator--{uuid.uuid5(NS, e['url_norm'] + '|' + e['payload_hash'])}"
        objects.append({
            "type": "indicator", "spec_version": "2.1", "id": ind_id,
            "created": _stix_ts(e["first_seen"]), "modified": _stix_ts(e["last_seen"]),
            "created_by_ref": IDENTITY_ID,
            "name": f"Indirect prompt injection ({e['category']}) at {e['host']}",
            "description": f"{e['location']} payload targeting {e['target']}. {WARNING}",
            "indicator_types": ["malicious-activity" if pub["flagged"] else "anomalous-activity"],
            "pattern": f"[url:value = '{url}']", "pattern_type": "stix",
            "valid_from": _stix_ts(e["first_seen"]),
            "confidence": round((e.get("confidence") or 0) * 100),
            "labels": [e["category"], e["intent"], pub["severity"], e["location"]],
            "x_injectionwatch_payload_hash": e["payload_hash"],
            "x_injectionwatch_payload_excerpt": e["payload_excerpt"],
            "x_injectionwatch_target": e["target"],
            "x_injectionwatch_techniques": pub["techniques"],
            "x_injectionwatch_last_seen": _stix_ts(e["last_seen"]),
            "x_injectionwatch_evidence_hash": e.get("evidence_hash"),
        })
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    return json.dumps(bundle, indent=2, ensure_ascii=False)
