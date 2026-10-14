"""safe_fetch(url): what an agent should call instead of a raw GET.

1. ask the feed (remote API or local DB) whether the URL is known-bad;
2. fetch the page;
3. run the local detector;
4. return ONLY human-visible text, minus any block the detector flagged. Everything
   non-rendered (comments, hidden elements, meta, attributes, JSON-LD) is dropped.

It reduces exposure; it is not a guarantee. Paraphrased or visible injections can survive.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import requests

from .config import BROWSER_UA
from .db import DB
from .detector import scan_candidates
from .extract import extract_candidates
from .textutil import clean_for_scoring, normalize_payload, payload_hash


@dataclass
class SafeFetchResult:
    url: str
    verdict: str                 # flagged | clean | blocked
    feed_verdict: str            # from /check: flagged | observed_clean | unknown | unavailable
    text: str
    removed: list[dict] = field(default_factory=list)
    status: int | None = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _feed_lookup(url: str, api_base: str | None, db_path: str | None, session) -> str:
    try:
        if db_path:
            db = DB(db_path)
            try:
                from .classify import FLAG_INTENTS

                es = db.entries_for_url(url)
                if any(e["intent"] in FLAG_INTENTS for e in es):
                    return "flagged"
                return "observed_clean" if db.last_crawl(url) else "unknown"
            finally:
                db.close()
        if api_base:
            r = session.get(f"{api_base.rstrip('/')}/v1/check", params={"url": url}, timeout=5)
            return r.json().get("verdict", "unavailable")
    except Exception:
        return "unavailable"
    return "unknown"


def sanitize_html(html: str, headers: dict | None = None, url: str = "", classifier=None):
    cands = extract_candidates(html, headers)
    res = scan_candidates(cands, url, classifier)
    flagged = {f.payload_hash for f in res.findings if f.flagged}
    keep = [c.text for c in cands if c.location == "visible" and payload_hash(c.text) not in flagged]
    # also drop visible blocks that *contain* a flagged payload (e.g. unicode-tag smuggling inside a <p>)
    flagged_norm = [normalize_payload(f.payload_excerpt.rstrip("…")) for f in res.findings if f.flagged]
    keep = [t for t in keep if not any(fn and fn[:60] in normalize_payload(t) for fn in flagged_norm)]
    return "\n".join(clean_for_scoring(t) for t in keep), res


def safe_fetch(url: str, api_base: str | None = None, db_path: str | None = None, fetcher=None,
               block_on_flagged: bool = True, classifier=None, session=None) -> SafeFetchResult:
    session = session or requests.Session()
    feed_verdict = _feed_lookup(url, api_base, db_path, session)
    if feed_verdict == "flagged" and block_on_flagged:
        return SafeFetchResult(url, "blocked", feed_verdict, "", [], None)
    if fetcher is not None:
        fr = fetcher(url)
        html, headers, status = fr["text"], fr.get("headers", {}), fr.get("status")
    else:
        r = session.get(url, headers={"User-Agent": BROWSER_UA}, timeout=15)
        html, headers, status = r.text, dict(r.headers), r.status_code
    text, res = sanitize_html(html, headers, url, classifier)
    removed = [f.to_dict() for f in res.findings if f.flagged]
    verdict = "flagged" if removed or feed_verdict == "flagged" else "clean"
    return SafeFetchResult(url, verdict, feed_verdict, text, removed, status)
