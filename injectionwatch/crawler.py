"""Polite crawler: robots.txt, per-host rate limit, identifying UA, no evasion.

Rules this crawler follows (see README "Ethics"):
  * identifies itself (config.CRAWLER_UA) and honors robots.txt for that token;
  * at most one request per host every `min_delay` seconds (default 5s);
  * homepage only by default; no cookies, no logins, no form submission;
  * on 401/403/429/503 or a challenge page it records the result and moves on - no
    retries with other UAs/IPs, no headless-browser workarounds;
  * circuit breaker: if many consecutive hosts fail at the network/proxy layer the run
    stops (it's our egress that's blocked, not the sites).
"""
from __future__ import annotations

import csv
import threading
import time
import urllib.robotparser
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit

import requests

from .config import BOT_TOKEN, CRAWLER_UA

HTML_TYPES = ("text/html", "application/xhtml+xml")


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int | None
    headers: dict[str, str]
    text: str
    error: str | None = None
    fetched_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds"))

    @property
    def ok_html(self) -> bool:
        ct = self.headers.get("content-type", "").lower()
        return self.status == 200 and (not ct or any(t in ct for t in HTML_TYPES))


class RobotsDisallowed(Exception):
    pass


class PoliteFetcher:
    def __init__(self, user_agent: str = CRAWLER_UA, robots_token: str = BOT_TOKEN, min_delay: float = 5.0,
                 timeout: float = 15.0, max_bytes: int = 2_000_000, respect_robots: bool = True,
                 session: requests.Session | None = None):
        self.user_agent = user_agent
        self.robots_token = robots_token
        self.min_delay = min_delay
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.respect_robots = respect_robots
        self.session = session or requests.Session()
        self.session.headers.update({"Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
                                     "Accept-Language": "en"})
        self._robots: dict[str, urllib.robotparser.RobotFileParser | None] = {}
        self._last: dict[str, float] = {}
        self._host_locks: dict[str, threading.Lock] = {}
        self._lock = threading.Lock()

    # -- rate limiting
    def _host_lock(self, host: str) -> threading.Lock:
        with self._lock:
            return self._host_locks.setdefault(host, threading.Lock())

    def _wait_turn(self, host: str):
        last = self._last.get(host)
        if last is not None:
            delay = self.min_delay - (time.monotonic() - last)
            if delay > 0:
                time.sleep(delay)
        self._last[host] = time.monotonic()

    # -- robots
    def _robots_for(self, scheme: str, host: str):
        key = f"{scheme}://{host}"
        if key in self._robots:
            return self._robots[key]
        rp: urllib.robotparser.RobotFileParser | None = urllib.robotparser.RobotFileParser()
        assert rp is not None
        self._wait_turn(host)
        try:
            r = self.session.get(f"{key}/robots.txt", headers={"User-Agent": self.user_agent},
                                 timeout=self.timeout, allow_redirects=True)
            if r.status_code in (401, 403):
                rp.disallow_all = True  # type: ignore[attr-defined]  # stdlib semantics: auth-protected robots => disallow
            elif 400 <= r.status_code < 500:
                rp.allow_all = True  # type: ignore[attr-defined]  # no robots.txt => allowed
            elif r.status_code >= 500:
                rp.disallow_all = True  # type: ignore[attr-defined]  # server error => be conservative
            else:
                rp.parse(r.text.splitlines())
        except requests.RequestException:
            rp = None  # network failure: caller treats as unfetchable
        self._robots[key] = rp
        return rp

    def allowed(self, url: str, token: str | None = None) -> bool | None:
        if not self.respect_robots:
            return True
        p = urlsplit(url)
        rp = self._robots_for(p.scheme, p.netloc)
        if rp is None:
            return None
        return rp.can_fetch(token or self.robots_token, url)

    # -- fetching
    def fetch(self, url: str, user_agent: str | None = None, robots_token: str | None = None,
              check_robots: bool = True) -> FetchResult:
        host = urlsplit(url).netloc
        with self._host_lock(host):
            if check_robots:
                ok = self.allowed(url, robots_token)
                if ok is None:
                    return FetchResult(url, url, None, {}, "", "robots_unreachable")
                if not ok:
                    return FetchResult(url, url, None, {}, "", "robots_disallowed")
            self._wait_turn(host)
            try:
                r = self.session.get(url, headers={"User-Agent": user_agent or self.user_agent},
                                     timeout=self.timeout, allow_redirects=True, stream=True)
                chunks, size = [], 0
                for chunk in r.iter_content(65536):
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= self.max_bytes:
                        break
                r.close()
                body = b"".join(chunks)[: self.max_bytes]
                enc = r.encoding or "utf-8"
                text = body.decode(enc, errors="replace")
                headers = {k.lower(): v for k, v in r.headers.items()}
                err = None
                if r.status_code in (401, 403, 429, 503):
                    err = f"blocked_or_limited_{r.status_code}"
                return FetchResult(url, r.url, r.status_code, headers, text, err)
            except requests.RequestException as e:
                return FetchResult(url, url, None, {}, "", f"network:{type(e).__name__}")


def read_domain_list(path: str, limit: int | None = None) -> list[str]:
    """Tranco-style CSV (rank,domain) or one domain/URL per line. Returns URLs."""
    urls = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#"):
                continue
            item = row[-1].strip()
            if not item or item.lower() == "domain":
                continue
            urls.append(item if "://" in item else f"https://{item}/")
            if limit and len(urls) >= limit:
                break
    return urls


@dataclass
class CrawlSummary:
    attempted: int = 0
    fetched_html: int = 0
    robots_disallowed: int = 0
    blocked: int = 0
    errors: int = 0
    pages_flagged: int = 0
    findings: int = 0
    aborted: str | None = None


def crawl(urls: list[str], db, fetcher: PoliteFetcher | None = None, classifier=None, workers: int = 4,
          rendered: bool = False, breaker_threshold: int = 8, log=print) -> CrawlSummary:
    """Fetch each URL politely, scan, and store. Hosts are crawled in parallel, each host serially."""
    from .detector import scan_html
    from .textutil import sha256_bytes

    fetcher = fetcher or PoliteFetcher()
    summary = CrawlSummary()
    consecutive_net_fail = 0
    renderer = None
    if rendered:
        from .render import Renderer

        renderer = Renderer()

    def work(u: str) -> FetchResult:
        return fetcher.fetch(u)

    try:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            batch = list(urls)
            for i in range(0, len(batch), workers):
                results = list(ex.map(work, batch[i:i + workers]))
                for fr in results:
                    summary.attempted += 1
                    if fr.error == "robots_disallowed":
                        summary.robots_disallowed += 1
                    elif fr.error and (fr.error.startswith("network") or fr.error == "robots_unreachable"):
                        summary.errors += 1
                        consecutive_net_fail += 1
                    elif fr.error and fr.error.startswith("blocked"):
                        summary.blocked += 1
                        consecutive_net_fail = 0
                    else:
                        consecutive_net_fail = 0
                    db.record_crawl(fr.url, fr.status, fr.error, fr.fetched_at)
                    if fr.ok_html:
                        summary.fetched_html += 1
                        rc = None
                        if renderer:
                            try:
                                rc, _ = renderer.candidates_from_url(fr.final_url)
                            except Exception as e:  # rendering is best effort
                                log(f"  render failed {fr.url}: {type(e).__name__}")
                        res = scan_html(fr.text, fr.final_url, fr.headers, classifier, rc)
                        ev = sha256_bytes(fr.text)
                        db.store_scan(fr.final_url, res, ev, fr.fetched_at, source="crawler")
                        if res.verdict == "flagged":
                            summary.pages_flagged += 1
                        summary.findings += len(res.findings)
                    log(f"  {fr.url} status={fr.status} err={fr.error}")
                if consecutive_net_fail >= breaker_threshold:
                    summary.aborted = (f"circuit breaker: {consecutive_net_fail} consecutive network-level "
                                       "failures (egress likely blocked); stopping without retries")
                    log(summary.aborted)
                    break
    finally:
        if renderer:
            renderer.close()
    return summary


def verify_submissions(db, fetcher: PoliteFetcher | None = None, classifier=None, limit: int = 50) -> dict:
    """Re-crawl URLs reported by the extension (logged out, robots-respecting). A submission is
    marked verified only if the crawler independently finds a payload with the same hash."""
    from .detector import scan_html
    from .textutil import sha256_bytes

    fetcher = fetcher or PoliteFetcher()
    rows = db.conn.execute("SELECT id, url_norm, payload_hash FROM submissions WHERE verified=0 LIMIT ?",
                           (limit,)).fetchall()
    out = {"checked": 0, "verified": 0, "not_reproduced": 0}
    for r in rows:
        fr = fetcher.fetch(r["url_norm"])
        db.record_crawl(fr.url, fr.status, fr.error, fr.fetched_at)
        out["checked"] += 1
        state = -1
        if fr.ok_html:
            res = scan_html(fr.text, fr.final_url, fr.headers, classifier)
            db.store_scan(fr.final_url, res, sha256_bytes(fr.text), fr.fetched_at, source="crawler")
            if any(f.payload_hash == r["payload_hash"] for f in res.findings):
                state = 1
        with db._lock:
            db.conn.execute("UPDATE submissions SET verified=? WHERE id=?", (state, r["id"]))
            db.conn.commit()
        out["verified" if state == 1 else "not_reproduced"] += 1
    return out
