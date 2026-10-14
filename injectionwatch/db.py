"""SQLite storage.

entries       one row per (normalized URL, normalized payload hash) - the dedupe key
observations  every time an entry was (re)seen, with evidence hash of the fetched body
crawl_log     every fetch attempt / WARC capture (for stats + "observed clean" verdicts)
submissions   unverified reports from the browser extension (NOT in the public feed
              until the crawler independently re-observes them)
warc_files    per-WARC-file resume checkpoints (byte offset of the first unhandled record)
scan_runs     one row per bulk scan invocation, with its statistics
status        active | removed (not seen on last re-crawl) | disputed | suppressed (appeal upheld)

v0.3 adds to ``entries``: ``severity`` (detector: ai_optout | defensive | promotional | manipulative | malicious |
benign) and human review fields ``review`` (NULL | true_positive | false_positive), ``review_severity`` (the
reviewer's severity, which overrides the detector's) and ``review_note``.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
  id INTEGER PRIMARY KEY,
  url TEXT NOT NULL,
  url_norm TEXT NOT NULL,
  host TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  payload_excerpt TEXT NOT NULL,
  category TEXT, intent TEXT, location TEXT, techniques TEXT, target TEXT,
  confidence REAL, heuristic_score REAL, reasons TEXT, classifier TEXT, path TEXT,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  evidence_hash TEXT, seen_count INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'active', status_note TEXT,
  severity TEXT, review TEXT, review_severity TEXT, review_note TEXT,
  UNIQUE(url_norm, payload_hash)
);
CREATE INDEX IF NOT EXISTS idx_entries_host ON entries(host);
CREATE INDEX IF NOT EXISTS idx_entries_last_seen ON entries(last_seen);
CREATE TABLE IF NOT EXISTS observations (
  id INTEGER PRIMARY KEY,
  entry_id INTEGER NOT NULL REFERENCES entries(id),
  observed_at TEXT NOT NULL, evidence_hash TEXT, source TEXT
);
CREATE INDEX IF NOT EXISTS idx_obs_entry ON observations(entry_id, evidence_hash, source);
CREATE TABLE IF NOT EXISTS crawl_log (
  id INTEGER PRIMARY KEY, url TEXT, url_norm TEXT, host TEXT, status INTEGER, error TEXT, fetched_at TEXT,
  source TEXT DEFAULT 'crawler'
);
CREATE INDEX IF NOT EXISTS idx_crawl_norm ON crawl_log(url_norm);
CREATE TABLE IF NOT EXISTS submissions (
  id INTEGER PRIMARY KEY, url_norm TEXT, host TEXT, payload_hash TEXT, category TEXT, technique TEXT,
  client TEXT, received_at TEXT, verified INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS warc_files (
  file_key TEXT PRIMARY KEY, path TEXT, offset INTEGER NOT NULL DEFAULT 0, completed INTEGER NOT NULL DEFAULT 0,
  stats TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS scan_runs (
  id INTEGER PRIMARY KEY, started_at TEXT, finished_at TEXT, inputs TEXT, stats TEXT
);
"""

TRACKING_PARAMS = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "gclid", "fbclid"}
STATUSES = ("active", "removed", "disputed", "suppressed")
REVIEWS = ("true_positive", "false_positive")
_V03_COLUMNS = ("severity", "review", "review_severity", "review_note")


def _sev(category: str | None, intent: str | None) -> str:
    from .classify import severity_of

    return severity_of(category, intent)


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def normalize_url(url: str, keep_query: bool = True) -> str:
    p = urlsplit(url.strip())
    scheme = (p.scheme or "https").lower()
    host = (p.hostname or "").lower().rstrip(".")
    if host and not host.isascii():
        try:  # match the browser's URL() so client-side lookups agree (IDN -> punycode)
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            pass
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    try:
        port = p.port
    except ValueError:
        port = None
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    path = p.path or "/"
    q = ""
    if keep_query and p.query:
        q = urlencode(sorted((k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
                             if k.lower() not in TRACKING_PARAMS))
    return urlunsplit((scheme, host, path, q, ""))


def host_of(url: str) -> str:
    return urlsplit(normalize_url(url)).netloc


class DB:
    def __init__(self, path: str = "injectionwatch.db", readonly: bool = False):
        self.path = path
        self._lock = threading.RLock()
        if readonly:
            self.conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False)
        else:
            self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        if not readonly:
            if path != ":memory:":
                self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.executescript(SCHEMA)
            self._migrate()
            self.conn.commit()

    def _migrate(self) -> None:
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(crawl_log)")}
        if "source" not in cols:  # v0.1 databases
            self.conn.execute("ALTER TABLE crawl_log ADD COLUMN source TEXT DEFAULT 'crawler'")
        ecols = {r[1] for r in self.conn.execute("PRAGMA table_info(entries)")}
        missing = [c for c in _V03_COLUMNS if c not in ecols]
        for c in missing:  # v0.1 / v0.2 databases
            self.conn.execute(f"ALTER TABLE entries ADD COLUMN {c} TEXT")
        if "severity" in missing:
            from .classify import severity_of

            rows = self.conn.execute("SELECT id, category, intent FROM entries").fetchall()
            self.conn.executemany("UPDATE entries SET severity=? WHERE id=?",
                                  [(severity_of(r[1], r[2]), r[0]) for r in rows])

    def close(self) -> None:
        self.conn.close()

    def commit(self) -> None:
        with self._lock:
            self.conn.commit()

    # ------------------------------------------------------------ writes
    def record_crawl(self, url: str, status: int | None, error: str | None, fetched_at: str | None = None,
                     source: str = "crawler", commit: bool = True) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO crawl_log(url,url_norm,host,status,error,fetched_at,source) VALUES (?,?,?,?,?,?,?)",
                (url, normalize_url(url), host_of(url), status, error, fetched_at or now_iso(), source))
            if commit:
                self.conn.commit()

    def record_crawl_many(self, rows: Iterable[tuple[str, int | None, str | None, str]], source: str) -> None:
        data = [(u, normalize_url(u), host_of(u), s, e, t, source) for u, s, e, t in rows]
        with self._lock:
            self.conn.executemany(
                "INSERT INTO crawl_log(url,url_norm,host,status,error,fetched_at,source) VALUES (?,?,?,?,?,?,?)", data)

    def store_scan(self, url: str, result: Any, evidence_hash: str, observed_at: str | None = None,
                   source: str = "crawler", mark_missing_removed: bool = True, commit: bool = True) -> list[int]:
        """Upsert findings from a ScanResult.

        * Re-observations bump ``seen_count``/``last_seen`` - but an identical observation
          (same entry, evidence hash and source, e.g. a WARC record re-processed after a resume)
          is ignored, so bulk scans are idempotent.
        * Active entries for this URL that were NOT re-observed become ``removed`` if this
          observation is at least as new as their ``last_seen``.
        """
        observed_at = observed_at or now_iso()
        un = normalize_url(url)
        ids = []
        with self._lock:
            cur = self.conn.cursor()
            for f in result.findings:
                row = cur.execute("SELECT id, status, last_seen FROM entries WHERE url_norm=? AND payload_hash=?",
                                  (un, f.payload_hash)).fetchone()
                if row:
                    eid = row["id"]
                    dup = cur.execute("SELECT 1 FROM observations WHERE entry_id=? AND evidence_hash=? AND source=?",
                                      (eid, evidence_hash, source)).fetchone()
                    if dup:
                        ids.append(eid)
                        continue
                    new_status = row["status"] if row["status"] in ("disputed", "suppressed") else "active"
                    newer = observed_at >= row["last_seen"]
                    cur.execute("UPDATE entries SET last_seen=MAX(last_seen, ?), first_seen=MIN(first_seen, ?), "
                                "seen_count=seen_count+1, evidence_hash=CASE WHEN ? THEN ? ELSE evidence_hash END, "
                                "status=?, confidence=MAX(confidence, ?) WHERE id=?",
                                (observed_at, observed_at, newer, evidence_hash, new_status, f.confidence, eid))
                else:
                    cur.execute(
                        "INSERT INTO entries(url,url_norm,host,payload_hash,payload_excerpt,category,intent,location,"
                        "techniques,target,confidence,heuristic_score,reasons,classifier,path,first_seen,last_seen,"
                        "evidence_hash,severity) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (url, un, host_of(url), f.payload_hash, f.payload_excerpt, f.category, f.intent, f.location,
                         json.dumps(f.techniques), f.target, f.confidence, f.heuristic_score,
                         json.dumps(f.reasons), f.classifier, f.path, observed_at, observed_at, evidence_hash,
                         f.severity))
                    eid = cur.lastrowid
                cur.execute("INSERT INTO observations(entry_id,observed_at,evidence_hash,source) VALUES (?,?,?,?)",
                            (eid, observed_at, evidence_hash, source))
                ids.append(eid)
            if mark_missing_removed:
                hashes = [f.payload_hash for f in result.findings]
                q = "UPDATE entries SET status='removed' WHERE url_norm=? AND status='active' AND last_seen <= ?"
                args: list[Any] = [un, observed_at]
                if hashes:
                    q += " AND payload_hash NOT IN (%s)" % ",".join("?" * len(hashes))
                    args += hashes
                cur.execute(q, args)
            if commit:
                self.conn.commit()
        return ids

    def mark_removed_if_clean(self, captures: list[tuple[str, str]]) -> int:
        """captures: (url, observed_at) of pages scanned clean. Active entries for those URLs that
        are not newer than the clean capture become 'removed'."""
        n = 0
        with self._lock:
            for i in range(0, len(captures), 500):
                chunk = captures[i:i + 500]
                norms = {normalize_url(u): t for u, t in chunk}
                rows = self.conn.execute(
                    "SELECT DISTINCT url_norm FROM entries WHERE status='active' AND url_norm IN (%s)"
                    % ",".join("?" * len(norms)), list(norms)).fetchall()
                for r in rows:
                    cur = self.conn.execute(
                        "UPDATE entries SET status='removed' WHERE url_norm=? AND status='active' AND last_seen <= ?",
                        (r[0], norms[r[0]]))
                    n += cur.rowcount
        return n

    def set_status(self, entry_id: int, status: str, note: str = "") -> bool:
        if status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        with self._lock:
            cur = self.conn.execute("UPDATE entries SET status=?, status_note=? WHERE id=?", (status, note, entry_id))
            self.conn.commit()
            return cur.rowcount > 0

    def add_submission(self, url: str, payload_hash: str, category: str, technique: str, client: str) -> int:
        un = normalize_url(url, keep_query=False)
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO submissions(url_norm,host,payload_hash,category,technique,client,received_at) "
                "VALUES (?,?,?,?,?,?,?)", (un, host_of(un), payload_hash, category, technique, client, now_iso()))
            self.conn.commit()
            return int(cur.lastrowid or 0)

    def import_entries(self, entries: list[dict[str, Any]]) -> int:
        """Merge entries from a previously published feed.json (keeps first_seen / seen_count /
        status history). Used by the scheduled publish workflow to carry the feed forward."""
        n = 0
        with self._lock:
            for e in entries:
                un = normalize_url(e["url"])
                row = self.conn.execute("SELECT id, first_seen, last_seen, seen_count FROM entries "
                                        "WHERE url_norm=? AND payload_hash=?", (un, e["payload_hash"])).fetchone()
                if row:
                    self.conn.execute(
                        "UPDATE entries SET first_seen=MIN(first_seen, ?), last_seen=MAX(last_seen, ?), "
                        "seen_count=MAX(seen_count, ?) WHERE id=?",
                        (e["first_seen"], e["last_seen"], int(e.get("seen_count") or 1), row["id"]))
                else:
                    self.conn.execute(
                        "INSERT INTO entries(url,url_norm,host,payload_hash,payload_excerpt,category,intent,location,"
                        "techniques,target,confidence,heuristic_score,reasons,classifier,path,first_seen,last_seen,"
                        "evidence_hash,seen_count,status,severity,review,review_severity) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (e["url"], un, host_of(e["url"]), e["payload_hash"], e.get("payload_excerpt", ""),
                         e.get("category"), e.get("intent"), e.get("location"), json.dumps(e.get("techniques") or []),
                         e.get("target"), e.get("confidence"), e.get("heuristic_score"),
                         json.dumps(e.get("reasons") or []), e.get("classifier", "imported"), e.get("path", ""),
                         e["first_seen"], e["last_seen"], e.get("evidence_hash"), int(e.get("seen_count") or 1),
                         e.get("status") if e.get("status") in STATUSES else "active",
                         e.get("detector_severity") or e.get("severity") or _sev(e.get("category"), e.get("intent")),
                         e.get("review") if e.get("review") in REVIEWS else None,
                         e.get("severity") if e.get("review") in REVIEWS else None))
                n += 1
            self.conn.commit()
        return n

    def apply_review(self, url: str, payload_hash: str, review: str, review_severity: str | None = None,
                     note: str = "") -> int:
        """Record a human label for an entry (matched by normalised URL + payload hash). Returns rows changed."""
        if review not in REVIEWS:
            raise ValueError(f"review must be one of {REVIEWS}")
        with self._lock:
            cur = self.conn.execute(
                "UPDATE entries SET review=?, review_severity=?, review_note=? WHERE url_norm=? AND payload_hash=?",
                (review, review_severity, note, normalize_url(url), payload_hash))
            self.conn.commit()
            return int(cur.rowcount)

    # ------------------------------------------------------------ WARC progress / runs
    def warc_progress(self, file_key: str) -> dict[str, Any] | None:
        with self._lock:
            r = self.conn.execute("SELECT * FROM warc_files WHERE file_key=?", (file_key,)).fetchone()
        return dict(r) if r else None

    def save_warc_progress(self, file_key: str, path: str, offset: int, completed: bool,
                           stats: dict[str, Any]) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO warc_files(file_key,path,offset,completed,stats,updated_at) VALUES (?,?,?,?,?,?) "
                "ON CONFLICT(file_key) DO UPDATE SET path=excluded.path, offset=excluded.offset, "
                "completed=excluded.completed, stats=excluded.stats, updated_at=excluded.updated_at",
                (file_key, path, int(offset), int(completed), json.dumps(stats), now_iso()))
            self.conn.commit()

    def start_scan_run(self, inputs: list[str]) -> int:
        with self._lock:
            cur = self.conn.execute("INSERT INTO scan_runs(started_at, inputs) VALUES (?,?)",
                                    (now_iso(), json.dumps(inputs)))
            self.conn.commit()
            return int(cur.lastrowid or 0)

    def finish_scan_run(self, run_id: int, stats: dict[str, Any]) -> None:
        with self._lock:
            self.conn.execute("UPDATE scan_runs SET finished_at=?, stats=? WHERE id=?",
                              (now_iso(), json.dumps(stats), run_id))
            self.conn.commit()

    def scan_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM scan_runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["inputs"] = json.loads(d["inputs"] or "[]")
            d["stats"] = json.loads(d["stats"] or "{}")
            out.append(d)
        return out

    # ------------------------------------------------------------ reads
    @staticmethod
    def _row(r: sqlite3.Row, include_payload: bool = True) -> dict[str, Any]:
        d = dict(r)
        d["techniques"] = json.loads(d.get("techniques") or "[]")
        d["reasons"] = json.loads(d.get("reasons") or "[]")
        if not include_payload:
            d.pop("payload_excerpt", None)
        return d

    def entries_for_url(self, url: str, include_payload: bool = False,
                        statuses: tuple[str, ...] = ("active",)) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM entries WHERE url_norm=? AND status IN (%s) ORDER BY confidence DESC"
                % ",".join("?" * len(statuses)), (normalize_url(url), *statuses)).fetchall()
        return [self._row(r, include_payload) for r in rows]

    def get_entry(self, entry_id: int) -> dict[str, Any] | None:
        with self._lock:
            r = self.conn.execute("SELECT * FROM entries WHERE id=? AND status != 'suppressed'",
                                  (entry_id,)).fetchone()
        return self._row(r) if r else None

    def host_entry_count(self, url: str) -> int:
        with self._lock:
            return int(self.conn.execute("SELECT COUNT(*) FROM entries WHERE host=? AND status='active'",
                                         (host_of(url),)).fetchone()[0])

    def last_crawl(self, url: str) -> dict[str, Any] | None:
        with self._lock:
            r = self.conn.execute("SELECT * FROM crawl_log WHERE url_norm=? ORDER BY id DESC LIMIT 1",
                                  (normalize_url(url),)).fetchone()
        return dict(r) if r else None

    def feed(self, since: str | None = None, include_inactive: bool = False, limit: int = 10000,
             min_confidence: float = 0.0, severities: Iterable[str] | None = None,
             reviewed_only: bool = False) -> list[dict[str, Any]]:
        """``severities`` filters on the effective severity (reviewer's, else detector's);
        ``reviewed_only`` keeps only entries a human labelled true_positive."""
        q = "SELECT * FROM entries WHERE confidence >= ?"
        args: list[Any] = [min_confidence]
        if reviewed_only:
            q += " AND review='true_positive'"
        if severities is not None:
            sev = list(severities)
            q += " AND COALESCE(review_severity, severity) IN (%s)" % ",".join("?" * len(sev))
            args += sev
        if not include_inactive:
            q += " AND status='active'"
        else:
            q += " AND status != 'suppressed'"
        if since:
            q += " AND last_seen >= ?"
            args.append(since)
        q += " ORDER BY last_seen DESC, id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            return [self._row(r) for r in self.conn.execute(q, args).fetchall()]

    def entries_page(self, cursor: int | None = None, limit: int = 100, since: str | None = None,
                     host: str | None = None, category: str | None = None, intent: str | None = None,
                     include_inactive: bool = False) -> tuple[list[dict[str, Any]], int | None]:
        """Keyset pagination by descending id. Returns (rows, next_cursor)."""
        q = "SELECT * FROM entries WHERE 1=1"
        args: list[Any] = []
        q += " AND status != 'suppressed'" if include_inactive else " AND status='active'"
        if cursor is not None:
            q += " AND id < ?"
            args.append(cursor)
        for col, val in (("host", host), ("category", category), ("intent", intent)):
            if val:
                q += f" AND {col} = ?"
                args.append(val.lower() if col == "host" else val)
        if since:
            q += " AND last_seen >= ?"
            args.append(since)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(limit + 1)
        with self._lock:
            rows = [self._row(r) for r in self.conn.execute(q, args).fetchall()]
        nxt = rows[limit - 1]["id"] if len(rows) > limit else None
        return rows[:limit], nxt

    def data_version(self) -> str:
        """Cheap fingerprint of everything the public API serves (used for ETags)."""
        with self._lock:
            r = self.conn.execute(
                "SELECT COUNT(*), COALESCE(MAX(id),0), COALESCE(MAX(last_seen),''), COALESCE(SUM(seen_count),0), "
                "COALESCE(SUM(CASE status WHEN 'active' THEN 1 WHEN 'removed' THEN 2 WHEN 'disputed' THEN 3 "
                "ELSE 5 END * id), 0) FROM entries").fetchone()
            c = self.conn.execute("SELECT COUNT(*), COALESCE(MAX(id),0) FROM crawl_log").fetchone()
            s = self.conn.execute("SELECT COUNT(*) FROM submissions").fetchone()
        return hashlib.sha256(json.dumps([list(r), list(c), list(s)]).encode()).hexdigest()[:20]

    def last_modified(self) -> str | None:
        with self._lock:
            r = self.conn.execute("SELECT MAX(last_seen) FROM entries").fetchone()
        return r[0] if r else None

    def ping(self) -> bool:
        with self._lock:
            return self.conn.execute("SELECT 1").fetchone()[0] == 1

    def stats(self) -> dict[str, Any]:
        def one(sql: str) -> int:
            return int(self.conn.execute(sql).fetchone()[0])

        def grp(col: str) -> dict[str, int]:
            return {str(r[0]): r[1] for r in self.conn.execute(
                f"SELECT {col}, COUNT(*) FROM entries WHERE status='active' GROUP BY {col} ORDER BY 2 DESC")}

        with self._lock:
            return {
                "entries_active": one("SELECT COUNT(*) FROM entries WHERE status='active'"),
                "entries_total": one("SELECT COUNT(*) FROM entries"),
                "hosts_with_entries": one("SELECT COUNT(DISTINCT host) FROM entries WHERE status='active'"),
                "urls_crawled": one("SELECT COUNT(DISTINCT url_norm) FROM crawl_log"),
                "fetch_attempts": one("SELECT COUNT(*) FROM crawl_log"),
                "fetch_ok": one("SELECT COUNT(*) FROM crawl_log WHERE status=200"),
                "robots_disallowed": one("SELECT COUNT(*) FROM crawl_log WHERE error='robots_disallowed'"),
                "fetch_errors": one("SELECT COUNT(*) FROM crawl_log WHERE error IS NOT NULL "
                                    "AND error!='robots_disallowed'"),
                "submissions_unverified": one("SELECT COUNT(*) FROM submissions WHERE verified=0"),
                "by_category": grp("category"), "by_intent": grp("intent"), "by_location": grp("location"),
                "by_target": grp("target"), "by_severity": grp("COALESCE(review_severity, severity)"),
                "signals": {
                    "ai_optout_entries": one("SELECT COUNT(*) FROM entries WHERE status='active' "
                                             "AND COALESCE(review_severity, severity)='ai_optout'"),
                    "ai_optout_hosts": one("SELECT COUNT(DISTINCT host) FROM entries WHERE status='active' "
                                           "AND COALESCE(review_severity, severity)='ai_optout'"),
                },
                "reviewed": {r[0] or "unreviewed": r[1] for r in self.conn.execute(
                    "SELECT review, COUNT(*) FROM entries WHERE status='active' GROUP BY review ORDER BY 2 DESC")},
            }
