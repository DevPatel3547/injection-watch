"""Bulk scanning of Common Crawl (or any) WARC files.

Design goals: streaming, multiprocess, resumable, memory-bounded.

* **Streaming**: records are read one at a time with ``warcio.ArchiveIterator``; only
  ``response`` records with an HTML payload are scanned; each payload is read up to
  ``max_bytes`` (default 2 MB, the same cap as the live crawler).
* **Multiprocess**: the parent process decompresses and parses WARC framing (cheap); HTML parsing
  and detection (expensive) run in a ``ProcessPoolExecutor``. At most ``workers * 4`` pages are
  in flight, so memory stays at roughly ``inflight x max_bytes`` regardless of file size.
* **Fast**: every rule carries an exact necessary-literal gate (``scorer.required_literals``), so most
  regexes are skipped on most text; measured ~33 pages/s/core on 19 KB synthetic pages (see README).
* **Resumable**: progress is checkpointed in the DB (``warc_files``) as the byte offset of the
  first record not yet fully handled. Results are handled strictly in file order, so every record
  before the checkpoint has been written. Re-running the same command continues where it stopped;
  completed files are skipped. Observations are idempotent per (entry, evidence hash, source),
  so records re-processed after a crash do not inflate ``seen_count``.
* **Output**: findings go to the SQLite feed DB (``observed_at`` = the WARC capture date, source
  ``warc:<file name>``) and optionally to a JSONL file (one line per finding, with WARC
  provenance). Per-run statistics go to ``scan_runs``.

Common Crawl WARC paths: https://data.commoncrawl.org/crawl-data/<CRAWL-ID>/warc.paths.gz
(see deploy/github-actions/monthly-publish.yml and docs/common-crawl.md).
"""
from __future__ import annotations

import codecs
import json
import os
import re
import time
from collections import deque
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ProcessPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import IO, Any

from .db import DB, normalize_url, now_iso
from .textutil import sha256_bytes

HTML_TYPES = ("text/html", "application/xhtml+xml")
DEFAULT_MAX_BYTES = 2_000_000
_META_CHARSET_RE = re.compile(rb"""<meta[^>]+charset\s*=\s*["']?\s*([a-zA-Z0-9_.:-]+)""", re.I)
_SNIFF_HTML_RE = re.compile(rb"^\s*(?:<!--.*?-->\s*)*<(?:!doctype\s+html|html|head|body)\b", re.I | re.S)


@dataclass
class WarcStats:
    files: int = 0
    files_completed: int = 0
    files_skipped_done: int = 0
    records_seen: int = 0
    responses: int = 0
    html_pages: int = 0
    pages_scanned: int = 0
    skipped_non_html: int = 0
    skipped_status: int = 0
    truncated: int = 0
    bytes_compressed: int = 0
    bytes_payload: int = 0
    errors: int = 0
    pages_flagged: int = 0
    findings: int = 0
    # v0.3 severity taxonomy: findings and pages per severity (ai_optout = opt-out signal, not an injection)
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    pages_by_severity: dict[str, int] = field(default_factory=dict)
    elapsed_s: float = 0.0
    error_samples: list[str] = field(default_factory=list)

    @property
    def pages_per_s(self) -> float:
        return round(self.html_pages / self.elapsed_s, 1) if self.elapsed_s else 0.0

    def add_error(self, msg: str) -> None:
        self.errors += 1
        if len(self.error_samples) < 20:
            self.error_samples.append(msg[:300])

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["pages_per_s"] = self.pages_per_s
        return d


# --------------------------------------------------------------------------- decoding helpers

def _charset(content_type: str | None, body: bytes) -> str:
    cands = []
    if content_type:
        m = re.search(r"charset\s*=\s*[\"']?([\w.:-]+)", content_type, re.I)
        if m:
            cands.append(m.group(1))
    m2 = _META_CHARSET_RE.search(body[:4096])
    if m2:
        cands.append(m2.group(1).decode("ascii", "ignore"))
    for c in cands:
        try:
            return codecs.lookup(c).name
        except LookupError:
            continue
    return "utf-8"


def decode_html(body: bytes, content_type: str | None) -> str:
    enc = _charset(content_type, body)
    try:
        return body.decode(enc, errors="replace")
    except LookupError:  # pragma: no cover - codecs.lookup already validated
        return body.decode("utf-8", errors="replace")


def is_html(content_type: str | None, identified: str | None, body_head: bytes) -> bool:
    ct = (content_type or "").lower()
    if any(t in ct for t in HTML_TYPES):
        return True
    if identified and any(t in identified.lower() for t in HTML_TYPES):
        return True
    if not ct or "text/plain" in ct or "octet-stream" in ct:
        return bool(_SNIFF_HTML_RE.match(body_head[:2048]))
    return False


# --------------------------------------------------------------------------- worker side

_WORKER_CLASSIFIER: Any = None


def _worker_init(classifier_kind: str) -> None:
    global _WORKER_CLASSIFIER
    from .classify import make_classifier
    from .scorer import load_rules

    load_rules()  # compile once per worker
    _WORKER_CLASSIFIER = make_classifier(classifier_kind)


def scan_page(item: dict[str, Any], classifier: Any = None) -> dict[str, Any]:
    """Scan one decoded page. Runs in a worker process; returns plain picklable data."""
    from .detector import scan_html

    out: dict[str, Any] = {"seq": item["seq"], "error": None, "findings": [], "flagged": False}
    try:
        html = decode_html(item["body"], item.get("content_type"))
        headers = item.get("headers") or {}
        res = scan_html(html, item["url"], headers, classifier or _WORKER_CLASSIFIER)
        out["findings"] = [f.to_dict() for f in res.findings]
        out["flagged"] = res.verdict == "flagged"
    except Exception as e:  # never let one page kill the run
        out["error"] = f"{type(e).__name__}: {e}"
    return out


# --------------------------------------------------------------------------- parent side

def _file_key(path: Path) -> str:
    st = path.stat()
    return f"{path.name}:{st.st_size}"


def _http_headers(record: Any) -> dict[str, str]:
    hh = record.http_headers
    if hh is None:
        return {}
    return {k.lower(): v for k, v in hh.headers}


def iter_pages(fh: IO[bytes], max_bytes: int, stats: WarcStats,
               on_record: Callable[[int], None] | None = None) -> Iterable[tuple[int, dict[str, Any] | None]]:
    """Yield (record_offset, page_item | None) for every WARC record. ``None`` = handled inline (skipped)."""
    from warcio.archiveiterator import ArchiveIterator

    it = ArchiveIterator(fh, no_record_parse=False)
    # NB: warcio's get_record_offset() reads the record to its end, so it must be called only
    # AFTER the payload has been read.
    for record in it:
        stats.records_seen += 1
        if record.rec_type != "response":
            off = it.get_record_offset()
            if on_record:
                on_record(off)
            yield off, None
            continue
        stats.responses += 1
        try:
            status = int(record.http_headers.get_statuscode()) if record.http_headers else None
        except (TypeError, ValueError):
            status = None
        headers = _http_headers(record)
        content_type = headers.get("content-type")
        identified = record.rec_headers.get_header("WARC-Identified-Payload-Type")
        body = b""
        read_error = None
        if status == 200:
            try:
                body = record.content_stream().read(max_bytes + 1)
            except Exception as e:  # corrupt gzip / chunking inside the record
                read_error = f"{type(e).__name__}: {e}"
        off = it.get_record_offset()
        if on_record:
            on_record(off)
        if status != 200:
            stats.skipped_status += 1
            yield off, None
            continue
        if read_error:
            stats.add_error(f"read@{off}: {read_error}")
            yield off, None
            continue
        if len(body) > max_bytes or record.rec_headers.get_header("WARC-Truncated"):
            stats.truncated += 1
            body = body[:max_bytes]
        if not is_html(content_type, identified, body[:2048]):
            stats.skipped_non_html += 1
            yield off, None
            continue
        stats.html_pages += 1
        stats.bytes_payload += len(body)
        yield off, {
            "url": record.rec_headers.get_header("WARC-Target-URI") or "",
            "warc_date": record.rec_headers.get_header("WARC-Date") or now_iso(),
            "record_id": record.rec_headers.get_header("WARC-Record-ID") or "",
            "content_type": content_type,
            "headers": headers,
            "body": body,
            "offset": off,
        }


class _Sink:
    """Writes results to the DB and JSONL in file order."""

    def __init__(self, db: DB | None, jsonl: IO[str] | None, source: str, record_urls: bool, stats: WarcStats):
        self.db, self.jsonl, self.source, self.record_urls, self.stats = db, jsonl, source, record_urls, stats
        self._clean_urls: list[tuple[str, str]] = []

    def handle(self, item: dict[str, Any], result: dict[str, Any]) -> None:
        from .detector import Finding, ScanResult

        st = self.stats
        if result["error"]:
            st.add_error(f"scan {item['url'][:120]}: {result['error']}")
            return
        st.pages_scanned += 1
        observed = _iso(item["warc_date"])
        if result["findings"]:
            st.findings += len(result["findings"])
            st.pages_flagged += int(result["flagged"])
            for f in result["findings"]:
                st.findings_by_severity[f["severity"]] = st.findings_by_severity.get(f["severity"], 0) + 1
            for sev in {f["severity"] for f in result["findings"]}:
                st.pages_by_severity[sev] = st.pages_by_severity.get(sev, 0) + 1
            if self.db is not None:
                fs = [Finding(**{k: v for k, v in f.items() if k not in ("flagged", "severity")})
                      for f in result["findings"]]
                self.db.store_scan(item["url"], ScanResult(item["url"], fs), sha256_bytes(item["body"]), observed,
                                   source=self.source, commit=False)
                if self.record_urls:
                    self.db.record_crawl(item["url"], 200, None, observed, source=self.source, commit=False)
            if self.jsonl is not None:
                for f in result["findings"]:
                    self.jsonl.write(json.dumps({
                        "url": item["url"], "url_norm": normalize_url(item["url"]), "warc_file": self.source[5:],
                        "warc_record_id": item["record_id"], "warc_date": item["warc_date"],
                        "warc_offset": item["offset"], **f}, ensure_ascii=False) + "\n")
        elif self.db is not None:
            self._clean_urls.append((item["url"], observed))

    def flush(self) -> None:
        if self.db is None:
            return
        if self._clean_urls:
            if self.record_urls:
                self.db.record_crawl_many([(u, 200, None, t) for u, t in self._clean_urls], source=self.source)
            # a clean capture newer than an active entry for the same URL means the payload is gone
            self.db.mark_removed_if_clean(self._clean_urls)
            self._clean_urls = []
        self.db.commit()
        if self.jsonl is not None:
            self.jsonl.flush()


def _iso(warc_date: str) -> str:
    return warc_date.replace("Z", "+00:00") if warc_date.endswith("Z") else warc_date


def scan_warcs(paths: list[str | Path], db: DB | None = None, jsonl_path: str | Path | None = None,
               workers: int | None = None, max_bytes: int = DEFAULT_MAX_BYTES,
               checkpoint_every: int = 500, record_urls: bool = True, limit: int | None = None,
               classifier_kind: str = "heuristic", log: Callable[[str], None] | None = None) -> WarcStats:
    """Scan WARC files. ``workers=0`` scans in-process (deterministic, used by tests).

    ``limit`` stops after that many records in this run (the checkpoint makes the next run continue).
    """
    log = log or (lambda m: None)
    workers = (os.cpu_count() or 2) if workers is None else workers
    stats = WarcStats()
    t0 = time.monotonic()
    jsonl = open(jsonl_path, "a", encoding="utf-8") if jsonl_path else None  # noqa: SIM115
    pool: ProcessPoolExecutor | None = None
    inline_classifier = None
    if workers > 0:
        pool = ProcessPoolExecutor(max_workers=workers, initializer=_worker_init, initargs=(classifier_kind,))
    else:
        from .classify import make_classifier

        inline_classifier = make_classifier(classifier_kind)
    max_inflight = max(4, workers * 4)
    run_id = db.start_scan_run([str(p) for p in paths]) if db is not None else None
    budget = limit
    try:
        for p in paths:
            path = Path(p)
            stats.files += 1
            key = _file_key(path)
            prog = db.warc_progress(key) if db is not None else None
            if prog and prog["completed"]:
                stats.files_skipped_done += 1
                log(f"skip (already completed): {path.name}")
                continue
            start = int(prog["offset"]) if prog else 0
            if start:
                log(f"resume {path.name} at byte {start}")
            source = f"warc:{path.name}"
            sink = _Sink(db, jsonl, source, record_urls, stats)
            pending: deque[tuple[dict[str, Any], Future[dict[str, Any]] | dict[str, Any]]] = deque()
            since_ckpt = 0
            last_off = start
            stopped = False

            def drain(block_until: int, _pending: Any = pending, _sink: _Sink = sink) -> None:
                while _pending and (len(_pending) > block_until or _done(_pending[0][1])):
                    item, fut = _pending.popleft()
                    res = fut.result() if isinstance(fut, Future) else fut
                    _sink.handle(item, res)

            with open(path, "rb") as fh:
                fh.seek(start)
                for off, item in iter_pages(fh, max_bytes, stats):
                    last_off = off
                    if item is not None:
                        item["seq"] = off
                        if pool is not None:
                            pending.append((item, pool.submit(scan_page, item)))
                        else:
                            pending.append((item, scan_page(item, inline_classifier)))
                        drain(max_inflight)
                    since_ckpt += 1
                    if since_ckpt >= checkpoint_every:
                        drain(0)
                        sink.flush()
                        if db is not None:
                            db.save_warc_progress(key, str(path), off, False, stats.to_dict())
                        since_ckpt = 0
                    if budget is not None:
                        budget -= 1
                        if budget <= 0:
                            stopped = True
                            break
                drain(0)
                sink.flush()
                stats.bytes_compressed += (fh.tell() if stopped else path.stat().st_size) - start
            if db is not None:
                if stopped:
                    # resume from the record after the last one handled
                    db.save_warc_progress(key, str(path), _next_offset(path, last_off), False, stats.to_dict())
                else:
                    db.save_warc_progress(key, str(path), path.stat().st_size, True, stats.to_dict())
            if stopped:
                log(f"stopped after limit in {path.name}; re-run to resume")
                break
            stats.files_completed += 1
            log(f"done {path.name}: {stats.html_pages} html pages so far, {stats.findings} findings")
    finally:
        if pool is not None:
            pool.shutdown(wait=True, cancel_futures=True)
        if jsonl is not None:
            jsonl.close()
        stats.elapsed_s = round(time.monotonic() - t0, 3)
        if db is not None and run_id is not None:
            db.finish_scan_run(run_id, stats.to_dict())
    return stats


def _done(f: Future[dict[str, Any]] | dict[str, Any]) -> bool:
    return not isinstance(f, Future) or f.done()


def _next_offset(path: Path, off: int) -> int:
    """Offset of the record that follows the record starting at ``off``."""
    from warcio.archiveiterator import ArchiveIterator

    with open(path, "rb") as fh:
        fh.seek(off)
        it = ArchiveIterator(fh)
        first = True
        for _ in it:
            if not first:
                return int(it.get_record_offset())
            first = False
        return path.stat().st_size


# --------------------------------------------------------------------------- synthetic WARCs (tests/demo)

def write_synthetic_warc(path: str | Path, pages: list[dict[str, Any]], gzip: bool = True) -> Path:
    """Write a small WARC: each page dict has url, body (str|bytes), and optional status,
    content_type, headers (extra HTTP headers), warc_date, rec_type ('response' default)."""
    from io import BytesIO

    from warcio.statusandheaders import StatusAndHeaders
    from warcio.warcwriter import WARCWriter

    path = Path(path)
    with open(path, "wb") as fh:
        w = WARCWriter(fh, gzip=gzip)
        w.write_record(w.create_warcinfo_record(path.name, {"software": "injectionwatch-synthetic",
                                                            "description": "synthetic test data"}))
        for p in pages:
            body = p["body"].encode("utf-8") if isinstance(p["body"], str) else p["body"]
            status = p.get("status", 200)
            reason = {200: "OK", 404: "Not Found", 301: "Moved Permanently", 500: "Server Error"}.get(status, "X")
            hdrs = [("Content-Type", p.get("content_type", "text/html; charset=utf-8")),
                    ("Content-Length", str(len(body))), *(p.get("headers") or {}).items()]
            http = StatusAndHeaders(f"{status} {reason}", hdrs, protocol="HTTP/1.1")
            warc_headers = {"WARC-Date": p["warc_date"]} if p.get("warc_date") else None
            rec_type = p.get("rec_type", "response")
            if rec_type == "request":
                req = StatusAndHeaders(f"GET {p['url']} HTTP/1.1", [("Host", "x")], protocol="HTTP/1.1",
                                       is_http_request=True)
                rec = w.create_warc_record(p["url"], "request", http_headers=req)
            else:
                rec = w.create_warc_record(p["url"], "response", payload=BytesIO(body), length=None,
                                           http_headers=http, warc_headers_dict=warc_headers)
            w.write_record(rec)
    return path
