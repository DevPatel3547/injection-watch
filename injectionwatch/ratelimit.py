"""Pluggable rate limiting.

``RateLimitBackend.hit(key, limit, window_s)`` records one request and returns a ``RateLimitResult``.

* ``MemoryBackend``  - sliding-window log in process memory (single process; bounded key count).
* ``SQLiteBackend``  - fixed-window counters in a SQLite file, shared by several worker processes
                       on one host (``uvicorn --workers N``) without extra infrastructure.

For multi-host deployments implement the protocol on Redis/Memcached (e.g. ``INCR`` + ``EXPIRE``)
or enforce limits at the CDN / reverse proxy. Keys are opaque strings; the API passes a salted
hash of the client address, never the raw IP.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    limit: int
    remaining: int
    reset_s: int


class RateLimitBackend(Protocol):
    def hit(self, key: str, limit: int, window_s: float) -> RateLimitResult: ...


class MemoryBackend:
    def __init__(self, max_keys: int = 100_000):
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()
        self.max_keys = max_keys

    def hit(self, key: str, limit: int, window_s: float) -> RateLimitResult:
        now = time.monotonic()
        with self._lock:
            dq = self._hits.get(key)
            if dq is None:
                dq = deque()
                self._hits[key] = dq
                while len(self._hits) > self.max_keys:   # bound memory: evict least recently used
                    self._hits.popitem(last=False)
            else:
                self._hits.move_to_end(key)
            while dq and now - dq[0] >= window_s:
                dq.popleft()
            if len(dq) >= limit:
                return RateLimitResult(False, limit, 0, int(window_s - (now - dq[0])) + 1)
            dq.append(now)
            reset = int(window_s - (now - dq[0])) + 1
            return RateLimitResult(True, limit, limit - len(dq), reset)


class SQLiteBackend:
    def __init__(self, path: str):
        self._conn = sqlite3.connect(path, check_same_thread=False, timeout=5)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("CREATE TABLE IF NOT EXISTS ratelimit (key TEXT, win INTEGER, n INTEGER, "
                           "PRIMARY KEY(key, win))")
        self._conn.commit()
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window_s: float) -> RateLimitResult:
        now = time.time()
        win = int(now // window_s)
        reset = int((win + 1) * window_s - now) + 1
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO ratelimit(key, win, n) VALUES (?,?,1) ON CONFLICT(key, win) DO UPDATE SET n=n+1 "
                "RETURNING n", (key, win))
            n = int(cur.fetchone()[0])
            if win % 16 == 0:
                self._conn.execute("DELETE FROM ratelimit WHERE win < ?", (win - 1,))
            self._conn.commit()
        if n > limit:
            return RateLimitResult(False, limit, 0, reset)
        return RateLimitResult(True, limit, limit - n, reset)


def make_backend(kind: str = "memory", path: str | None = None) -> RateLimitBackend:
    if kind == "sqlite":
        return SQLiteBackend(path or "ratelimit.db")
    if kind == "memory":
        return MemoryBackend()
    raise ValueError(f"unknown rate limit backend: {kind}")
