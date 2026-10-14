import json
import logging
import socket

import pytest
from fastapi.testclient import TestClient

from injectionwatch.api import Settings, create_app, validate_http_url
from injectionwatch.db import DB
from injectionwatch.detector import scan_html
from injectionwatch.ratelimit import MemoryBackend, SQLiteBackend, make_backend

from .conftest import load_fixture


def _settings(path, **kw):
    return Settings(db_path=path, salt="test", **kw)


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "api.db")
    db = DB(path)
    db.store_scan("https://bad.example/p", scan_html(load_fixture("01_comment_ignore_previous.html")), "ev",
                  "2026-10-01T00:00:00+00:00")
    for i, name in enumerate(["06_hidden_display_none.html", "27_hiring_bot_injection.html",
                              "12_aria_hidden_injection.html"]):
        db.store_scan(f"https://h{i}.example/x", scan_html(load_fixture(name)), "ev", "2026-10-02T00:00:00+00:00")
    db.record_crawl("https://bad.example/p", 200, None)
    db.record_crawl("https://good.example/", 200, None)
    db.close()
    return path


@pytest.fixture
def client(db_path):
    return TestClient(create_app(settings=_settings(db_path, rate_limit=1000)))


def test_check_verdicts_and_payload_opt_in(client):
    r = client.get("/v1/check", params={"url": "https://bad.example/p"})
    body = r.json()
    assert r.status_code == 200 and body["verdict"] == "flagged" and body["entries"][0]["payload_excerpt"] is None
    assert body["entries"][0]["flagged"] is True and "never fetches" in body["note"]
    r2 = client.get("/v1/check", params={"url": "https://bad.example/p", "include_payload": "true"}).json()
    assert r2["entries"][0]["payload_excerpt"]
    assert client.get("/v1/check", params={"url": "https://good.example/"}).json()["verdict"] == "observed_clean"
    assert client.get("/v1/check", params={"url": "https://never.example/"}).json()["verdict"] == "unknown"


@pytest.mark.parametrize("bad", ["ftp://x.example/", "javascript:alert(1)", "https://user:pw@x.example/",
                                 "https:///nohost", "https://x.example/ space", "http://exa mple.com/",
                                 "https://x.example:99999/", "https://" + "a" * 2050 + ".example/"])
def test_check_rejects_bad_urls(client, bad):
    r = client.get("/v1/check", params={"url": bad})
    assert r.status_code == 422 and r.json()["error"] == "invalid_request"


def test_check_never_opens_a_connection(client, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    for u in ("http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22/", "http://[::1]/",
              "http://localhost/admin"):
        r = client.get("/v1/check", params={"url": u})
        assert r.status_code == 200 and r.json()["verdict"] == "unknown"


def test_validate_http_url():
    assert validate_http_url("https://bücher.example/a?b=1")
    with pytest.raises(ValueError):
        validate_http_url("https://bad_host!.example/")


def test_etag_and_cache_headers(client, db_path):
    r = client.get("/v1/stats")
    etag = r.headers["etag"]
    assert etag.startswith('W/"') and "max-age" in r.headers["cache-control"]
    r304 = client.get("/v1/stats", headers={"If-None-Match": etag})
    assert r304.status_code == 304 and r304.content == b""
    c = client.get("/v1/check", params={"url": "https://bad.example/p"})
    assert client.get("/v1/check", params={"url": "https://bad.example/p"},
                      headers={"If-None-Match": c.headers["etag"]}).status_code == 304
    f = client.get("/v1/feed")
    assert client.get("/v1/feed", headers={"If-None-Match": f.headers["etag"]}).status_code == 304
    # data change -> new ETag
    db = DB(db_path)
    db.record_crawl("https://new.example/", 200, None)
    db.close()
    assert client.get("/v1/stats").headers["etag"] != etag


def test_entries_pagination(client):
    p1 = client.get("/v1/entries", params={"limit": 2})
    b1 = p1.json()
    assert len(b1["items"]) == 2 and b1["next_cursor"] and 'rel="next"' in p1.headers["link"]
    b2 = client.get("/v1/entries", params={"limit": 2, "cursor": b1["next_cursor"]}).json()
    ids = [e["id"] for e in b1["items"] + b2["items"]]
    assert len(ids) == len(set(ids)) == 4 and b2["next_cursor"] is None
    assert ids == sorted(ids, reverse=True)
    assert all(e["host"] == "h1.example" for e in client.get("/v1/entries", params={"host": "h1.example"})
               .json()["items"])
    assert client.get("/v1/entries", params={"category": "nope"}).status_code == 422
    assert client.get("/v1/entries", params={"limit": 501}).status_code == 422
    assert client.get("/v1/entries", params={"since": "'; DROP TABLE"}).status_code == 422
    one = client.get(f"/v1/entries/{ids[0]}").json()
    assert one["id"] == ids[0] and one["payload_excerpt"] is None
    assert client.get("/v1/entries/999999").status_code == 404


def test_feed_formats_stats_and_openapi(client):
    assert json.loads(client.get("/v1/feed").text)["count"] == 4
    csv_r = client.get("/v1/feed", params={"format": "csv"})
    assert csv_r.text.startswith("id,url") and csv_r.headers["content-type"].startswith("text/csv")
    assert client.get("/v1/feed", params={"format": "stix"}).json()["type"] == "bundle"
    assert client.get("/v1/feed", params={"format": "xml"}).status_code == 422
    s = client.get("/v1/stats").json()
    assert s["entries_active"] == 4 and s["urls_crawled"] == 2
    spec = client.get("/v1/openapi.json").json()
    assert {"/v1/check", "/v1/entries", "/v1/feed", "/v1/stats", "/v1/submit"} <= set(spec["paths"])
    assert client.get("/docs").status_code == 200


def test_health_and_security_headers(client):
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json() == {"status": "ready"}
    h = client.get("/v1/health")
    assert h.json()["status"] == "ok" and h.json()["rules_version"] >= "0.2.0"
    assert h.headers["x-content-type-options"] == "nosniff"
    assert h.headers["content-security-policy"].startswith("default-src 'none'")
    assert len(h.headers["x-request-id"]) >= 8
    assert client.get("/v1/health", headers={"X-Request-ID": "abcdef123456"}).headers["x-request-id"] == "abcdef123456"


def test_legacy_routes_redirect(client):
    r = client.get("/check", params={"url": "https://bad.example/p"}, follow_redirects=False)
    assert r.status_code == 308 and r.headers["location"].startswith("/v1/check?url=")
    assert r.headers["deprecation"] == "true"


def test_cors(client):
    r = client.options("/v1/check", headers={"Origin": "https://agent.example", "Access-Control-Request-Method": "GET"})
    assert r.status_code == 200 and r.headers["access-control-allow-origin"] == "*"
    assert "access-control-allow-credentials" not in r.headers
    assert client.get("/v1/stats", headers={"Origin": "https://x.example"}).headers["access-control-allow-origin"] == "*"


def test_cors_restricted(db_path):
    c = TestClient(create_app(settings=_settings(db_path, cors_origins=["https://feed.example"])))
    r = c.get("/v1/stats", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers


def test_submit_strips_query_and_validates(client):
    ok = client.post("/v1/submit", json={"url": "https://site.example/a?session=SECRET#x", "payload_hash": "a" * 64,
                                         "category": "instruction_override", "technique": "display:none<script>"})
    assert ok.status_code == 202 and ok.json()["stored_url"] == "https://site.example/a"
    for bad in ({"url": "https://s.example/", "payload_hash": "nothex", "category": "instruction_override"},
                {"url": "https://s.example/", "payload_hash": "b" * 64, "category": "made_up"},
                {"url": "file:///etc/passwd", "payload_hash": "b" * 64, "category": "other"},
                {"url": "https://s.example/", "payload_hash": "b" * 64, "category": "other", "extra": 1}):
        assert client.post("/v1/submit", json=bad).status_code == 422
    assert client.get("/v1/stats").json()["submissions_unverified"] == 1


def test_rate_limit_headers_and_429(db_path):
    c = TestClient(create_app(settings=_settings(db_path, rate_limit=3, submit_rate_limit=1)))
    rs = [c.get("/v1/stats") for _ in range(5)]
    assert [r.status_code for r in rs[:3]] == [200, 200, 200] and rs[3].status_code == 429
    assert rs[0].headers["x-ratelimit-limit"] == "3" and rs[2].headers["x-ratelimit-remaining"] == "0"
    assert int(rs[3].headers["retry-after"]) >= 1 and rs[3].json()["error"] == "rate_limited"
    assert c.get("/healthz").status_code == 200        # health checks are never rate limited
    body = {"url": "https://s.example/", "payload_hash": "c" * 64, "category": "other"}
    assert c.post("/v1/submit", json=body).status_code == 202
    assert c.post("/v1/submit", json=body).status_code == 429


def test_trust_proxy_keys_by_forwarded_for(db_path):
    c = TestClient(create_app(settings=_settings(db_path, rate_limit=1, trust_proxy=True)))
    assert c.get("/v1/stats", headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 200
    assert c.get("/v1/stats", headers={"X-Forwarded-For": "2.2.2.2"}).status_code == 200
    assert c.get("/v1/stats", headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 429


def test_rate_limit_backends(tmp_path):
    for be in (MemoryBackend(max_keys=2), SQLiteBackend(str(tmp_path / "rl.db")), make_backend("memory")):
        assert [be.hit("k", 2, 60).allowed for _ in range(3)] == [True, True, False]
        assert be.hit("other", 2, 60).allowed
    mem = MemoryBackend(max_keys=2)
    for k in "abc":
        mem.hit(k, 1, 60)
    assert mem.hit("a", 1, 60).allowed       # 'a' evicted (bounded memory)
    with pytest.raises(ValueError):
        make_backend("redis")


def test_structured_logs_have_no_ip_or_query(db_path, caplog):
    c = TestClient(create_app(settings=_settings(db_path)))
    with caplog.at_level(logging.INFO, logger="injectionwatch.api"):
        c.get("/v1/check", params={"url": "https://secret-token.example/?t=XYZ"})
    rec = [r for r in caplog.records if r.getMessage() == "request"][-1]
    assert rec.path == "/v1/check" and rec.status == 200 and rec.duration_ms >= 0
    dumped = json.dumps(vars(rec), default=str)
    assert "XYZ" not in dumped and "testclient" not in dumped


def test_json_formatter():
    import io

    from injectionwatch.logging_setup import configure

    buf = io.StringIO()
    configure("INFO", buf)
    logging.getLogger("injectionwatch.test").info("hello", extra={"k": 1})
    line = json.loads(buf.getvalue().strip().splitlines()[-1])
    assert line["msg"] == "hello" and line["k"] == 1 and line["level"] == "info"


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("INJECTIONWATCH_CORS_ORIGINS", "https://a.example, https://b.example")
    monkeypatch.setenv("INJECTIONWATCH_RATE_LIMIT", "7")
    monkeypatch.setenv("INJECTIONWATCH_TRUST_PROXY", "true")
    monkeypatch.setenv("INJECTIONWATCH_LOG_SALT", "s")
    s = Settings.from_env(db_path="x.db")
    assert s.cors_origins == ["https://a.example", "https://b.example"] and s.rate_limit == 7 and s.trust_proxy
    assert s.salt == "s" and s.db_path == "x.db"
