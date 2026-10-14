"""Public read API + extension submission endpoint (FastAPI), versioned under /v1.

GET  /v1/check?url=...           verdict for one URL - a pure DB lookup: the URL is NEVER fetched
GET  /v1/entries?cursor=&limit=  keyset-paginated entries (filters: host, category, intent, since)
GET  /v1/entries/{id}            one entry
GET  /v1/feed?format=json|csv|stix
GET  /v1/stats                   aggregate counts
GET  /v1/health, /healthz (liveness), /readyz (DB reachable)
POST /v1/submit                  extension report: URL + payload hash + category ONLY (unverified lead)

Cross-cutting: ETag / If-None-Match (304) + Cache-Control on read routes, pluggable rate limiting
(``ratelimit.py``) with X-RateLimit-* headers, CORS (read-only public by default), request ids,
security headers, JSON structured logs without client IPs or query strings.
Configuration comes from ``Settings`` (environment variables, see ``Settings.from_env``).
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import re
import secrets
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import export
from .classify import CATEGORIES, FEED_SEVERITIES, INTENTS, severity_of
from .config import VERSION
from .db import DB, normalize_url, now_iso
from .detector import MIN_FLAG_CONFIDENCE
from .ratelimit import RateLimitBackend, make_backend
from .scorer import load_rules

log = logging.getLogger("injectionwatch.api")
MAX_URL_LEN = 2048
_CTRL_RE = re.compile(r"[\x00-\x20\x7f]")
_HOST_RE = re.compile(r"^[a-z0-9.-]+$", re.I)


# --------------------------------------------------------------------------- settings

@dataclass
class Settings:
    db_path: str = "injectionwatch.db"
    cors_origins: list[str] = field(default_factory=lambda: ["*"])
    rate_limit: int = 60                 # requests per window per client (read routes)
    submit_rate_limit: int = 10          # POST /v1/submit per window per client
    window_s: float = 60.0
    rate_backend: str = "memory"         # memory | sqlite
    rate_db: str = "ratelimit.db"
    trust_proxy: bool = False            # honour X-Forwarded-For (only behind a proxy you control)
    cache_max_age: int = 300
    salt: str = field(default_factory=lambda: secrets.token_hex(16))

    @classmethod
    def from_env(cls, **overrides: Any) -> Settings:
        env = os.environ
        s = cls(
            db_path=env.get("INJECTIONWATCH_DB", cls.db_path),
            cors_origins=[o.strip() for o in env.get("INJECTIONWATCH_CORS_ORIGINS", "*").split(",") if o.strip()],
            rate_limit=int(env.get("INJECTIONWATCH_RATE_LIMIT", cls.rate_limit)),
            submit_rate_limit=int(env.get("INJECTIONWATCH_SUBMIT_RATE_LIMIT", cls.submit_rate_limit)),
            rate_backend=env.get("INJECTIONWATCH_RATE_BACKEND", cls.rate_backend),
            rate_db=env.get("INJECTIONWATCH_RATE_DB", cls.rate_db),
            trust_proxy=env.get("INJECTIONWATCH_TRUST_PROXY", "0") in ("1", "true", "yes"),
        )
        if env.get("INJECTIONWATCH_LOG_SALT"):
            s.salt = env["INJECTIONWATCH_LOG_SALT"]
        for k, v in overrides.items():
            setattr(s, k, v)
        return s


# --------------------------------------------------------------------------- validation

def validate_http_url(url: str) -> str:
    """Validate a URL *as data*. Nothing here resolves DNS or opens connections (SSRF-safe by design)."""
    if len(url) > MAX_URL_LEN:
        raise ValueError("url too long")
    if _CTRL_RE.search(url):
        raise ValueError("url contains whitespace or control characters")
    p = urlsplit(url)
    if p.scheme.lower() not in ("http", "https"):
        raise ValueError("url must be http(s)")
    if p.username or p.password or "@" in p.netloc:
        raise ValueError("url must not contain credentials")
    host = p.hostname or ""
    if not host:
        raise ValueError("url must have a host")
    try:
        host.encode("idna")
        _ = p.port
    except (UnicodeError, ValueError) as e:
        raise ValueError(f"invalid host or port: {e}") from None
    try:
        ipaddress.ip_address(host)
        return url
    except ValueError:
        pass
    if not _HOST_RE.match(host.encode("idna").decode("ascii")):
        raise ValueError("invalid host")
    return url


# --------------------------------------------------------------------------- schemas

class EntryOut(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: int
    url: str
    url_norm: str
    host: str
    payload_hash: str = Field(description="sha256 of the normalized payload (NFKC, invisible chars stripped, "
                                          "lower-cased, whitespace collapsed)")
    payload_excerpt: str | None = Field(None, description="UNTRUSTED attacker-controlled text, truncated to 200 "
                                                          "chars, URLs defanged. Omitted unless requested.")
    category: str
    intent: str
    flagged: bool
    location: str
    techniques: list[str]
    target: str
    confidence: float
    reasons: list[str]
    classifier: str | None = None
    first_seen: str
    last_seen: str
    seen_count: int
    evidence_hash: str | None = None
    status: Literal["active", "removed", "disputed", "suppressed"]


class CheckResponse(BaseModel):
    url: str
    verdict: Literal["flagged", "observed_clean", "unknown"]
    entries: list[EntryOut]
    host_active_entries: int
    last_observed: str | None
    checked_at: str
    note: str = "unknown = never observed; observed_clean != safe. This endpoint never fetches the URL."


class EntryPage(BaseModel):
    items: list[EntryOut]
    next_cursor: int | None
    limit: int


class StatsOut(BaseModel):
    model_config = ConfigDict(extra="allow")

    entries_active: int
    entries_total: int
    hosts_with_entries: int
    urls_crawled: int
    by_category: dict[str, int]
    by_intent: dict[str, int]
    by_location: dict[str, int]
    by_target: dict[str, int]


class HealthOut(BaseModel):
    status: Literal["ok", "degraded"]
    version: str
    rules_version: str
    data_version: str | None = None


class SubmissionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(max_length=MAX_URL_LEN)
    payload_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    category: str
    technique: str = Field("unknown", max_length=200)
    extension_version: str = Field("unknown", max_length=200)

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        return validate_http_url(v)

    @field_validator("category")
    @classmethod
    def _cat(cls, v: str) -> str:
        if v not in CATEGORIES:
            raise ValueError("unknown category")
        return v

    @field_validator("technique", "extension_version")
    @classmethod
    def _short(cls, v: str) -> str:
        return re.sub(r"[^\w:.\-@\[\]=]", "", v)[:64]


class SubmissionAccepted(BaseModel):
    accepted: bool
    id: int
    stored_url: str
    note: str = "unverified until the crawler independently re-observes it"


class ErrorOut(BaseModel):
    error: str
    detail: Any = None


# --------------------------------------------------------------------------- helpers

def _public_entry(e: dict[str, Any], include_payload: bool = True) -> dict[str, Any]:
    d = dict(e)
    detector_sev = d.get("severity") or severity_of(d.get("category"), d.get("intent"))
    d["detector_severity"] = detector_sev
    d["severity"] = d.get("review_severity") or detector_sev
    d["flagged"] = d["severity"] in FEED_SEVERITIES and (d.get("confidence") or 0) >= MIN_FLAG_CONFIDENCE
    if not include_payload:
        d["payload_excerpt"] = None
    return d


def _etag(*parts: object) -> str:
    return 'W/"' + hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:32] + '"'


def _not_modified(request: Request, etag: str) -> bool:
    inm = request.headers.get("if-none-match", "")
    return any(t.strip() in (etag, "*", etag[2:]) for t in inm.split(",")) if inm else False


def _client_key(request: Request, settings: Settings) -> str:
    ip = request.client.host if request.client else "unknown"
    if settings.trust_proxy:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            ip = fwd.split(",")[0].strip()
    return hashlib.sha256((settings.salt + ip).encode()).hexdigest()[:24]


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Resource-Policy": "cross-origin",
}
API_CSP = "default-src 'none'; frame-ancestors 'none'"
_DOC_PATHS = ("/docs", "/redoc", "/v1/openapi.json")
_UNLIMITED = ("/healthz", "/readyz")


# --------------------------------------------------------------------------- app

def create_app(db_path: str | None = None, rate_limit: int | None = None, window_s: float | None = None,
               settings: Settings | None = None, rate_backend: RateLimitBackend | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    if db_path is not None:
        settings.db_path = db_path
    if rate_limit is not None:
        settings.rate_limit = rate_limit
    if window_s is not None:
        settings.window_s = window_s
    cfg, _ = load_rules()
    app = FastAPI(
        title="InjectionWatch API", version=VERSION,
        description=("Open feed of indirect prompt injections (hidden instructions aimed at AI agents) observed on "
                     "public web pages. `/v1/check` is a lookup only: it never fetches the URL you pass. "
                     "Payload excerpts are untrusted attacker-controlled text. Feed data: CC BY 4.0."),
        license_info={"name": "Code: Apache-2.0; feed data: CC BY 4.0",
                      "url": "https://creativecommons.org/licenses/by/4.0/"},
        openapi_url="/v1/openapi.json", docs_url="/docs", redoc_url="/redoc",
        openapi_tags=[{"name": "feed", "description": "Read-only feed access"},
                      {"name": "submissions", "description": "Unverified leads from the browser extension"},
                      {"name": "ops", "description": "Health checks"}],
    )
    db = DB(settings.db_path)
    limiter = rate_backend or make_backend(settings.rate_backend, settings.rate_db)
    app.state.db = db
    app.state.settings = settings

    app.add_middleware(
        CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["Content-Type", "If-None-Match"],
        expose_headers=["ETag", "Link", "X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining",
                        "X-RateLimit-Reset", "Retry-After"], max_age=600)

    @app.middleware("http")
    async def _edge(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        t0 = time.perf_counter()
        rid = request.headers.get("x-request-id", "")
        if not re.fullmatch(r"[\w-]{8,64}", rid):
            rid = uuid.uuid4().hex
        path = request.url.path
        rl = None
        if path not in _UNLIMITED and request.method != "OPTIONS":
            is_submit = path.endswith("/submit") and request.method == "POST"
            limit = settings.submit_rate_limit if is_submit else settings.rate_limit
            key = ("submit:" if is_submit else "read:") + _client_key(request, settings)
            rl = limiter.hit(key, limit, settings.window_s)
        if rl is not None and not rl.allowed:
            response: Response = JSONResponse({"error": "rate_limited", "detail": f"retry in {rl.reset_s}s"},
                                              status_code=429, headers={"Retry-After": str(rl.reset_s)})
        else:
            response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        if rl is not None:
            response.headers["X-RateLimit-Limit"] = str(rl.limit)
            response.headers["X-RateLimit-Remaining"] = str(rl.remaining)
            response.headers["X-RateLimit-Reset"] = str(rl.reset_s)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if not path.startswith(_DOC_PATHS):
            response.headers.setdefault("Content-Security-Policy", API_CSP)
        log.info("request", extra={"request_id": rid, "method": request.method, "path": path,
                                   "status": response.status_code,
                                   "duration_ms": round((time.perf_counter() - t0) * 1000, 2)})
        return response

    def cached(request: Request, etag: str, body: Any, media_type: str = "application/json",
               last_modified: str | None = None) -> Response:
        headers = {"ETag": etag, "Cache-Control": f"public, max-age={settings.cache_max_age}"}
        if last_modified:
            headers["X-Last-Observed"] = last_modified
        if _not_modified(request, etag):
            return Response(status_code=304, headers=headers)
        if isinstance(body, (str, bytes)):
            return Response(body, media_type=media_type, headers=headers)
        return JSONResponse(body, headers=headers)

    # ---------------------------------------------------------------- ops
    @app.get("/healthz", tags=["ops"], include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", tags=["ops"], include_in_schema=False, responses={503: {"model": ErrorOut}})
    def readyz() -> Response:
        try:
            db.ping()
        except Exception:
            return JSONResponse({"error": "db_unavailable"}, status_code=503)
        return JSONResponse({"status": "ready"})

    @app.get("/v1/health", tags=["ops"], response_model=HealthOut)
    def health() -> HealthOut:
        try:
            dv: str | None = db.data_version()
            status: Literal["ok", "degraded"] = "ok"
        except Exception:
            dv, status = None, "degraded"
        return HealthOut(status=status, version=VERSION, rules_version=str(cfg["version"]), data_version=dv)

    # ---------------------------------------------------------------- feed
    @app.get("/v1/check", tags=["feed"], response_model=CheckResponse,
             responses={304: {"description": "Not modified"}, 422: {"model": ErrorOut}})
    def check(request: Request,
              url: str = Query(..., max_length=MAX_URL_LEN, description="http(s) URL to look up (never fetched)"),
              include_payload: bool = Query(False, description="include untrusted payload excerpts")) -> Response:
        try:
            validate_http_url(url)
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        etag = _etag(db.data_version(), normalize_url(url), include_payload)
        if _not_modified(request, etag):
            return cached(request, etag, None)
        entries = [_public_entry(e, include_payload) for e in db.entries_for_url(url, include_payload=True)]
        last = db.last_crawl(url)
        verdict: Literal["flagged", "observed_clean", "unknown"]
        if any(e["flagged"] for e in entries):
            verdict = "flagged"
        elif last and last.get("status") == 200:
            verdict = "observed_clean"
        else:
            verdict = "unknown"
        body = CheckResponse(url=normalize_url(url), verdict=verdict, entries=[EntryOut(**e) for e in entries],
                             host_active_entries=db.host_entry_count(url),
                             last_observed=last.get("fetched_at") if last else None, checked_at=now_iso())
        return cached(request, etag, body.model_dump(mode="json"))

    @app.get("/v1/entries", tags=["feed"], response_model=EntryPage)
    def entries(request: Request,
                cursor: int | None = Query(None, ge=1, description="opaque cursor from next_cursor"),
                limit: int = Query(100, ge=1, le=500),
                since: str | None = Query(None, max_length=40, pattern=r"^\d{4}-\d{2}-\d{2}[T\d:.+\-Z]*$"),
                host: str | None = Query(None, max_length=255, pattern=r"^[A-Za-z0-9.\-:\[\]]+$"),
                category: str | None = Query(None), intent: str | None = Query(None),
                include_payload: bool = False, include_inactive: bool = False) -> Response:
        if category and category not in CATEGORIES:
            raise HTTPException(422, "unknown category")
        if intent and intent not in INTENTS:
            raise HTTPException(422, "unknown intent")
        etag = _etag(db.data_version(), cursor, limit, since, host, category, intent, include_payload,
                     include_inactive)
        if _not_modified(request, etag):
            return cached(request, etag, None)
        rows, nxt = db.entries_page(cursor, limit, since, host, category, intent, include_inactive)
        page = EntryPage(items=[EntryOut(**_public_entry(r, include_payload)) for r in rows],
                         next_cursor=nxt, limit=limit)
        resp = cached(request, etag, page.model_dump(mode="json"))
        if nxt is not None:
            q = request.query_params.multi_items()
            qs = "&".join(f"{k}={v}" for k, v in q if k != "cursor") + ("&" if q else "") + f"cursor={nxt}"
            resp.headers["Link"] = f'</v1/entries?{qs.lstrip("&")}>; rel="next"'
        return resp

    @app.get("/v1/entries/{entry_id}", tags=["feed"], response_model=EntryOut, responses={404: {"model": ErrorOut}})
    def entry(request: Request, entry_id: int = Path(..., ge=1), include_payload: bool = False) -> Response:
        e = db.get_entry(entry_id)
        if e is None:
            raise HTTPException(404, "no such entry")
        return cached(request, _etag(db.data_version(), entry_id, include_payload),
                      EntryOut(**_public_entry(e, include_payload)).model_dump(mode="json"))

    @app.get("/v1/feed", tags=["feed"], responses={200: {"content": {
        "application/json": {}, "text/csv": {}, "application/stix+json;version=2.1": {}}}})
    def feed(request: Request, format: Literal["json", "csv", "stix"] = "json",
             since: str | None = Query(None, max_length=40, pattern=r"^\d{4}-\d{2}-\d{2}[T\d:.+\-Z]*$"),
             include_inactive: bool = False, limit: int = Query(1000, ge=1, le=10000)) -> Response:
        etag = _etag(db.data_version(), format, since, include_inactive, limit)
        if _not_modified(request, etag):
            return cached(request, etag, None)
        rows = db.feed(since=since, include_inactive=include_inactive, limit=limit)
        if format == "csv":
            return cached(request, etag, export.to_csv(rows), "text/csv; charset=utf-8")
        if format == "stix":
            return cached(request, etag, export.to_stix(rows), "application/stix+json;version=2.1")
        return cached(request, etag, export.to_json(rows), "application/json")

    @app.get("/v1/stats", tags=["feed"], response_model=StatsOut)
    def stats(request: Request) -> Response:
        etag = _etag(db.data_version(), "stats")
        if _not_modified(request, etag):
            return cached(request, etag, None)
        return cached(request, etag, db.stats())

    # ---------------------------------------------------------------- submissions
    @app.post("/v1/submit", tags=["submissions"], status_code=202, response_model=SubmissionAccepted)
    def submit(sub: SubmissionIn) -> SubmissionAccepted:
        # Query + fragment are stripped server-side too: they can carry session tokens / PII.
        url = normalize_url(sub.url, keep_query=False)
        sid = db.add_submission(url, sub.payload_hash, sub.category, sub.technique,
                                f"extension/{sub.extension_version}")
        return SubmissionAccepted(accepted=True, id=sid, stored_url=url)

    # ---------------------------------------------------------------- legacy (v0.1) paths
    for old in ("check", "feed", "stats"):
        def _legacy(request: Request, _old: str = old) -> Response:
            target = f"/v1/{_old}" + (f"?{request.url.query}" if request.url.query else "")
            return RedirectResponse(target, status_code=308, headers={"Deprecation": "true"})

        app.add_api_route(f"/{old}", _legacy, methods=["GET"], include_in_schema=False)

    @app.exception_handler(HTTPException)
    async def _http_exc(_request: Request, exc: HTTPException) -> JSONResponse:
        code = {404: "not_found", 422: "invalid_request", 429: "rate_limited"}.get(exc.status_code, "error")
        return JSONResponse({"error": code, "detail": exc.detail}, status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def _validation_exc(_request: Request, exc: RequestValidationError) -> JSONResponse:
        detail = [{"loc": list(e.get("loc", [])), "msg": e.get("msg", "")} for e in exc.errors()]
        return JSONResponse({"error": "invalid_request", "detail": detail}, status_code=422)

    return app


def app_from_env() -> FastAPI:
    """ASGI factory: ``uvicorn --factory injectionwatch.api:app_from_env``."""
    return create_app(settings=Settings.from_env())
