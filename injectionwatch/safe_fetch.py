"""Hardened fetching for agents: SSRF guard, redirect re-checks, size and type limits.

``fetch_page(url, policy)`` is the low-level, policy-enforcing HTTP GET used by ``guard.fetch``,
the MCP ``fetch_url_safely`` tool and ``safe_fetch()``. What it guarantees:

* http/https only, no credentials in the URL;
* the host is resolved once and EVERY address must be public (no private, loopback,
  link-local, CGNAT, multicast, reserved or unspecified ranges, IPv4 or IPv6, including
  IPv4-mapped, 6to4, Teredo and NAT64 embeddings) unless ``allow_private=True``;
* the connection goes to the vetted IP itself (TLS still verifies the certificate against the
  real host name via SNI), so a DNS answer that changes between check and connect
  (DNS rebinding) cannot redirect the request;
* redirects are followed by hand, at most ``max_redirects``, and every hop is re-vetted;
* the body is streamed and capped (``max_bytes``, measured after decompression, so a gzip bomb
  stops at the cap), only HTML or plain-text content types are accepted, one total timeout.

Proxies: when an HTTP(S) proxy is configured (``HTTPS_PROXY`` etc., honoured by default like
``requests`` does) the proxy makes its own DNS lookup. The host is still vetted locally first,
but the connect-to-vetted-IP guarantee then depends on the proxy. Set
``FetchPolicy(trust_env_proxy=False)`` to connect directly.

``safe_fetch()`` (v0.1 API) is kept as a thin wrapper around ``guard.fetch``.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urljoin, urlsplit

from .config import GUARD_UA
from .errors import FetchBlocked, FetchError

Resolver = Callable[[str, int], list[str]]

DEFAULT_TYPES = ("text/html", "text/plain", "application/xhtml+xml")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_CHARSET_RE = re.compile(rb"""<meta[^>]+charset\s*=\s*["']?([A-Za-z0-9_\-:.]+)""", re.I)


@dataclass(frozen=True)
class FetchPolicy:
    """Limits for one fetch. The defaults are what an agent tool should use."""

    allow_private: bool = False
    max_redirects: int = 5
    max_bytes: int = 5 * 1024 * 1024
    timeout: float = 15.0
    allowed_types: tuple[str, ...] = DEFAULT_TYPES
    allow_missing_type: bool = True
    user_agent: str | None = None          # None -> identifies as InjectionWatch (not a browser)
    allowed_ports: frozenset[int] | None = None   # None -> any port
    trust_env_proxy: bool = True
    verify_tls: bool = True

    @property
    def ua(self) -> str:
        return self.user_agent or GUARD_UA


@dataclass
class FetchedPage:
    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    body: bytes
    content_type: str
    charset: str
    redirects: list[str] = field(default_factory=list)
    ip: str = ""

    @property
    def text(self) -> str:
        return self.body.decode(self.charset or "utf-8", errors="replace")


# --------------------------------------------------------------------------- address vetting

def _embedded_v4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip.teredo is not None:
        return ip.teredo[1]
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def blocked_reason(ip_str: str) -> str | None:
    """Why this address must not be fetched by an agent, or None if it is a public unicast address."""
    try:
        ip = ipaddress.ip_address(ip_str.split("%", 1)[0])
    except ValueError:
        return "not an IP address"
    if isinstance(ip, ipaddress.IPv6Address):
        inner = _embedded_v4(ip)
        if inner is not None:
            r = blocked_reason(str(inner))
            return f"embeds {inner}: {r}" if r else None
    for attr, why in (("is_loopback", "loopback"), ("is_link_local", "link-local (cloud metadata lives here)"),
                      ("is_multicast", "multicast"), ("is_unspecified", "unspecified"),
                      ("is_private", "private network"), ("is_reserved", "reserved")):
        if getattr(ip, attr):
            return why
    if not ip.is_global:
        return "not globally routable"
    return None


def system_resolver(host: str, port: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise FetchError(f"cannot resolve host {host!r}: {e.strerror or e}",
                         "check the URL, your network and DNS") from None
    out: list[str] = []
    for info in infos:
        addr = str(info[4][0])
        if addr not in out:
            out.append(addr)
    return out


def vet_url(url: str, policy: FetchPolicy, resolver: Resolver = system_resolver) -> tuple[str, str, int, str]:
    """Validate ``url`` against ``policy``; returns (scheme, host, port, vetted_ip). Raises FetchBlocked."""
    try:
        p = urlsplit(url)
        port = p.port
    except ValueError as e:
        raise FetchBlocked(f"invalid URL: {e}", "pass an absolute http(s) URL") from None
    scheme = p.scheme.lower()
    if scheme not in ("http", "https"):
        raise FetchBlocked(f"scheme {scheme or '(none)'!r} is not allowed", "only http and https URLs can be fetched")
    if p.username is not None or p.password is not None:
        raise FetchBlocked("URLs with embedded credentials are not allowed", "remove the user:password@ part")
    host = (p.hostname or "").rstrip(".")
    if not host:
        raise FetchBlocked("URL has no host", "pass an absolute http(s) URL")
    port = port or (443 if scheme == "https" else 80)
    if policy.allowed_ports is not None and port not in policy.allowed_ports:
        raise FetchBlocked(f"port {port} is not allowed by the fetch policy", "use a standard port")
    try:
        literal: str | None = str(ipaddress.ip_address(host))
    except ValueError:
        literal = None
    addrs = [literal] if literal else resolver(host, port)
    if not addrs:
        raise FetchError(f"host {host!r} resolved to no addresses", "check the URL")
    if not policy.allow_private:
        for a in addrs:
            why = blocked_reason(a)
            if why:
                raise FetchBlocked(f"refusing to fetch {host}: it resolves to {a} ({why})",
                                   "agents must not reach internal addresses; pass allow_private=True only for "
                                   "trusted local testing")
    return scheme, host, port, addrs[0]


# --------------------------------------------------------------------------- transport

class Transport(Protocol):
    def open(self, *, scheme: str, host: str, port: int, ip: str, path: str, headers: Mapping[str, str],
             timeout: float, policy: FetchPolicy, url: str) -> Any:
        """Return a urllib3-style streaming response (``status``, ``headers``, ``stream()``, ``release_conn()``)."""
        ...


def _ca_bundle() -> str | bool:
    for var in ("REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE"):
        v = os.environ.get(var)
        if v and os.path.exists(v):
            return v
    try:
        import certifi

        return str(certifi.where())
    except Exception:  # pragma: no cover - certifi ships with requests
        return True


class Urllib3Transport:
    """Connects to the vetted IP; TLS uses SNI and certificate checks for the real host name."""

    def _proxy_for(self, url: str, policy: FetchPolicy) -> str | None:
        if not policy.trust_env_proxy:
            return None
        from requests.utils import get_environ_proxies

        proxies = get_environ_proxies(url)
        return proxies.get(urlsplit(url).scheme.lower()) or proxies.get("all")

    def open(self, *, scheme: str, host: str, port: int, ip: str, path: str, headers: Mapping[str, str],
             timeout: float, policy: FetchPolicy, url: str) -> Any:
        import urllib3

        t = urllib3.Timeout(connect=min(timeout, 10.0), read=timeout)
        ca = _ca_bundle()
        tls: dict[str, Any] = {"cert_reqs": "CERT_REQUIRED" if policy.verify_tls else "CERT_NONE"}
        if policy.verify_tls and isinstance(ca, str):
            tls["ca_certs"] = ca
        proxy = self._proxy_for(url, policy)
        try:
            if proxy:
                pm = urllib3.ProxyManager(proxy, timeout=t, retries=False, **(tls if scheme == "https" else {}))
                return pm.request("GET", url, headers=dict(headers), preload_content=False, redirect=False,
                                  retries=False, decode_content=True)
            hostport = f"[{ip}]" if ":" in ip else ip
            pool: Any
            if scheme == "https":
                pool = urllib3.HTTPSConnectionPool(hostport.strip("[]"), port, timeout=t, retries=False,
                                                   server_hostname=host,
                                                   assert_hostname=host if policy.verify_tls else False, **tls)
            else:
                pool = urllib3.HTTPConnectionPool(hostport.strip("[]"), port, timeout=t, retries=False)
            return pool.urlopen("GET", path, headers=dict(headers), preload_content=False, redirect=False,
                                retries=False, decode_content=True, assert_same_host=False)
        except urllib3.exceptions.SSLError as e:
            raise FetchError(f"TLS error for {host}: {e}", "the site's certificate did not verify") from None
        except urllib3.exceptions.TimeoutError:
            raise FetchError(f"timed out connecting to {host}", "try again later or raise the timeout") from None
        except urllib3.exceptions.HTTPError as e:
            raise FetchError(f"connection to {host} failed: {type(e).__name__}",
                             "check the URL and your network") from None


# --------------------------------------------------------------------------- fetch

def _media_type(ct: str) -> str:
    return ct.split(";", 1)[0].strip().lower()


def _charset(ct: str, head: bytes) -> str:
    m = re.search(r"charset\s*=\s*\"?([A-Za-z0-9_\-:.]+)", ct, re.I)
    if m:
        cs = m.group(1)
    else:
        mm = _CHARSET_RE.search(head[:4096])
        cs = mm.group(1).decode("ascii", "ignore") if mm else "utf-8"
    try:
        "".encode(cs)
    except LookupError:
        cs = "utf-8"
    return cs


def fetch_page(url: str, policy: FetchPolicy | None = None, *, resolver: Resolver = system_resolver,
               transport: Transport | None = None) -> FetchedPage:
    """Policy-enforcing GET. Raises FetchBlocked (policy) or FetchError (network, limits, type)."""
    policy = policy or FetchPolicy()
    transport = transport or Urllib3Transport()
    deadline = time.monotonic() + policy.timeout
    current = url
    redirects: list[str] = []
    while True:
        scheme, host, port, ip = vet_url(current, policy, resolver)
        p = urlsplit(current)
        path = (p.path or "/") + (f"?{p.query}" if p.query else "")
        default_port = 443 if scheme == "https" else 80
        headers = {"Host": host if port == default_port else f"{host}:{port}", "User-Agent": policy.ua,
                   "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9",
                   "Accept-Encoding": "gzip, deflate", "Connection": "close"}
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FetchError(f"timed out after {policy.timeout:g}s", "the site is slow; raise the timeout")
        resp = transport.open(scheme=scheme, host=host, port=port, ip=ip, path=path, headers=headers,
                              timeout=remaining, policy=policy, url=current)
        try:
            status = int(resp.status)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            if status in (301, 302, 303, 307, 308) and hdrs.get("location"):
                if len(redirects) >= policy.max_redirects:
                    raise FetchError(f"too many redirects (> {policy.max_redirects})", "the URL redirects in a loop")
                nxt = urljoin(current, hdrs["location"])
                redirects.append(nxt)
                current = nxt
                continue
            ct = hdrs.get("content-type", "")
            mt = _media_type(ct)
            if mt and mt not in policy.allowed_types:
                raise FetchError(f"content type {mt!r} is not allowed",
                                 f"only {', '.join(policy.allowed_types)} are fetched")
            if not mt and not policy.allow_missing_type:
                raise FetchError("response has no content type", "the server must send Content-Type")
            try:
                declared = int(hdrs.get("content-length", "-1"))
            except ValueError:
                declared = -1
            if declared > policy.max_bytes:
                raise FetchError(f"body is {declared} bytes, over the {policy.max_bytes}-byte cap",
                                 "raise FetchPolicy.max_bytes if you really need this page")
            buf = bytearray()
            for chunk in resp.stream(64 * 1024):
                buf += chunk
                if len(buf) > policy.max_bytes:
                    raise FetchError(f"body exceeds the {policy.max_bytes}-byte cap",
                                     "raise FetchPolicy.max_bytes if you really need this page")
                if time.monotonic() > deadline:
                    raise FetchError(f"timed out after {policy.timeout:g}s while reading the body",
                                     "the site is slow; raise the timeout")
            body = bytes(buf)
            return FetchedPage(url, current, status, hdrs, body, mt or "text/html", _charset(ct, body), redirects, ip)
        except FetchError:
            raise
        except Exception as e:  # urllib3 read errors, decode errors
            raise FetchError(f"error reading response from {host}: {type(e).__name__}",
                             "check the URL and your network") from None
        finally:
            try:
                resp.release_conn()
            except Exception:
                pass


# --------------------------------------------------------------------------- v0.1 compatibility

@dataclass
class SafeFetchResult:
    url: str
    verdict: str                 # flagged | clean | blocked
    feed_verdict: str            # from /check: flagged | observed_clean | unknown | unavailable
    text: str
    removed: list[dict[str, Any]] = field(default_factory=list)
    status: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def _feed_lookup(url: str, api_base: str | None, db_path: str | None, session: Any = None) -> str:
    """Feed verdict for ``url``: flagged | observed_clean | unknown | unavailable. Never raises."""
    try:
        if db_path:
            from .classify import FLAG_INTENTS
            from .db import DB

            db = DB(db_path)
            try:
                es = db.entries_for_url(url)
                if any(e["intent"] in FLAG_INTENTS for e in es):
                    return "flagged"
                return "observed_clean" if db.last_crawl(url) else "unknown"
            finally:
                db.close()
        if api_base:
            import requests

            session = session or requests.Session()
            r = session.get(f"{api_base.rstrip('/')}/v1/check", params={"url": url}, timeout=5)
            return str(r.json().get("verdict", "unavailable"))
    except Exception:
        return "unavailable"
    return "unknown"


def sanitize_html(html: str, headers: dict[str, str] | None = None, url: str = "", classifier: Any = None):
    """(visible text minus flagged blocks, ScanResult). Kept for v0.1 callers; see guard.sanitize."""
    from .guard import _sanitize

    text, _removed, res, _hidden = _sanitize(html, url, headers, classifier)
    return text, res


def safe_fetch(url: str, api_base: str | None = None, db_path: str | None = None, fetcher: Any = None,
               block_on_flagged: bool = True, classifier: Any = None, session: Any = None,
               policy: FetchPolicy | None = None) -> SafeFetchResult:
    """v0.1 API. ``fetcher(url) -> {"text", "headers", "status"}`` bypasses the network (tests,
    custom transports). Without it the hardened ``fetch_page`` is used. Policy violations come back
    as verdict ``blocked`` with the reason in ``removed``; they are not raised."""
    from .guard import fetch as guard_fetch
    from .guard import sanitize

    feed_verdict = _feed_lookup(url, api_base, db_path, session)
    if feed_verdict == "flagged" and block_on_flagged:
        return SafeFetchResult(url, "blocked", feed_verdict, "", [], None)
    if fetcher is not None:
        fr = fetcher(url)
        page = sanitize(fr["text"], url, headers=fr.get("headers", {}), classifier=classifier)
        status = fr.get("status")
    else:
        try:
            page = guard_fetch(url, policy=policy, classifier=classifier, check_feed=False)
        except FetchBlocked as e:
            return SafeFetchResult(url, "blocked", feed_verdict, "", [{"reason": e.message}], None)
        status = page.status
    verdict = "flagged" if page.removed or feed_verdict == "flagged" else "clean"
    return SafeFetchResult(url, verdict, feed_verdict, page.text, page.removed, status)
