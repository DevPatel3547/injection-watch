"""Optional rendered pass (Playwright + Chromium) to compute visible vs hidden text.

Uses the same JS extractor as the browser extension (``js/hidden_text.js``), which reads
*computed* styles, so external stylesheets, cascades and JS-inserted content are handled
by the browser itself.

* ``candidates_from_html`` renders local HTML under a fake origin (``https://render.invalid/``).
  Subresource requests never touch the network: stylesheets (and other files) are served from
  ``resources`` (path -> content) or a ``css_resolver`` callback; everything else is aborted.
* ``candidates_from_url`` renders a live page; images, media and fonts are blocked (politeness,
  speed); documents, stylesheets and scripts load normally.

Chromium: ``$INJECTIONWATCH_CHROMIUM`` (path to a chromium / headless_shell / Chrome binary) wins; otherwise
Playwright's own download (``python -m playwright install chromium``, honouring ``PLAYWRIGHT_BROWSERS_PATH``).
On macOS an installed Google Chrome also works: ``INJECTIONWATCH_CHROMIUM="/Applications/Google
Chrome.app/Contents/MacOS/Google Chrome"``.
"""
from __future__ import annotations

import mimetypes
from collections.abc import Callable, Mapping
from importlib import resources as pkg_resources
from typing import Any
from urllib.parse import urlsplit

from .errors import ChromiumNotFound, MissingDependency
from .extract import Candidate

JS_SOURCE = pkg_resources.files("injectionwatch").joinpath("js/hidden_text.js").read_text("utf-8")
_EVAL = "() => { %s\n return injectionwatchHiddenText(document); }" % JS_SOURCE.replace(
    'if (typeof module !== "undefined"', 'if (false && typeof module !== "undefined"')
FAKE_ORIGIN = "https://render.invalid/"
_BLOCK_LIVE = {"image", "media", "font"}
CHROMIUM_ENV = "INJECTIONWATCH_CHROMIUM"
MAC_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


def chromium_hint() -> str:
    import sys

    base = "python -m playwright install chromium"
    if sys.platform == "darwin":
        return (f"{base}  (or use an installed Chrome: export {CHROMIUM_ENV}=\"{MAC_CHROME}\")")
    if sys.platform.startswith("linux"):
        return f"{base} --with-deps  (or set {CHROMIUM_ENV}=/path/to/chromium)"
    return f"{base}  (or set {CHROMIUM_ENV}=path\\to\\chrome.exe)"


def chromium_executable() -> str | None:
    """The explicit Chromium override, if set and present (None = let Playwright find its own)."""
    import os

    p = os.environ.get(CHROMIUM_ENV, "").strip()
    if not p:
        return None
    if not os.path.isfile(p):
        raise ChromiumNotFound(f"{CHROMIUM_ENV} points to {p!r}, which does not exist", chromium_hint())
    return p


def _content_type(path: str) -> str:
    if path.endswith(".css"):
        return "text/css; charset=utf-8"
    return mimetypes.guess_type(path)[0] or "application/octet-stream"


class Renderer:
    def __init__(self, user_agent: str | None = None, timeout_ms: int = 15000, executable_path: str | None = None):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as e:
            raise MissingDependency("playwright", "render", "the rendered pass") from e
        exe = executable_path or chromium_executable()
        self._pw = sync_playwright().start()
        try:
            self._browser = self._pw.chromium.launch(headless=True, executable_path=exe)
            self._ctx = self._browser.new_context(user_agent=user_agent, java_script_enabled=True,
                                                  service_workers="block")
        except Exception as e:
            self._pw.stop()
            msg = str(e)
            if "Executable doesn't exist" in msg or "executable" in msg.lower() and "not found" in msg.lower():
                raise ChromiumNotFound("Playwright is installed but no Chromium was found", chromium_hint()) from None
            raise ChromiumNotFound(f"could not start Chromium: {msg.splitlines()[0][:160]}", chromium_hint()) from None
        self.timeout_ms = timeout_ms

    @staticmethod
    def _to_candidates(data: dict[str, Any]) -> list[Candidate]:
        out = []
        for c in data.get("candidates", []):
            techs = list(c.get("techniques") or [])
            if c["location"] != "visible":
                techs.append("rendered")
            out.append(Candidate(c["text"], c["location"], techs, c.get("path", ""), bool(c.get("in_code"))))
        return out

    def candidates_from_html(self, html: str, resources: Mapping[str, str | bytes] | None = None,
                             css_resolver: Callable[[str], str | None] | None = None,
                             base_url: str = FAKE_ORIGIN) -> list[Candidate]:
        """Render ``html`` offline. ``resources`` maps URL paths (``/static/site.css``) to content."""
        res = dict(resources or {})
        page = self._ctx.new_page()

        def handler(route: Any) -> None:
            req = route.request
            url = req.url
            if url == base_url:
                route.fulfill(status=200, content_type="text/html; charset=utf-8", body=html)
                return
            path = urlsplit(url).path
            if path in res:
                body = res[path]
                route.fulfill(status=200, content_type=_content_type(path),
                              body=body if isinstance(body, bytes) else body.encode("utf-8"))
                return
            if css_resolver is not None and req.resource_type == "stylesheet":
                try:
                    css = css_resolver(url)
                except Exception:
                    css = None
                if css is not None:
                    route.fulfill(status=200, content_type="text/css; charset=utf-8", body=css)
                    return
            route.abort()

        try:
            page.route("**/*", handler)
            page.goto(base_url, timeout=self.timeout_ms, wait_until="load")
            return self._to_candidates(page.evaluate(_EVAL))
        finally:
            page.close()

    def candidates_from_url(self, url: str) -> tuple[list[Candidate], str]:
        page = self._ctx.new_page()
        try:
            page.route("**/*", lambda route: route.abort() if route.request.resource_type in _BLOCK_LIVE
                       else route.continue_())
            page.goto(url, timeout=self.timeout_ms, wait_until="load")
            return self._to_candidates(page.evaluate(_EVAL)), page.content()
        finally:
            page.close()

    def close(self) -> None:
        try:
            self._ctx.close()
            self._browser.close()
        finally:
            self._pw.stop()

    def __enter__(self) -> Renderer:
        return self

    def __exit__(self, *a: object) -> None:
        self.close()
