"""Error types with a one-line message and a hint, rendered by the CLI as ``error: ... (hint: ...)``.

Exit codes used by the CLI: 0 ok, 1 runtime error (or ``--fail-on`` triggered), 2 usage error.
"""
from __future__ import annotations


class InjectionWatchError(Exception):
    """Base class. ``hint`` is a short, actionable next step shown after the message."""

    exit_code = 1

    def __init__(self, message: str, hint: str = ""):
        super().__init__(message)
        self.message = message
        self.hint = hint

    def one_line(self) -> str:
        return f"{self.message} (hint: {self.hint})" if self.hint else self.message


class UsageError(InjectionWatchError):
    """Bad arguments or input files."""

    exit_code = 2


class MissingDependency(InjectionWatchError):
    """An optional extra is not installed."""

    def __init__(self, module: str, extra: str, purpose: str = ""):
        what = f" for {purpose}" if purpose else ""
        super().__init__(f"the optional dependency '{module}' is not installed{what}",
                         f"pip install 'injectionwatch[{extra}]'  (or: pipx inject injectionwatch "
                         f"'injectionwatch[{extra}]')")
        self.module = module
        self.extra = extra


class FetchError(InjectionWatchError):
    """The fetch failed (network, HTTP protocol, size or type limits)."""


class FetchBlocked(FetchError):
    """The fetch was refused by policy before any connection (SSRF guard, scheme, credentials)."""


class ChromiumNotFound(InjectionWatchError):
    """Playwright is installed but no usable Chromium was found."""
