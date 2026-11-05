"""InjectionWatch: find and strip hidden prompt injections before an AI agent reads a page.

Public API (imported lazily, so ``import injectionwatch`` stays cheap):

    from injectionwatch import guard            # guard.fetch / sanitize / scan_html / scan_text
    from injectionwatch import FetchPolicy, SanitizedPage, wrap_tool
"""
from __future__ import annotations

import importlib
from typing import Any

from .config import VERSION as __version__

__all__ = ["FetchPolicy", "SanitizedPage", "__version__", "guard", "wrap_tool"]


def __getattr__(name: str) -> Any:
    if name == "guard":
        return importlib.import_module(".guard", __name__)
    if name in ("FetchPolicy", "SanitizedPage"):
        return getattr(importlib.import_module(".guard", __name__), name)
    if name == "wrap_tool":
        return importlib.import_module(".integrations.tools", __name__).wrap_tool
    raise AttributeError(f"module 'injectionwatch' has no attribute {name!r}")
