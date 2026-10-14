"""Text normalization, hashing, truncation and defanging.

The payload hash definition MUST stay in sync with extension/src/scorer.ts
(`iwNormalize`): NFKC -> drop zero-width + Unicode tag chars -> lowercase ->
collapse whitespace -> strip -> sha256 hex.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata

# Zero-width / invisible formatting characters commonly used to hide or split text.
ZERO_WIDTH = "​‌‍⁠﻿᠎"
SOFT_HYPHEN = "­"
_ZW_RE = re.compile(f"[{ZERO_WIDTH}{SOFT_HYPHEN}]")
_TAG_RE = re.compile("[\U000E0000-\U000E007F]")
_WS_RE = re.compile(r"\s+")
# zero-width char sitting between two ASCII letters = likely keyword-splitting obfuscation
_ZW_IN_WORD_RE = re.compile(f"[A-Za-z][{ZERO_WIDTH}]+[A-Za-z]")
_URL_RE = re.compile(r"\b(https?)://([^\s\"'<>]+)", re.I)

EXCERPT_LEN = 200


def strip_invisible(s: str) -> str:
    return _TAG_RE.sub("", _ZW_RE.sub("", s))


def has_zero_width_obfuscation(s: str) -> bool:
    return bool(_ZW_IN_WORD_RE.search(s))


def decode_unicode_tags(s: str) -> str:
    """Decode Unicode 'tag' characters (U+E0020..U+E007E) to ASCII ("ASCII smuggling")."""
    out = []
    for ch in s:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            out.append(chr(cp - 0xE0000))
    return "".join(out)


def find_unicode_tag_runs(s: str, min_len: int = 4) -> list[str]:
    runs = re.findall("[\U000E0000-\U000E007F]{%d,}" % min_len, s)
    return [decode_unicode_tags(r) for r in runs]


def clean_for_scoring(s: str) -> str:
    """Remove invisible chars and collapse whitespace, keeping case for display."""
    s = unicodedata.normalize("NFKC", s)
    s = strip_invisible(s)
    return _WS_RE.sub(" ", s).strip()


def normalize_payload(s: str) -> str:
    return clean_for_scoring(s).lower()


def payload_hash(s: str) -> str:
    return hashlib.sha256(normalize_payload(s).encode("utf-8")).hexdigest()


def sha256_bytes(b: bytes | str) -> str:
    if isinstance(b, str):
        b = b.encode("utf-8", "replace")
    return hashlib.sha256(b).hexdigest()


def defang(s: str) -> str:
    """Make URLs non-clickable/non-fetchable: https://evil.com/x -> hxxps://evil[.]com/x"""

    def _sub(m: re.Match) -> str:
        scheme = m.group(1).lower().replace("http", "hxxp")
        rest = m.group(2)
        host, sep, tail = rest.partition("/")
        return f"{scheme}://{host.replace('.', '[.]')}{sep}{tail}"

    return _URL_RE.sub(_sub, s)


def excerpt(s: str, n: int = EXCERPT_LEN) -> str:
    s = defang(clean_for_scoring(s))
    return s if len(s) <= n else s[: n - 1].rstrip() + "…"


_TEMPLATE_SUBS = [
    (re.compile(r"\bhxxps?://\S+|\bhttps?://\S+", re.I), "<url>"),
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.\[\]-]+\b"), "<email>"),
    (re.compile(r"\d+"), "<n>"),
]


def template_key(s: str, n: int = 120) -> str:
    t = normalize_payload(s)
    for rx, rep in _TEMPLATE_SUBS:
        t = rx.sub(rep, t)
    return t[:n]
