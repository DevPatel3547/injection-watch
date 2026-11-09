"""``injectionwatch scan-site DIR``: scan a built static site (or any directory of HTML) for hidden prompt
injections, for example text planted by a compromised CMS plugin, theme, dependency or user content.

Stylesheets referenced by the pages are resolved from the same directory (never fetched), so CSS-based
hiding in the site's own CSS is caught by the static pass. Nothing touches the network.
"""
from __future__ import annotations

import fnmatch
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .detector import Finding, ScanResult, scan_html
from .errors import UsageError

DEFAULT_INCLUDE = ("*.html", "*.htm", "*.xhtml", "*.shtml")
DEFAULT_EXCLUDE = ("node_modules/*", ".git/*", "*/node_modules/*", "*/.git/*")
SITE_ORIGIN = "https://site.invalid/"
MAX_FILE_BYTES = 10 * 1024 * 1024


@dataclass
class FileResult:
    path: Path            # absolute
    rel: str              # posix path relative to the scanned root
    result: ScanResult
    lines: dict[str, int] = field(default_factory=dict)   # payload_hash -> 1-based line in the file

    def line_of(self, f: Finding) -> int:
        return self.lines.get(f.payload_hash, 1)


@dataclass
class SiteScan:
    root: Path
    files: list[FileResult]
    skipped: list[tuple[str, str]] = field(default_factory=list)

    def findings(self) -> Iterable[tuple[FileResult, Finding]]:
        for fr in self.files:
            for f in fr.result.findings:
                yield fr, f

    @property
    def n_findings(self) -> int:
        return sum(len(fr.result.findings) for fr in self.files)

    @property
    def n_flagged(self) -> int:
        return sum(1 for _, f in self.findings() if f.flagged)

    def summary(self) -> dict[str, Any]:
        by_sev: dict[str, int] = {}
        for _, f in self.findings():
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        return {"root": str(self.root), "files_scanned": len(self.files), "files_skipped": len(self.skipped),
                "findings": self.n_findings, "flagged": self.n_flagged, "by_severity": by_sev,
                "files_flagged": sum(1 for fr in self.files if fr.result.verdict == "flagged")}


def _css_resolver(root: Path, page_rel: str):
    root_r = root.resolve()

    def resolve(url: str) -> str | None:
        path = url
        if url.startswith(SITE_ORIGIN):
            path = url[len(SITE_ORIGIN):]
        elif re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I) or url.startswith("//"):
            # absolute URL to some host: the site's own asset is usually at the same path under the root
            path = re.sub(r"^[a-z][a-z0-9+.-]*:", "", url, flags=re.I).lstrip("/")
            path = path.split("/", 1)[1] if "/" in path else ""
        path = path.split("?", 1)[0].split("#", 1)[0].lstrip("/")
        if not path:
            return None
        cand = (root_r / path).resolve()
        try:
            cand.relative_to(root_r)          # never read outside the scanned directory
        except ValueError:
            return None
        if cand.is_file() and cand.stat().st_size <= MAX_FILE_BYTES:
            return cand.read_text("utf-8", errors="replace")
        return None

    return resolve


_ZW = set("\u200b\u200c\u200d\u2060\ufeff\u180e\u00ad")


def _searchable(raw: str) -> tuple[str, list[int]]:
    """``raw`` with zero-width chars removed and Unicode tag chars decoded, plus a map back to raw offsets."""
    chars, idx = [], []
    for i, ch in enumerate(raw):
        cp = ord(ch)
        if ch in _ZW:
            continue
        if 0xE0020 <= cp <= 0xE007E:
            ch = chr(cp - 0xE0000)
        elif 0xE0000 <= cp <= 0xE007F:
            continue
        chars.append(ch)
        idx.append(i)
    return "".join(chars), idx


def _locate(raw: str, f: Finding) -> int:
    """Best-effort 1-based line of a finding in the source file (1 if it cannot be placed)."""
    words = re.findall(r"\w{2,}", f.payload_excerpt.replace("[.]", "."))[:6]
    if not words:
        return 1
    text, idx = _searchable(raw)
    m = re.search(r"\W+(?:\w+\W+){0,2}?".join(map(re.escape, words[:4])), text, re.I)
    if m is None and len(words) >= 2:
        m = re.search(r"\W+".join(map(re.escape, words[:2])), text, re.I)
    if m is None:
        return 1
    return raw.count("\n", 0, idx[m.start()] if idx else 0) + 1


def iter_pages(root: Path, include: tuple[str, ...] = DEFAULT_INCLUDE,
               exclude: tuple[str, ...] = DEFAULT_EXCLUDE) -> list[Path]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in (".git", "node_modules"))
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            rel = p.relative_to(root).as_posix()
            if any(fnmatch.fnmatch(fn.lower(), pat) for pat in include) and not any(
                    fnmatch.fnmatch(rel, pat) for pat in exclude):
                out.append(p)
    return out


def scan_site(root: str | Path, *, use_css: bool = True, include: tuple[str, ...] = DEFAULT_INCLUDE,
              exclude: tuple[str, ...] = DEFAULT_EXCLUDE, classifier: Any = None,
              max_files: int | None = None) -> SiteScan:
    root = Path(root)
    if not root.exists():
        raise UsageError(f"{root} does not exist", "pass the directory your site builds into, e.g. _site or dist")
    if root.is_file():
        files, root = [root], root.parent
    else:
        files = iter_pages(root, include, exclude)
    if max_files is not None:
        files = files[:max_files]
    scan = SiteScan(root.resolve(), [])
    for p in files:
        rel = p.relative_to(root).as_posix()
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                scan.skipped.append((rel, f"larger than {MAX_FILE_BYTES} bytes"))
                continue
            raw = p.read_text("utf-8", errors="replace")
        except OSError as e:
            scan.skipped.append((rel, f"unreadable: {e.strerror or e}"))
            continue
        res = scan_html(raw, SITE_ORIGIN + rel, classifier=classifier,
                        css_resolver=_css_resolver(root, rel) if use_css else None)
        res.url = rel
        scan.files.append(FileResult(p.resolve(), rel, res, {f.payload_hash: _locate(raw, f) for f in res.findings}))
    return scan


def format_text(scan: SiteScan, show_all: bool = False) -> str:
    rows = []
    for fr, f in scan.findings():
        if not (f.flagged or show_all):
            continue
        mark = "FLAGGED" if f.flagged else "note"
        rows.append(f"{fr.rel}:{fr.line_of(f)}  {mark:<7} {f.severity:<12} {f.category:<26} "
                    f"[{f.location}{'/' + ','.join(f.techniques) if f.techniques else ''}] {f.payload_excerpt[:90]}")
    s = scan.summary()
    rows.append(f"\n{s['files_scanned']} file(s) scanned, {s['flagged']} flagged finding(s) in "
                f"{s['files_flagged']} file(s), {s['findings']} finding(s) in total"
                + (f", {s['files_skipped']} skipped" if s["files_skipped"] else ""))
    return "\n".join(rows).lstrip("\n")


def format_markdown(scan: SiteScan) -> str:
    s = scan.summary()
    out = ["### InjectionWatch scan-site", "",
           f"**{s['flagged']} flagged** finding(s) in {s['files_flagged']} of {s['files_scanned']} file(s).", ""]
    flagged = [(fr, f) for fr, f in scan.findings() if f.flagged]
    if flagged:
        out += ["| file | line | severity | category | where |", "|---|---|---|---|---|"]
        for fr, f in flagged[:50]:
            where = f.location + (f" ({', '.join(f.techniques)})" if f.techniques else "")
            out.append(f"| `{fr.rel}` | {fr.line_of(f)} | {f.severity} | {f.category} | {where} |")
        if len(flagged) > 50:
            out.append(f"\n…and {len(flagged) - 50} more (see the SARIF report).")
    return "\n".join(out) + "\n"
