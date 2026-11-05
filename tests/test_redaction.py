"""Redaction regression tests for the committed real-web data and the published site.

The affected sites of the real-web sample are held back (private disclosure). Replacing the host with
``redacted-site-N.example`` is not enough on its own: a Common Crawl WARC name + offset, a capture
timestamp, a unique URL path or a DOM path is enough to find the original record again. These checks are
structural, so they keep working on any future data without needing a list of the real hosts.
"""
from __future__ import annotations

import csv
import io
import json
import re
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
DATA_DIRS = ("reports", "site")
TEXT_SUFFIXES = {".json", ".jsonl", ".csv", ".md", ".txt", ".html", ".js", ".py", ".yml", ".yaml", ".toml", ".cff"}

WARC_NAME = re.compile(r"CC-MAIN-\d{14}-\d{14}-\d{5}\.warc(?:\.gz)?|crawl-data/CC-MAIN-\d{4}-\d{2}/segments/")
REDACTED_URL = re.compile(r"redacted-site-\d+(?:\.|\[\.\])example(?P<rest>[^\s\"'<>\]),|]*)")
ALLOWED_REST = re.compile(r"(?:/redacted-path-\d+)?/?")
LOCATOR_KEYS = {"warc", "offset", "warc_offset", "warc_record_id", "warc_filename", "warc_path"}
CAPTURE_TS = re.compile(r"\d{4}-\d{2}-\d{2}T(\d{2}:\d{2}:\d{2})")
OPAQUE_PAGE_ID = re.compile(r"(?:v01-)?p\d{4}")
REDACTED_HOST = re.compile(r"redacted-site-\d+\.example")


def _tracked_files() -> list[Path]:
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
        files = [ROOT / p for p in out.decode("utf-8").split("\0") if p]
    except (OSError, subprocess.CalledProcessError):  # not a git checkout (sdist, Docker image)
        files = [p for p in ROOT.rglob("*") if ".git" not in p.parts]
    return [p for p in files if p.is_file() and p.suffix in TEXT_SUFFIXES]


FILES = _tracked_files()
DATA_FILES = [p for p in FILES if p.relative_to(ROOT).parts[0] in DATA_DIRS and p.suffix in {".json", ".jsonl", ".csv"}]


def _rel(p: Path) -> str:
    return p.relative_to(ROOT).as_posix()


def _records(p: Path) -> Iterator[Any]:
    text = p.read_text("utf-8")
    if p.suffix == ".jsonl":
        for line in text.splitlines():
            if line.strip():
                yield json.loads(line)
    elif p.suffix == ".json":
        d = json.loads(text)
        # yield the top level and every list element / shard entry as its own record
        yield d
        if isinstance(d, dict):
            for v in d.values():
                if isinstance(v, list):
                    yield from v
                elif isinstance(v, dict):
                    for vv in v.values():
                        if isinstance(vv, list):
                            yield from vv
    else:
        yield from csv.DictReader(io.StringIO(text))


def _walk(o: Any, path: str = "") -> Iterator[tuple[str, Any]]:
    if isinstance(o, dict):
        for k, v in o.items():
            yield f"{path}.{k}", v
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from _walk(v, f"{path}[{i}]")


def test_inventory_is_not_empty() -> None:
    assert any(_rel(p).startswith("reports/realweb/") for p in DATA_FILES)
    assert any(_rel(p).startswith("site/") for p in DATA_FILES)


@pytest.mark.parametrize("path", FILES, ids=_rel)
def test_no_common_crawl_warc_locations(path: Path) -> None:
    m = WARC_NAME.search(path.read_text("utf-8", errors="replace"))
    assert m is None, f"{_rel(path)} names a Common Crawl WARC file ({m.group(0) if m else ''})"


@pytest.mark.parametrize("path", FILES, ids=_rel)
def test_redacted_urls_have_no_real_path(path: Path) -> None:
    for m in REDACTED_URL.finditer(path.read_text("utf-8", errors="replace")):
        rest = m.group("rest")
        assert ALLOWED_REST.fullmatch(rest), f"{_rel(path)}: redacted host keeps a real path/query: {rest[:12]}..."


@pytest.mark.parametrize("path", DATA_FILES, ids=_rel)
def test_data_files_carry_no_record_locators(path: Path) -> None:
    for rec in _records(path):
        for key, value in _walk(rec):
            name = key.rsplit(".", 1)[-1]
            assert name not in LOCATOR_KEYS, f"{_rel(path)}: field {key} locates a WARC record"
            if name == "page_id" and isinstance(value, str):
                assert OPAQUE_PAGE_ID.fullmatch(value), f"{_rel(path)}: page_id {value!r} is not opaque"


@pytest.mark.parametrize("path", DATA_FILES, ids=_rel)
def test_redacted_records_are_reduced(path: Path) -> None:
    for rec in _records(path):
        if not isinstance(rec, dict) or "redacted-site-" not in json.dumps(rec, ensure_ascii=False):
            continue
        if path.name in {"meta.json", "label_stats.json", "scan_stats.json"} and "entries" not in rec:
            continue  # aggregate files: covered by the URL and locator checks
        for key, value in _walk(rec):
            if not isinstance(value, str):
                continue
            name = key.rsplit(".", 1)[-1]
            for ts in CAPTURE_TS.finditer(value):
                if name not in {"created", "modified", "generated_at"}:
                    assert ts.group(1) == "00:00:00", f"{_rel(path)}: {key} keeps an exact capture time"
            if name == "path":
                assert re.fullmatch(r"[a-z][a-z0-9-]*|<!-- -->", value), f"{_rel(path)}: DOM path {value!r} not reduced"
            if name in {"payload_excerpt", "hidden_text", "x_injectionwatch_payload_excerpt"} and len(value) > 40:
                assert "[passage omitted" in value, f"{_rel(path)}: {key} keeps the full payload of a redacted site"


def test_reviewed_true_positives_stay_redacted() -> None:
    """While the disclosure hold is in force, every reviewed TP and every published entry is redacted.
    Lifting the hold for a site is a deliberate decision: update this test in the same commit."""
    rw = ROOT / "reports/realweb"
    for labels in rw.rglob("labels.jsonl"):
        for rec in _records(labels):
            if rec.get("label") == "true_injection":
                assert REDACTED_HOST.search(rec["url"]), f"{_rel(labels)}: TP with an unredacted host (hit {rec.get('hit')})"
    feed = json.loads((ROOT / "site/feed.json").read_text("utf-8"))
    for e in feed["entries"]:
        assert REDACTED_HOST.fullmatch(e["host"]), "site/feed.json publishes an unredacted host"


EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
PHONE = re.compile(r"(?<![\w.])\+?\d[\d \-().]{7,}\d(?![\w])")
TEXT_KEYS = {"hidden_text", "payload_excerpt", "reason", "note", "reasons", "x_injectionwatch_payload_excerpt"}


@pytest.mark.parametrize("path", DATA_FILES, ids=_rel)
def test_page_text_carries_no_contact_details(path: Path) -> None:
    """Hidden text quoted from third-party pages must not republish e-mail addresses or phone numbers."""
    for rec in _records(path):
        for key, value in _walk(rec):
            if key.rsplit(".", 1)[-1].split("[")[0] not in TEXT_KEYS:
                continue
            for s in value if isinstance(value, list) else [value]:
                if not isinstance(s, str):
                    continue
                for m in EMAIL.finditer(s):
                    assert m.group(0).endswith(".example"), f"{_rel(path)}: {key} quotes an e-mail address"
                for m in PHONE.finditer(s):
                    digits = re.sub(r"\D", "", m.group(0))
                    is_date = re.match(r"\d{4}-\d{2}-\d{2}", m.group(0))
                    assert is_date or len(digits) < 9, f"{_rel(path)}: {key} quotes a phone number"
