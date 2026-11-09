"""Pinned public sources for IW-Bench and the cache that holds them.

Nothing here is vendored into the repository. ``fetch_all`` makes a sparse, depth-1 git checkout of
each source at a **pinned commit SHA** into the cache directory, verifies the checked-out commit and
records a SHA-256 of every file the bench reads (``cache/bench/<id>/.iwbench.json``). A later run
refuses a checkout whose commit or file hashes changed.

Cache location: ``$INJECTIONWATCH_CACHE/bench`` if set, else ``~/.cache/injectionwatch/bench``.

Licences were checked by hand at the pinned commit. Every source below allows redistribution of
derived results (the bench publishes only counts, rates and opaque item ids, never source text).
Tensor Trust (HumanCompatibleAI/tensor-trust-data) was considered and left out: the repository
carries no licence file.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

GITHUB = "https://github.com/"


@dataclass(frozen=True)
class Source:
    id: str
    repo: str
    commit: str
    license: str
    role: str                 # payload | carrier | negative | mixed
    sparse: tuple[str, ...]   # git sparse-checkout (non-cone) patterns
    cite: str = ""
    notes: str = ""

    @property
    def url(self) -> str:
        return GITHUB + self.repo


SOURCES: tuple[Source, ...] = (
    Source("injecagent", "uiuc-kang-lab/InjecAgent", "f19c9f2c79a41046eb13c03c51a24c567a8ffa07", "MIT",
           "payload", ("/data/attacker_cases_dh.jsonl", "/data/attacker_cases_ds.jsonl", "/LICENCE", "/README.md"),
           "Zhan et al., InjecAgent (ACL Findings 2024)",
           "attacker instructions (62); 'enhanced' adds the paper's IMPORTANT!!! override prefix"),
    Source("bipia", "microsoft/BIPIA", "a004b69ec0dd446e0afd461d98cb5e96e120a5d0", "MIT", "mixed",
           ("/benchmark/text_attack_train.json", "/benchmark/text_attack_test.json",
            "/benchmark/code_attack_train.json", "/benchmark/code_attack_test.json",
            "/benchmark/email/", "/benchmark/table/", "/LICENSE", "/README.md"),
           "Yi et al., Benchmarking and Defending Against Indirect Prompt Injection Attacks (BIPIA, 2023)",
           "text and code attacks keep BIPIA's own train/test split; email and table contexts are benign negatives"),
    Source("agentdojo", "ethz-spylab/agentdojo", "089ed468cf3ed0322acc66b0211f26d9d90dbf60", "MIT", "payload",
           ("/src/agentdojo/default_suites/v1/", "/src/agentdojo/attacks/", "/LICENSE", "/README.md"),
           "Debenedetti et al., AgentDojo (NeurIPS 2024 D&B)",
           "v1 injection-task goals, bare and wrapped in the paper's attack templates"),
    Source("opi", "liu00222/Open-Prompt-Injection", "fbed5cca347488f88363790ae3ae97c56116da6a", "MIT", "payload",
           ("/data/system_prompts/", "/OpenPromptInjection/attackers/", "/LICENSE", "/README.md"),
           "Liu et al., Formalizing and Benchmarking Prompt Injection Attacks and Defenses (USENIX Security 2024)",
           "injected-task instructions under the paper's attacker templates; the HF-hosted task data is omitted"),
    Source("greshake", "greshake/llm-security", "c312325bee5f16d8f6524bd6f41e1510c5623a1e", "MIT", "payload",
           ("/scenarios/gpt4/", "/scenarios/gpt3langchain/", "/LICENSE", "/README.md"),
           "Greshake et al., Not what you've signed up for (AISec 2023)",
           "the injected web content of each demo scenario"),
    Source("pint", "lakeraai/pint-benchmark", "0efab3f463eae9c823130d8faffb71b2e7c06e63", "MIT", "mixed",
           ("/benchmark/data/example-dataset.yaml", "/LICENSE", "/README.md"),
           "Lakera PINT benchmark (public example file only, not the private PINT set)",
           "the public example items: a few injections and benign hard negatives"),
    Source("owasp_llm", "OWASP/www-project-top-10-for-large-language-model-applications",
           "99f4395589bdbd120ae961f9cd179e79d7f9b27f", "CC-BY-SA-4.0", "negative",
           ("/2_0_vulns/LLM0*.md", "/2_0_vulns/LLM1*.md", "/2_0_vulns/translations/*/LLM01*", "/LICENSE.md"),
           "OWASP Top 10 for LLM Applications 2025",
           "pages that discuss prompt injection (hard negatives), English plus 9 translations of LLM01"),
    Source("readability", "mozilla/readability", "ab4027a8b37669745016869a37a504727992b2ba", "Apache-2.0",
           "carrier", ("/test/test-pages/*/source.html", "/LICENSE.md"),
           "Mozilla Readability test pages (saved real-world articles)", "dev-split carriers"),
    Source("scrapinghub", "scrapinghub/article-extraction-benchmark", "4a3bc979f76c0df73cb95fe272e2fc1b96f9f010",
           "MIT", "carrier", ("/html/", "/LICENSE"),
           "Zyte (Scrapinghub) article extraction benchmark (181 real article pages)", "test-split carriers"),
)
SOURCE_BY_ID = {s.id: s for s in SOURCES}


def cache_root() -> Path:
    base = os.environ.get("INJECTIONWATCH_CACHE")
    root = Path(base).expanduser() if base else Path.home() / ".cache" / "injectionwatch"
    return root / "bench"


def source_dir(source_id: str, root: Path | None = None) -> Path:
    return (root or cache_root()) / source_id


class SourceError(RuntimeError):
    pass


def _git(args: list[str], cwd: Path, timeout: int = 600) -> str:
    proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise SourceError(f"git {' '.join(args[:2])} failed in {cwd}: {proc.stderr.strip()[:300]}")
    return proc.stdout


def _file_hashes(d: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in sorted(d.rglob("*")):
        if p.is_file() and ".git" not in p.relative_to(d).parts and p.name != ".iwbench.json":
            out[p.relative_to(d).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def is_ready(src: Source, root: Path | None = None) -> bool:
    meta = source_dir(src.id, root) / ".iwbench.json"
    if not meta.exists():
        return False
    try:
        m = json.loads(meta.read_text("utf-8"))
    except ValueError:
        return False
    return bool(m.get("commit") == src.commit and m.get("files"))


def verify(src: Source, root: Path | None = None) -> None:
    """Raise SourceError unless the cached checkout matches the pinned commit and recorded hashes."""
    d = source_dir(src.id, root)
    meta_p = d / ".iwbench.json"
    if not meta_p.exists():
        raise SourceError(f"{src.id}: not in the cache; run `injectionwatch bench data`")
    m = json.loads(meta_p.read_text("utf-8"))
    if m.get("commit") != src.commit:
        raise SourceError(f"{src.id}: cached commit {m.get('commit')} != pinned {src.commit}; re-run bench data")
    now = _file_hashes(d)
    if now != m.get("files"):
        changed = sorted(set(now.items()) ^ set(m.get("files", {}).items()))[:3]
        raise SourceError(f"{src.id}: cached files changed ({changed}); re-run `injectionwatch bench data --force`")


def fetch(src: Source, root: Path | None = None, force: bool = False,
          log: Callable[[str], None] = print) -> Path:
    """Sparse depth-1 checkout of ``src`` at its pinned commit (idempotent)."""
    d = source_dir(src.id, root)
    if is_ready(src, root) and not force:
        verify(src, root)
        log(f"  {src.id:<12} cached  {src.commit[:12]}")
        return d
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    try:
        _git(["init", "-q"], d)
        _git(["remote", "add", "origin", src.url], d)
        _git(["config", "remote.origin.promisor", "true"], d)
        _git(["config", "remote.origin.partialclonefilter", "blob:none"], d)
        _git(["sparse-checkout", "set", "--no-cone", *src.sparse], d)
        _git(["fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", src.commit], d)
        _git(["checkout", "-q", "FETCH_HEAD"], d)
        head = _git(["rev-parse", "HEAD"], d).strip()
        if head != src.commit:
            raise SourceError(f"{src.id}: checked out {head}, expected {src.commit}")
    except (SourceError, subprocess.TimeoutExpired, OSError) as e:
        shutil.rmtree(d, ignore_errors=True)
        raise SourceError(f"{src.id}: fetch from {src.url} failed: {e}") from e
    files = _file_hashes(d)
    if not files:
        shutil.rmtree(d, ignore_errors=True)
        raise SourceError(f"{src.id}: sparse checkout is empty (patterns {src.sparse})")
    meta = {"id": src.id, "repo": src.repo, "commit": src.commit, "license": src.license, "files": files}
    (d / ".iwbench.json").write_text(json.dumps(meta, indent=1, sort_keys=True), "utf-8")
    shutil.rmtree(d / ".git", ignore_errors=True)  # only the verified files are needed
    log(f"  {src.id:<12} fetched {src.commit[:12]}  {len(files)} files  ({src.license})")
    return d


def fetch_all(ids: list[str] | None = None, root: Path | None = None, force: bool = False,
              log: Callable[[str], None] = print) -> list[Path]:
    wanted = [SOURCE_BY_ID[i] for i in ids] if ids else list(SOURCES)
    return [fetch(s, root, force, log) for s in wanted]


@dataclass
class SourceStatus:
    id: str
    ready: bool
    error: str = ""
    extra: dict[str, str] = field(default_factory=dict)


def status(root: Path | None = None) -> list[SourceStatus]:
    out = []
    for s in SOURCES:
        try:
            verify(s, root)
            out.append(SourceStatus(s.id, True))
        except SourceError as e:
            out.append(SourceStatus(s.id, False, str(e)))
    return out
