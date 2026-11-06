"""Command line: ``injectionwatch <command> ...`` (or ``python -m injectionwatch``).

Errors are one line with a hint (``error: ... (hint: ...)``); ``--debug`` adds tracebacks and debug logs.
Exit codes: 0 ok, 1 runtime error or a ``--fail-on`` condition, 2 usage error, 130 interrupted.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import traceback
from pathlib import Path
from typing import Any

from .errors import InjectionWatchError, UsageError

CLASSIFIERS = ["heuristic", "local", "anthropic"]
log = logging.getLogger("injectionwatch.cli")


def _add_classifier(p: argparse.ArgumentParser) -> None:
    p.add_argument("--classifier", choices=CLASSIFIERS, default=None,
                   help="stage-2 classifier: heuristic (default), local = OpenAI-compatible endpoint such as Ollama "
                        "($INJECTIONWATCH_LLM_BASE_URL, $INJECTIONWATCH_LLM_MODEL), anthropic (needs API key)")
    p.add_argument("--llm", action="store_true", help=argparse.SUPPRESS)  # v0.1 alias for --classifier anthropic


def _classifier(a: argparse.Namespace) -> Any:
    """Build the classifier the user asked for, failing loudly (with a fix) instead of silently using the
    heuristic when an explicitly requested LLM classifier cannot work."""
    from .classify import AnthropicClassifier, make_classifier

    kind = "anthropic" if getattr(a, "llm", False) and not a.classifier else a.classifier
    if kind == "anthropic":
        if not os.environ.get("ANTHROPIC_API_KEY", "").strip() and not os.environ.get("ANTHROPIC_AUTH_TOKEN"):
            raise UsageError("--classifier anthropic needs ANTHROPIC_API_KEY",
                             "export ANTHROPIC_API_KEY=... (see `injectionwatch doctor`), or use --classifier "
                             "heuristic / local")
        return AnthropicClassifier()        # raises MissingDependency with the pip command if the SDK is absent
    return make_classifier(kind)


def _read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    p = Path(path)
    if not p.is_file():
        raise UsageError(f"{path}: no such file", "pass an HTML file path, or - to read stdin")
    return p.read_text("utf-8", errors="replace")


def _holds(path: str | None) -> Any:
    """``--hold FILE`` (else $INJECTIONWATCH_HOLD_FILE). A named file that is missing is an error, never a silent
    'no holds': publishing without the holds would leak the held sites."""
    from . import export

    if path is not None and not Path(path).is_file():
        raise UsageError(f"hold file {path} not found", "pass the private hold list kept outside the repo")
    env = os.environ.get(export.HOLD_ENV)
    if path is None and env and not Path(env).is_file():
        raise UsageError(f"${export.HOLD_ENV} points to {env}, which does not exist",
                         "fix the path or unset the variable")
    return export.load_holds(path)


def _add_bench(sub: Any) -> None:
    import importlib

    try:  # lane A's package; imported dynamically so the CLI works in installs without it
        add_parser = importlib.import_module(".bench.cli", __package__).add_parser
    except ImportError:
        b = sub.add_parser("bench", help="IW-Bench recall benchmark (not available in this install)")
        b.add_argument("rest", nargs=argparse.REMAINDER)
        b.set_defaults(_bench_missing=True)
        return
    add_parser(sub)


def build_parser() -> argparse.ArgumentParser:
    from .config import VERSION

    ap = argparse.ArgumentParser(prog="injectionwatch",
                                 description="Find and strip hidden prompt injections before AI agents read them.")
    ap.add_argument("--version", action="version", version=f"injectionwatch {VERSION}")
    ap.add_argument("--log-level", default=None, help="DEBUG, INFO, WARNING (default), ERROR; JSON lines on stderr")
    ap.add_argument("--debug", action="store_true", help="show tracebacks and debug logs")
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    dr = sub.add_parser("doctor", help="check this install and print what is missing and how to fix it")
    dr.add_argument("--network", action="store_true", help="also check Anthropic API, Ollama, Common Crawl")
    dr.add_argument("--json", action="store_true", help="machine-readable output")
    dr.add_argument("--require", nargs="*", default=[], metavar="COMPONENT",
                    help="exit 1 unless these are ready: api mcp render llm anthropic langchain extension ollama")
    dr.add_argument("--no-chromium", action="store_true", help="skip starting Playwright to locate Chromium")

    g = sub.add_parser("guard", help="fetch a URL safely (or sanitise a local HTML file) and print agent-safe text")
    g.add_argument("target", help="http(s) URL, a local .html file, or - for stdin")
    g.add_argument("--json", action="store_true", help="full JSON result (text, removed blocks, verdict)")
    g.add_argument("--allow-private", action="store_true",
                   help="allow private/loopback addresses (local testing only; off for agents)")
    g.add_argument("--max-bytes", type=int, default=5 * 1024 * 1024)
    g.add_argument("--timeout", type=float, default=15.0)
    g.add_argument("--user-agent", default=None, help="default identifies as InjectionWatch-Guard")
    g.add_argument("--fail-on-flagged", action="store_true", help="exit 1 if anything was flagged")

    ss = sub.add_parser("scan-site", help="scan a built static site directory (CI); optional SARIF output")
    ss.add_argument("path", help="directory (e.g. _site, dist, public) or a single HTML file")
    ss.add_argument("--sarif", default=None, metavar="OUT", help="write SARIF 2.1.0 to OUT")
    ss.add_argument("--fail-on", choices=["flagged", "any", "never"], default="flagged",
                    help="exit 1 when there are flagged findings (default), any finding, or never")
    ss.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    ss.add_argument("--json-out", default=None, metavar="FILE", help="also write the JSON result to FILE")
    ss.add_argument("--summary-md", default=None, metavar="FILE",
                    help="append a Markdown summary (e.g. $GITHUB_STEP_SUMMARY)")
    ss.add_argument("--all", action="store_true", help="also list unflagged findings in text output")
    ss.add_argument("--no-css", action="store_true", help="do not apply the site's own stylesheets")
    ss.add_argument("--include", nargs="*", default=None, metavar="GLOB", help="file globs (default *.html *.htm)")
    ss.add_argument("--exclude", nargs="*", default=None, metavar="GLOB", help="relative-path globs to skip")
    ss.add_argument("--uri-base", default=None,
                    help="make SARIF paths relative to this dir (default: current dir, i.e. the repo root in CI)")
    _add_classifier(ss)

    _add_bench(sub)

    s = sub.add_parser("scan", help="scan a local HTML file (or - for stdin)")
    s.add_argument("path")
    s.add_argument("--rendered", action="store_true", help="also run the Playwright/Chromium rendered pass")
    s.add_argument("--css", nargs="*", default=[], help="local stylesheet files to apply (external CSS)")
    s.add_argument("--llm-recall", action="store_true", help="send gated near-misses to the LLM classifier")
    _add_classifier(s)

    w = sub.add_parser("scan-warc", help="stream-scan WARC files (e.g. Common Crawl) into the DB / JSONL")
    w.add_argument("warcs", nargs="+", help="*.warc.gz / *.warc files (order matters for resume)")
    w.add_argument("--db", default="injectionwatch.db")
    w.add_argument("--no-db", action="store_true", help="JSONL only")
    w.add_argument("--jsonl", default=None, help="append one JSON line per finding")
    w.add_argument("--workers", type=int, default=None, help="worker processes (default: CPU count; 0 = inline)")
    w.add_argument("--max-bytes", type=int, default=2_000_000, help="per-record payload cap")
    w.add_argument("--checkpoint-every", type=int, default=500, help="records between resume checkpoints")
    w.add_argument("--limit", type=int, default=None, help="stop after N records (re-run to resume)")
    w.add_argument("--no-record-urls", action="store_true", help="don't log clean captures (smaller DB)")
    w.add_argument("--stats-out", default=None)
    w.add_argument("--classifier", choices=CLASSIFIERS, default="heuristic")

    c = sub.add_parser("crawl", help="politely crawl a domain list into the DB")
    c.add_argument("domains", help="Tranco-style CSV rank,domain (or one domain/URL per line)")
    c.add_argument("--db", default="injectionwatch.db")
    c.add_argument("--limit", type=int, default=200)
    c.add_argument("--delay", type=float, default=5.0, help="min seconds between requests to the same host")
    c.add_argument("--workers", type=int, default=4)
    c.add_argument("--rendered", action="store_true")
    c.add_argument("--json-summary", default=None)
    _add_classifier(c)

    k = sub.add_parser("cloak", help="check one URL for AI-agent cloaking (UA-based)")
    k.add_argument("url")
    k.add_argument("--agents", nargs="*", default=None)
    k.add_argument("--delay", type=float, default=2.0)

    e = sub.add_parser("export", help="export the feed")
    e.add_argument("--db", default="injectionwatch.db")
    e.add_argument("--format", choices=["json", "csv", "stix"], default="json")
    e.add_argument("--out", default="-")
    e.add_argument("--hold", default=None, metavar="FILE",
                   help="private-disclosure hold list; held sites are exported redacted (default: "
                        "$INJECTIONWATCH_HOLD_FILE)")

    pb = sub.add_parser("publish", help="build the static GitHub Pages site (dashboard + feed + lookup shards)")
    pb.add_argument("--db", default="injectionwatch.db")
    pb.add_argument("--out", default="site")
    pb.add_argument("--note", default="", help="data note shown on the dashboard")
    pb.add_argument("--severities", default=None,
                    help="comma-separated severities to publish as entries (default: all but ai_optout; "
                         "e.g. manipulative,malicious)")
    pb.add_argument("--reviewed-only", action="store_true", help="publish only entries reviewed as true_positive")
    pb.add_argument("--hold", default=None, metavar="FILE",
                    help="private-disclosure hold list; held sites are published redacted (default: "
                         "$INJECTIONWATCH_HOLD_FILE)")

    rv = sub.add_parser("review", help="apply human labels (JSONL: url, payload_hash, label, severity, note)")
    rv.add_argument("labels")
    rv.add_argument("--db", default="injectionwatch.db")

    m = sub.add_parser("merge-feed", help="merge a previously published feed.json into the DB")
    m.add_argument("feed_json")
    m.add_argument("--db", default="injectionwatch.db")

    r = sub.add_parser("report", help="generate the State of Injections markdown report")
    r.add_argument("--db", default="injectionwatch.db")
    r.add_argument("--out", default="reports/state_of_injections.md")
    r.add_argument("--note", default="")

    v = sub.add_parser("serve", help="run the HTTP API (uvicorn)")
    v.add_argument("--db", default="injectionwatch.db")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8000)
    v.add_argument("--rate-limit", type=int, default=None)

    ev = sub.add_parser("eval", help="precision/recall on the fixture corpora")
    ev.add_argument("--fixtures", nargs="*", default=None, help="fixture dirs (default: all corpora)")
    ev.add_argument("--modes", nargs="*", default=["static"], choices=["static", "static_css", "rendered"])
    ev.add_argument("--rendered", action="store_true", help="shorthand for --modes static static_css rendered")
    ev.add_argument("--json-out", default=None)
    ev.add_argument("--details", action="store_true", help="print per-technique tables and errors")
    _add_classifier(ev)

    st = sub.add_parser("status", help="appeal/takedown handling: set an entry's status")
    st.add_argument("entry_id", type=int)
    st.add_argument("status", choices=["active", "removed", "disputed", "suppressed"])
    st.add_argument("--note", default="")
    st.add_argument("--db", default="injectionwatch.db")

    sub.add_parser("agents", help="list the AI-agent UA catalog")

    vs = sub.add_parser("verify-submissions", help="re-crawl extension reports; verify by payload hash")
    vs.add_argument("--db", default="injectionwatch.db")
    vs.add_argument("--delay", type=float, default=5.0)
    return ap


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    from .logging_setup import configure

    configure("DEBUG" if a.debug else (a.log_level or "WARNING"))
    try:
        return _dispatch(a)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except InjectionWatchError as e:
        if a.debug:
            traceback.print_exc()
        print(f"error: {e.one_line()}", file=sys.stderr)
        return e.exit_code
    except BrokenPipeError:  # e.g. `injectionwatch scan-site . | head`
        return 0
    except Exception as e:
        if a.debug:
            traceback.print_exc()
        log.debug("unhandled error", exc_info=True)
        msg = str(e).splitlines()[0][:200] if str(e) else ""
        print(f"error: {type(e).__name__}{': ' + msg if msg else ''} (hint: re-run with --debug for the "
              "traceback; report bugs at https://github.com/DevPatel3547/injection-watch/issues)", file=sys.stderr)
        return 1


def _dispatch(a: argparse.Namespace) -> int:
    if a.cmd == "doctor":
        from . import doctor

        checks = doctor.run_checks(network=a.network, probe_chromium=not a.no_chromium)
        code = doctor.exit_code(checks, a.require)
        print(doctor.to_json(checks, code) if a.json else
              doctor.format_table(checks, color=sys.stdout.isatty() and not os.environ.get("NO_COLOR")))
        return code
    if a.cmd == "guard":
        return _guard(a)
    if a.cmd == "scan-site":
        return _scan_site(a)
    if a.cmd == "bench":
        if getattr(a, "_bench_missing", False):
            raise UsageError("the bench module is not available in this install",
                             "install from a source checkout: pip install -e '.[dev]'")
        import importlib

        return int(importlib.import_module(".bench.cli", __package__).run(a))
    if a.cmd == "scan":
        from .detector import scan_html

        html = _read_input(a.path)
        sheets = {Path(p).name: Path(p).read_text("utf-8", errors="replace") for p in a.css}

        def resolver(url: str) -> str | None:
            return sheets.get(url.rsplit("/", 1)[-1].split("?")[0])

        rc = None
        if a.rendered:
            from .render import Renderer

            with Renderer() as rd:
                rc = rd.candidates_from_html(html, css_resolver=resolver if sheets else None)
        res = scan_html(html, a.path, None, _classifier(a), rc, llm_recall_mode=a.llm_recall,
                        css_resolver=resolver if sheets else None)
        print(json.dumps(res.to_dict(), indent=2, ensure_ascii=False))
    elif a.cmd == "scan-warc":
        from .db import DB
        from .warc import scan_warcs

        db = None if a.no_db else DB(a.db)
        stats = scan_warcs(a.warcs, db, a.jsonl, workers=a.workers, max_bytes=a.max_bytes,
                           checkpoint_every=a.checkpoint_every, record_urls=not a.no_record_urls, limit=a.limit,
                           classifier_kind=a.classifier, log=lambda m: print(m, file=sys.stderr))
        out = json.dumps(stats.to_dict(), indent=2)
        print(out)
        if a.stats_out:
            Path(a.stats_out).write_text(out, encoding="utf-8")
    elif a.cmd == "crawl":
        from .crawler import PoliteFetcher, crawl, read_domain_list
        from .db import DB

        urls = read_domain_list(a.domains, a.limit)
        summ = crawl(urls, DB(a.db), PoliteFetcher(min_delay=a.delay), _classifier(a), a.workers, a.rendered)
        print(json.dumps(summ.__dict__, indent=2))
        if a.json_summary:
            Path(a.json_summary).write_text(json.dumps(summ.__dict__, indent=2))
    elif a.cmd == "cloak":
        from .cloaking import check_cloaking
        from .config import fetchable_agents
        from .crawler import PoliteFetcher

        rep = check_cloaking(a.url, PoliteFetcher(min_delay=a.delay), fetchable_agents(a.agents))
        print(json.dumps(rep.to_dict(), indent=2))
    elif a.cmd == "export":
        from . import export
        from .db import DB

        entries = export.apply_holds(DB(a.db).feed(limit=10_000_000), _holds(a.hold))
        data = {"json": export.to_json, "csv": export.to_csv, "stix": export.to_stix}[a.format](entries)
        if a.out == "-":
            sys.stdout.write(data)
        else:
            Path(a.out).write_text(data, encoding="utf-8")
    elif a.cmd == "publish":
        from .db import DB
        from .publish import build_site

        sev = [x.strip() for x in a.severities.split(",") if x.strip()] if a.severities else None
        print(json.dumps(build_site(DB(a.db), a.out, data_note=a.note, severities=sev,
                                    reviewed_only=a.reviewed_only, holds=_holds(a.hold)), indent=2))
    elif a.cmd == "review":
        from .classify import SEVERITIES
        from .db import DB

        db = DB(a.db)
        n = missing = 0
        for line in Path(a.labels).read_text("utf-8").splitlines():
            if not line.strip():
                continue
            lab = json.loads(line)
            tp = lab["label"] in ("true_injection", "true_positive")
            sev = lab.get("severity") if lab.get("severity") in SEVERITIES else None
            changed = db.apply_review(lab["url"], lab["payload_hash"], "true_positive" if tp else "false_positive",
                                      sev if tp else "benign", lab.get("note", ""))
            n += changed
            missing += int(changed == 0)
        print(json.dumps({"reviewed": n, "unmatched": missing}))
    elif a.cmd == "merge-feed":
        from .db import DB

        data = json.loads(Path(a.feed_json).read_text("utf-8"))
        print(f"merged {DB(a.db).import_entries(data.get('entries', []))} entries")
    elif a.cmd == "report":
        from .db import DB
        from .report import generate_report

        md = generate_report(DB(a.db), data_note=a.note)
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(md, encoding="utf-8")
        print(f"wrote {a.out}")
    elif a.cmd == "serve":  # pragma: no cover - blocking server
        import uvicorn

        from .api import Settings, create_app

        overrides: dict[str, Any] = {"db_path": a.db}
        if a.rate_limit is not None:
            overrides["rate_limit"] = a.rate_limit
        uvicorn.run(create_app(settings=Settings.from_env(**overrides)), host=a.host, port=a.port,
                    log_config=None, proxy_headers=False)
    elif a.cmd == "eval":
        from .evaluate import CORPORA, format_table, run_matrix, summary_table

        corpora = ({Path(d).name: Path(d) for d in a.fixtures} if a.fixtures
                   else {k: v for k, v in CORPORA.items() if (v / "labels.json").exists()})
        modes = ("static", "static_css", "rendered") if a.rendered else tuple(a.modes)
        matrix = run_matrix(corpora, modes, classifier=_classifier(a) if (a.classifier or a.llm) else None)
        print(summary_table(matrix))
        if a.details:
            for corpus, by_mode in matrix.items():
                for mode, res in by_mode.items():
                    print(f"\n== {corpus} ({mode})\n{format_table(res)}\n\n{format_table(res, 'per_lang')}")
        if a.json_out:
            Path(a.json_out).parent.mkdir(parents=True, exist_ok=True)
            Path(a.json_out).write_text(json.dumps(matrix, indent=1, ensure_ascii=False, default=str), "utf-8")
    elif a.cmd == "status":
        from .db import DB

        ok = DB(a.db).set_status(a.entry_id, a.status, a.note)
        print("updated" if ok else "no such entry")
    elif a.cmd == "verify-submissions":
        from .crawler import PoliteFetcher, verify_submissions
        from .db import DB

        print(json.dumps(verify_submissions(DB(a.db), PoliteFetcher(min_delay=a.delay)), indent=2))
    elif a.cmd == "agents":
        from .config import AGENT_UAS

        for ag in AGENT_UAS:
            print(f"{ag.name:<20} {ag.operator:<12} {ag.kind:<18} ua={ag.ua_status:<11} verify={ag.verification}")
    return 0


def _guard(a: argparse.Namespace) -> int:
    from . import guard
    from .safe_fetch import FetchPolicy

    t = a.target
    if t == "-" or (not t.lower().startswith(("http://", "https://")) and Path(t).exists()):
        page = guard.sanitize(_read_input(t), "" if t == "-" else t)
    elif "://" not in t and not Path(t).exists() and ("/" in t or t.endswith((".html", ".htm"))):
        raise UsageError(f"{t}: no such file", "pass an existing file, - for stdin, or a full http(s):// URL")
    else:
        url = t if "://" in t else "https://" + t
        page = guard.fetch(url, policy=FetchPolicy(allow_private=a.allow_private, max_bytes=a.max_bytes,
                                                   timeout=a.timeout, user_agent=a.user_agent))
    if a.json:
        print(json.dumps(page.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(page.text)
        cats = sorted({str(r.get("category")) for r in page.removed if r.get("category")})
        print(f"\n[injectionwatch] verdict={page.verdict} removed={len(page.removed)}"
              f"{' (' + ', '.join(cats) + ')' if cats else ''} hidden_blocks_dropped={page.hidden_dropped}",
              file=sys.stderr)
    return 1 if a.fail_on_flagged and page.flagged else 0


def _scan_site(a: argparse.Namespace) -> int:
    from .sitescan import DEFAULT_EXCLUDE, DEFAULT_INCLUDE, format_markdown, format_text, scan_site

    scan = scan_site(a.path, use_css=not a.no_css, include=tuple(a.include or DEFAULT_INCLUDE),
                     exclude=tuple(a.exclude if a.exclude is not None else DEFAULT_EXCLUDE),
                     classifier=_classifier(a) if a.classifier else None)
    if not scan.files and not scan.skipped:
        print(f"warning: no HTML files found under {a.path}", file=sys.stderr)
    if a.sarif:
        from .sarif import write_sarif

        write_sarif(scan, a.sarif, uri_base=Path(a.uri_base) if a.uri_base else None)
    as_json = json.dumps({"summary": scan.summary(),
                          "files": [{"path": fr.rel, **fr.result.to_dict(),
                                     "lines": {f.payload_hash: fr.line_of(f) for f in fr.result.findings}}
                                    for fr in scan.files if fr.result.findings]}, indent=2, ensure_ascii=False)
    if a.json_out:
        Path(a.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.json_out).write_text(as_json + "\n", encoding="utf-8")
    if a.format == "json":
        print(as_json)
    elif a.format == "markdown":
        print(format_markdown(scan))
    else:
        print(format_text(scan, show_all=a.all))
    if a.summary_md:
        with open(a.summary_md, "a", encoding="utf-8") as fh:
            fh.write(format_markdown(scan))
    if a.fail_on == "flagged" and scan.n_flagged:
        return 1
    if a.fail_on == "any" and scan.n_findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
