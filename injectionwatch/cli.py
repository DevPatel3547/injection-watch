"""Command line: ``injectionwatch <command> ...`` (or ``python -m injectionwatch``)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

CLASSIFIERS = ["heuristic", "local", "anthropic"]


def _add_classifier(p: argparse.ArgumentParser) -> None:
    p.add_argument("--classifier", choices=CLASSIFIERS, default=None,
                   help="stage-2 classifier: heuristic (default), local = OpenAI-compatible endpoint such as Ollama "
                        "($INJECTIONWATCH_LLM_BASE_URL, $INJECTIONWATCH_LLM_MODEL), anthropic (needs API key)")
    p.add_argument("--llm", action="store_true", help=argparse.SUPPRESS)  # v0.1 alias for --classifier anthropic


def _classifier(a: argparse.Namespace) -> Any:
    from .classify import make_classifier

    return make_classifier("anthropic" if getattr(a, "llm", False) and not a.classifier else a.classifier)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="injectionwatch", description="Indirect prompt injection feed tooling")
    ap.add_argument("--log-level", default="WARNING")
    sub = ap.add_subparsers(dest="cmd", required=True)

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

    pb = sub.add_parser("publish", help="build the static GitHub Pages site (dashboard + feed + lookup shards)")
    pb.add_argument("--db", default="injectionwatch.db")
    pb.add_argument("--out", default="site")
    pb.add_argument("--note", default="", help="data note shown on the dashboard")
    pb.add_argument("--severities", default=None,
                    help="comma-separated severities to publish as entries (default: all but ai_optout; "
                         "e.g. manipulative,malicious)")
    pb.add_argument("--reviewed-only", action="store_true", help="publish only entries reviewed as true_positive")

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

    configure(a.log_level)

    if a.cmd == "scan":
        from .detector import scan_html

        html = sys.stdin.read() if a.path == "-" else Path(a.path).read_text("utf-8", errors="replace")
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

        entries = DB(a.db).feed(limit=10_000_000)
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
                                    reviewed_only=a.reviewed_only), indent=2))
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


if __name__ == "__main__":
    sys.exit(main())
