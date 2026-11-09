"""``injectionwatch bench ...``: fetch the public sources, run IW-Bench, print or compare results.

Standalone entry point: ``python -m injectionwatch.bench.cli --help``.

    bench data [--force] [--only ID ...]      sparse git checkouts at pinned SHAs into the cache
    bench status                              which sources are cached and verified
    bench run [--mode M] [--split S] [--quick] [--jobs N] [--ml on|off|default] [--out DIR] [--name NAME]
    bench show FILE.json                      Markdown summary of a result file
    bench compare A.json B.json               side-by-side headline numbers
"""
from __future__ import annotations

import argparse
import inspect
import json
import sys
import time
from pathlib import Path
from typing import Any

DEFAULT_OUT = Path("build") / "bench"


def add_parser(subparsers: Any) -> None:
    p = subparsers.add_parser("bench", help="IW-Bench recall benchmark built from public injection datasets",
                              description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    _configure(p)


def _configure(p: argparse.ArgumentParser) -> None:
    sub = p.add_subparsers(dest="bench_cmd", required=True)
    d = sub.add_parser("data", help="fetch pinned dataset/carrier sources into the cache")
    d.add_argument("--force", action="store_true", help="re-fetch even if cached")
    d.add_argument("--only", nargs="*", metavar="ID", help="only these source ids")
    sub.add_parser("status", help="show cached sources")
    r = sub.add_parser("run", help="run the benchmark")
    r.add_argument("--mode", default="static", choices=["static", "static_css", "rendered", "all"])
    r.add_argument("--split", default="test", choices=["dev", "test", "all"],
                   help="dev while tuning; test only for reporting (default: test)")
    r.add_argument("--quick", action="store_true", help="~1/10 subsample on small carriers (CI smoke run)")
    r.add_argument("--per-payload", type=int, default=3, help="techniques per payload (default 3)")
    r.add_argument("--per-benign", type=int, default=2, help="techniques per benign text (default 2)")
    r.add_argument("--jobs", type=int, default=2, help="worker processes for static modes (default 2)")
    r.add_argument("--ml", default="default", choices=["default", "on", "off"], help="learned stage")
    r.add_argument("--no-cache", action="store_true", help="do not reuse cached extraction results")
    r.add_argument("--out", type=Path, default=DEFAULT_OUT, help=f"output directory (default {DEFAULT_OUT})")
    r.add_argument("--name", default="", help="result file stem (default latest[_<mode>])")
    r.add_argument("--version-label", default="", help="label stored in the result (default: package version)")
    r.add_argument("--details", action="store_true", help="also write per-page rows (<name>.rows.jsonl)")
    s = sub.add_parser("show", help="print a result file as Markdown")
    s.add_argument("file", type=Path)
    c = sub.add_parser("compare", help="compare two result files")
    c.add_argument("a", type=Path)
    c.add_argument("b", type=Path)


def _detector_info(mode: str, ml_on: bool) -> dict[str, Any]:
    from ..scorer import load_rules

    cfg, _ = load_rules()
    return {"name": "injectionwatch", "rules_version": cfg.get("version"), "ml": ml_on, "mode": mode}


def _scan_kwargs(ml: str) -> tuple[dict[str, Any], bool]:
    from .. import detector

    params = inspect.signature(detector.scan_candidates).parameters
    if "ml" not in params:
        if ml == "on":
            raise SystemExit("error: this detector version has no learned stage (--ml on)")
        return {}, False
    if ml == "default":
        import importlib

        on = bool(importlib.import_module("injectionwatch.ml").ml_default_enabled())
        return {"ml": on}, on
    return {"ml": ml == "on"}, ml == "on"


def _progress(start: float) -> Any:
    last = [0.0]

    def cb(i: int, n: int) -> None:
        now = time.time()
        if now - last[0] > 5 or i == n:
            last[0] = now
            print(f"\r  {i}/{n} pages  {now - start:5.0f}s", end="" if i < n else "\n", file=sys.stderr, flush=True)
    return cb


def run(args: argparse.Namespace) -> int:
    from . import report, runner, sources

    if args.bench_cmd == "data":
        try:
            sources.fetch_all(args.only, force=args.force)
        except sources.SourceError as e:
            print(f"error: {e}\nhint: needs git and HTTPS access to github.com", file=sys.stderr)
            return 1
        print(f"cache: {sources.cache_root()}")
        return 0
    if args.bench_cmd == "status":
        bad = 0
        for st in sources.status():
            print(f"  {st.id:<12} {'ok' if st.ready else 'missing'}  {st.error}")
            bad += not st.ready
        return 1 if bad else 0
    if args.bench_cmd == "show":
        print(report.markdown(json.loads(args.file.read_text("utf-8"))))
        return 0
    if args.bench_cmd == "compare":
        a, b = (json.loads(p.read_text("utf-8")) for p in (args.a, args.b))
        keys = ("overall", "visible_control", "benign_hidden_text", "discussion_pages")
        print(f"{'':<22}{args.a.stem:>28}{args.b.stem:>28}")
        for k in keys:
            for m in ("recall", "fp_rate"):
                va, vb = a[k].get(m), b[k].get(m)
                if va is None and vb is None:
                    continue
                print(f"{k + '.' + m:<34}{va!s:>16}{vb!s:>28}")
        return 0
    # run
    missing = [st.id for st in sources.status() if not st.ready]
    if missing:
        print(f"error: sources not cached: {', '.join(missing)}\nhint: run `injectionwatch bench data` first",
              file=sys.stderr)
        return 1
    from ..config import VERSION

    modes = ["static", "static_css", "rendered"] if args.mode == "all" else [args.mode]
    scan_kwargs, ml_on = _scan_kwargs(args.ml)
    specs = runner.build_specs(args.split, args.per_payload, args.per_benign, args.quick)
    for mode in modes:
        t0 = time.time()
        print(f"IW-Bench: {len(specs)} pages, mode={mode}, split={args.split}, ml={ml_on}"
              + (" (quick)" if args.quick else ""), file=sys.stderr)
        rows = runner.run_specs(runner.shuffle_for_balance(specs), mode, scan_kwargs, args.jobs,
                                not args.no_cache, _progress(t0))
        config = {"quick": args.quick, "per_payload": args.per_payload, "per_benign": args.per_benign,
                  "seed": "iwbench-v1", "elapsed_s": round(time.time() - t0, 1)}
        summ = report.summarise(rows, detector=_detector_info(mode, ml_on), split=args.split, config=config,
                                version=args.version_label or VERSION)
        stem = args.name or ("latest" if len(modes) == 1 else f"latest_{mode}")
        if args.name and len(modes) > 1:
            stem = f"{args.name}_{mode}"
        out = args.out / f"{stem}.json"
        report.write_summary(summ, out)
        if args.details:
            with (args.out / f"{stem}.rows.jsonl").open("w", encoding="utf-8") as fh:
                for r in rows:
                    fh.write(json.dumps(r) + "\n")
        report.update_index(args.out)
        print(report.markdown(summ))
        print(f"\nwrote {out} ({time.time() - t0:.0f}s)", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="injectionwatch bench", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    _configure(p)
    return run(p.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
