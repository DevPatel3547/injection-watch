"""Sample-scan Common Crawl WARCs with the InjectionWatch static detector (research harness).

Downloads randomly chosen WARC files from one crawl one at a time (at most one WARC ahead, so disk use
stays near 2 x ~1.2 GB), scans every HTTP-200 text/html response with a per-page timeout in a process
pool, deletes each WARC after scanning, and writes:

    out/hits.jsonl              one line per finding (url, WARC offset, severity, category, full hidden text...)
    out/scan_stats.json         funnel counts, per-WARC stats, per-severity page / finding counts
    out/hit_pages/*.html.gz     raw HTML of every page with a finding (cap: --hit-page-cap)
    out/hit_pages/index.jsonl   page_id -> url, WARC, offset, HTTP response headers
    out/selected_warcs.txt      the sampled WARC paths (reproducible with --seed)
    out/feed.db                 optional (--db): findings stored with InjectionWatch's DB layer

Usage:
    python scripts/scan_cc.py --crawl CC-MAIN-2026-40 --paths warc.paths.gz --max 20 --out out --db out/feed.db

``injectionwatch scan-warc`` is the production path (resumable, DB-native). This harness adds the page
timeout, the detection funnel and saved hit pages needed to hand-label a sample.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import random
import re
import signal
import subprocess
import threading
import time
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from typing import Any

BASE = "https://data.commoncrawl.org/"
PAGE_TIMEOUT_S = 20
MAX_INFLIGHT = 400
KEEP_HEADERS = 40

# ------------------------------------------------------------------ worker side
_W: dict[str, Any] = {}


class _Timeout(Exception):
    pass


def _alarm(signum, frame):
    raise _Timeout()


def _winit() -> None:
    from injectionwatch import detector, scorer
    from injectionwatch.extract import extract_candidates

    cfg, _ = scorer.load_rules()
    _W["thr"] = float(cfg["threshold"])
    _W["extract"] = extract_candidates
    _W["scan_candidates"] = detector.scan_candidates
    orig = scorer.score_text
    rec = {"rule_nonvisible": False, "rule_any": False, "over_thr": False}
    _W["rec"] = rec

    def wrapped(text, location="hidden_css", in_code=False, techniques=None, page_is_discussion=False):
        sr = orig(text, location, in_code, techniques, page_is_discussion)
        if sr.hits:
            rec["rule_any"] = True
            if location != "visible":
                rec["rule_nonvisible"] = True
        if sr.score >= _W["thr"]:
            rec["over_thr"] = True
        return sr

    detector.score_text = wrapped  # detector imported the name directly
    signal.signal(signal.SIGALRM, _alarm)


_CHARSET_RE = re.compile(rb"<meta[^>]+charset=[\"']?([a-zA-Z0-9_\-]+)", re.I)


def _decode(body: bytes, ctype: str) -> str:
    cs = None
    m = re.search(r"charset=([\w\-]+)", ctype or "", re.I)
    if m:
        cs = m.group(1)
    else:
        m2 = _CHARSET_RE.search(body[:4096])
        if m2:
            cs = m2.group(1).decode("ascii", "ignore")
    for enc in (cs, "utf-8"):
        if not enc:
            continue
        try:
            return body.decode(enc, errors="replace")
        except LookupError:
            continue
    return body.decode("utf-8", errors="replace")


def scan_page(task):
    url, warc, offset, ctype, headers, body = task
    rec = _W["rec"]
    for k in rec:
        rec[k] = False
    out: dict[str, Any] = {"url": url, "warc": warc, "offset": offset, "status": "ok"}
    signal.setitimer(signal.ITIMER_REAL, PAGE_TIMEOUT_S)
    try:
        html = _decode(body, ctype)
        cands = _W["extract"](html, headers)
        res = _W["scan_candidates"](cands, url)
        out["n_cands"] = len(cands)
        out["n_nonvisible"] = sum(1 for c in cands if c.location != "visible")
        out.update(rec)
        findings = []
        cand_text: dict[tuple[str, str], str] = {}
        if res.findings:
            from injectionwatch.textutil import payload_hash

            for c in cands:
                cand_text.setdefault((payload_hash(c.text), c.location), c.text)
        for f in res.findings:
            d = f.to_dict()
            d["hidden_text"] = cand_text.get((f.payload_hash, f.location), f.payload_excerpt)[:1000]
            findings.append(d)
        out["findings"] = findings
        if findings:
            out["html"] = body
            out["headers"] = dict(list(headers.items())[:KEEP_HEADERS])
    except _Timeout:
        out["status"] = "timeout"
    except Exception as e:
        out["status"] = "error"
        out["error"] = f"{type(e).__name__}: {e}"[:200]
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    return out


# ------------------------------------------------------------------ driver side

def log(msg: str) -> None:
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def download(path: str, dest: str, base: str = BASE) -> bool:
    part = dest + ".part"
    for attempt in range(4):
        rc = subprocess.call(["curl", "-sS", "--fail", "-C", "-", "--retry", "5", "--retry-delay", "10",
                              "--connect-timeout", "30", "-o", part, base + path])
        if rc == 0:
            os.replace(part, dest)
            return True
        log(f"download rc={rc} attempt={attempt} for {path}; sleeping")
        time.sleep(30 * (attempt + 1))
    return False


def iter_html_records(fp, warc_name, st):
    from warcio.archiveiterator import ArchiveIterator

    it = ArchiveIterator(fp)
    for rec in it:
        st["records"] += 1
        if rec.rec_type != "response":
            continue
        st["responses"] += 1
        hdrs = rec.http_headers
        if hdrs is None:
            continue
        ctype = (hdrs.get_header("Content-Type") or "").lower()
        if "html" not in ctype:
            continue
        try:
            status = int(hdrs.get_statuscode() or "0")
        except ValueError:
            status = 0
        if status != 200:
            st["html_non200"] += 1
            continue
        body = rec.content_stream().read()
        offset = it.get_record_offset()
        if not body:
            continue
        url = rec.rec_headers.get_header("WARC-Target-URI")
        date = rec.rec_headers.get_header("WARC-Date")
        h = dict(hdrs.headers)
        yield (url, warc_name, offset, ctype, h, body), date


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--crawl", required=True)
    ap.add_argument("--paths", default="warc.paths.gz")
    ap.add_argument("--out", default="out")
    ap.add_argument("--max", type=int, default=20)
    ap.add_argument("--initial", type=int, default=3, help="always scan at least this many WARCs")
    ap.add_argument("--budget-s", type=float, default=6 * 3600)
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--seed", type=int, default=20261012)
    ap.add_argument("--exclude", default=None, help="file of WARC paths to never select (e.g. a previous sample)")
    ap.add_argument("--hit-page-cap", type=int, default=5000)
    ap.add_argument("--db", default=None, help="also store findings in an InjectionWatch SQLite DB")
    ap.add_argument("--base", default=BASE, help="download prefix (file:// works for local tests)")
    a = ap.parse_args()

    from injectionwatch import __version__
    from injectionwatch.scorer import load_rules

    os.makedirs(a.out, exist_ok=True)
    pages_dir = os.path.join(a.out, "hit_pages")
    os.makedirs(pages_dir, exist_ok=True)
    dl_dir = os.path.join(a.out, "dl")
    os.makedirs(dl_dir, exist_ok=True)

    with gzip.open(a.paths, "rt") as f:
        all_paths = [line.strip() for line in f if line.strip()]
    excluded = set()
    if a.exclude:
        with open(a.exclude) as ef:
            excluded = {line.strip() for line in ef if line.strip()}
    pool = [p for p in all_paths if p not in excluded]
    chosen = random.Random(a.seed).sample(pool, a.max)
    with open(os.path.join(a.out, "selected_warcs.txt"), "w") as f:
        f.write("\n".join(chosen) + "\n")

    db = None
    if a.db:
        from injectionwatch.db import DB

        db = DB(a.db)
        run_id = db.start_scan_run(chosen)

    hits_fp = open(os.path.join(a.out, "hits.jsonl"), "a")  # noqa: SIM115
    idx_fp = open(os.path.join(pages_dir, "index.jsonl"), "a")  # noqa: SIM115
    T0 = time.time()
    G: Counter[str] = Counter()
    by_loc, by_tech, by_cat, by_rule, by_sev = Counter(), Counter(), Counter(), Counter(), Counter()
    by_loc_pages, by_sev_pages = Counter(), Counter()
    per_warc: list[dict[str, Any]] = []
    saved_pages = 0
    errors_sample: list[dict[str, Any]] = []
    cfg, _ = load_rules()

    def write_stats(done: bool = False) -> None:
        el = time.time() - T0
        stats = {
            "crawl": a.crawl, "injectionwatch_version": __version__, "rules_version": cfg["version"],
            "seed": a.seed, "warcs_selected": chosen, "warcs_scanned": [w["warc"] for w in per_warc],
            "elapsed_s": round(el, 1), "workers": a.workers, "page_timeout_s": PAGE_TIMEOUT_S,
            "totals": dict(G), "pages_per_s_overall": round(G["pages_scanned"] / el, 2) if el else 0,
            "findings_by_severity": dict(by_sev), "pages_by_severity": dict(by_sev_pages),
            "finding_locations": dict(by_loc), "pages_with_finding_by_location": dict(by_loc_pages),
            "finding_techniques": dict(by_tech.most_common(60)),
            "finding_categories": dict(by_cat), "finding_rules": dict(by_rule.most_common(80)),
            "hit_pages_saved": saved_pages, "per_warc": per_warc, "errors_sample": errors_sample[:20],
            "definitions": {
                "pages_scanned": "HTTP 200 text/html response records parsed by extract_candidates+scan_candidates",
                "pages_rule_match_nonvisible": "pages where >=1 non-visible candidate matched >=1 counted rule",
                "pages_over_threshold": "pages where some candidate's location-weighted score >= threshold",
                "pages_with_finding": "pages with >=1 detector Finding (any severity, incl. ai_optout signals)",
                "pages_by_severity": "pages with >=1 Finding of that severity",
                "pages_flagged": "pages whose verdict is flagged (severity manipulative/malicious)",
            },
            "done": done,
        }
        tmp = os.path.join(a.out, "scan_stats.json.tmp")
        with open(tmp, "w") as f:
            json.dump(stats, f, indent=2)
        os.replace(tmp, os.path.join(a.out, "scan_stats.json"))

    def handle(fut, date: str | None) -> None:
        nonlocal saved_pages
        try:
            r = fut.result()
        except Exception as e:
            G["pages_worker_crash"] += 1
            if len(errors_sample) < 50:
                errors_sample.append({"status": "worker_crash", "error": repr(e)[:200]})
            return
        st = r["status"]
        if st != "ok":
            G[f"pages_{st}"] += 1
            if len(errors_sample) < 50:
                errors_sample.append({"url": r["url"], "status": st, "error": r.get("error")})
            return
        G["pages_scanned"] += 1
        G["candidates_total"] += r["n_cands"]
        for k in ("rule_any", "rule_nonvisible", "over_thr"):
            G[{"rule_any": "pages_rule_match_any", "rule_nonvisible": "pages_rule_match_nonvisible",
               "over_thr": "pages_over_threshold"}[k]] += int(r[k])
        G["pages_with_nonvisible_candidate"] += int(bool(r["n_nonvisible"]))
        fs = r["findings"]
        if not fs:
            return
        G["pages_with_finding"] += 1
        G["pages_flagged"] += int(any(f["flagged"] for f in fs))
        for sev in {f["severity"] for f in fs}:
            by_sev_pages[sev] += 1
        page_id = hashlib.sha1(f'{r["warc"]}:{r["offset"]}'.encode()).hexdigest()[:16]
        saved = False
        if saved_pages < a.hit_page_cap:
            with gzip.open(os.path.join(pages_dir, page_id + ".html.gz"), "wb") as g:
                g.write(r["html"])
            saved_pages += 1
            saved = True
            idx_fp.write(json.dumps({"page_id": page_id, "url": r["url"], "warc": r["warc"], "offset": r["offset"],
                                     "warc_date": date, "headers": r.get("headers", {})}, ensure_ascii=False) + "\n")
        for loc in {f["location"] for f in fs}:
            by_loc_pages[loc] += 1
        for f in fs:
            G["findings_total"] += 1
            by_sev[f["severity"]] += 1
            by_loc[f["location"]] += 1
            for t in f["techniques"] or ["(none)"]:
                by_tech[t] += 1
            by_cat[f["category"]] += 1
            for rs in f["reasons"]:
                m = re.match(r"rule (\S+) \(.*\) matched '.*'(?: \[inside quotes\])?$", rs)
                if m and "but ignored" not in rs:
                    by_rule[m.group(1)] += 1
            hits_fp.write(json.dumps({
                "page_id": page_id, "html_saved": saved, "url": r["url"], "warc": r["warc"], "offset": r["offset"],
                "warc_date": date, "location": f["location"], "techniques": f["techniques"], "path": f["path"],
                "hidden_text": f["hidden_text"], "score": f["heuristic_score"], "category": f["category"],
                "intent": f["intent"], "severity": f["severity"], "confidence": f["confidence"],
                "flagged": f["flagged"], "payload_hash": f["payload_hash"], "payload_excerpt": f["payload_excerpt"],
                "target": f["target"], "reasons": f["reasons"],
            }, ensure_ascii=False) + "\n")
        if db is not None:
            from injectionwatch.detector import Finding, ScanResult

            obs = (date or "").replace("Z", "+00:00") or None
            keep = set(Finding.__dataclass_fields__)
            fobjs = [Finding(**{k: v for k, v in f.items() if k in keep}) for f in fs]
            db.store_scan(r["url"], ScanResult(r["url"], fobjs), hashlib.sha256(r["html"]).hexdigest(), obs,
                          source=f"warc:{r['warc']}", mark_missing_removed=False, commit=False)

    ready: dict[str, str | None] = {}
    lock = threading.Lock()
    stop_flag = threading.Event()

    def fetcher(paths: list[str]) -> None:
        for p in paths:
            if stop_flag.is_set():
                return
            dest = os.path.join(dl_dir, os.path.basename(p))
            ok = download(p, dest, a.base)
            with lock:
                ready[p] = dest if ok else None
            while True:  # never more than one WARC ahead (disk cap)
                with lock:
                    pending = sum(1 for v in ready.values() if v)
                if pending < 2 or stop_flag.is_set():
                    break
                time.sleep(2)

    th = threading.Thread(target=fetcher, args=(chosen,), daemon=True)
    th.start()

    with ProcessPoolExecutor(max_workers=a.workers, initializer=_winit) as ex:
        for i, p in enumerate(chosen):
            if i >= a.initial and time.time() - T0 > a.budget_s:
                log(f"budget exceeded after {i} WARCs; stopping")
                stop_flag.set()
                break
            while True:
                with lock:
                    if p in ready:
                        dest = ready[p]
                        break
                time.sleep(2)
            if dest is None:
                log(f"skip {p}: download failed")
                with lock:
                    ready.pop(p, None)
                continue
            name = os.path.basename(p)
            log(f"scanning {i + 1}/{len(chosen)} {name} ({os.path.getsize(dest) / 1e9:.2f} GB)")
            st: Counter[str] = Counter()
            t1 = time.time()
            before = Counter(G)
            inflight: dict[Any, str | None] = {}
            n = 0
            with open(dest, "rb") as fp:
                for task, date in iter_html_records(fp, name, st):
                    inflight[ex.submit(scan_page, task)] = date
                    n += 1
                    if len(inflight) >= MAX_INFLIGHT:
                        done, _ = wait(list(inflight), return_when=FIRST_COMPLETED)
                        for d in done:
                            handle(d, inflight.pop(d))
                    if n % 5000 == 0:
                        sc = G["pages_scanned"] - before["pages_scanned"]
                        log(f"  {name}: submitted {n}, scanned {sc}, {sc / (time.time() - t1):.1f} p/s")
                        write_stats()
                for d in wait(list(inflight)).done:
                    handle(d, inflight.pop(d))
            dt = time.time() - t1
            delta = {k: G[k] - before.get(k, 0) for k in G}
            per_warc.append({"warc": p, "scan_s": round(dt, 1), "records": st["records"],
                             "responses": st["responses"], "html_non200": st["html_non200"],
                             "html_pages_submitted": n, **delta,
                             "pages_per_s": round(delta.get("pages_scanned", 0) / dt, 2) if dt else 0})
            hits_fp.flush()
            idx_fp.flush()
            if db is not None:
                db.commit()
            os.remove(dest)
            with lock:
                ready.pop(p, None)
            log(f"done {name}: pages={delta.get('pages_scanned', 0)} findings={delta.get('findings_total', 0)} "
                f"in {dt:.0f}s")
            write_stats()
    stop_flag.set()
    write_stats(done=True)
    if db is not None:
        db.finish_scan_run(run_id, {"pages_scanned": G["pages_scanned"], "html_pages": G["pages_scanned"],
                                    "findings": G["findings_total"], "pages_flagged": G["pages_flagged"],
                                    "findings_by_severity": dict(by_sev), "pages_by_severity": dict(by_sev_pages)})
        db.commit()
    log("ALL DONE")


if __name__ == "__main__":
    main()
