"""Write a synthetic WARC from the fixture corpora (for `make warc-demo` and benchmarking).

Usage: python scripts/make_synthetic_warc.py OUT.warc.gz [--filler N]
Every fixture page becomes one response record at https://<fixture-name>.example/ ; --filler adds N
benign ~20 KB pages (navigation, stylesheet, paragraphs) to approximate a real crawl's mix.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from injectionwatch.warc import write_synthetic_warc

WORDS = ["the", "of", "and", "to", "in", "a", "is", "that", "for", "it", "with", "as", "was", "on", "be", "by", "this", "are", "from", "at", "or", "have", "an", "they", "which", "one", "you", "were", "her", "all", "she", "there", "would", "their", "we", "him", "been", "has", "when", "who", "will", "more", "no", "if", "out", "so", "said", "what", "up", "its", "about", "into", "than", "them", "can", "only", "other", "new", "some", "could", "time", "these"]


def filler(i: int, rnd: random.Random) -> str:
    nav = "".join(f"<li><a href='/c/{j}' title='Category {j}'>Category {j}</a></li>" for j in range(40))
    paras = "".join("<p>" + " ".join(rnd.choice(WORDS) for _ in range(80)) + "</p>" for _ in range(25))
    css = "<style>" + "".join(f".c{j}{{color:#333;margin:{j}px}} .h{j}{{display:none}} " for j in range(150)) + "</style>"
    return (f"<!doctype html><html><head><title>Page {i}</title>{css}</head><body><nav><ul>{nav}</ul></nav>"
            f"<article>{paras}</article><div class='h3'>Subscribe to our newsletter.</div></body></html>")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--filler", type=int, default=200)
    a = ap.parse_args()
    pages = []
    for d in ("fixtures", "fixtures_dev"):
        labels = json.loads((ROOT / d / "labels.json").read_text("utf-8"))
        for fname, lab in sorted(labels.items()):
            pages.append({"url": f"https://{Path(fname).stem.replace('_', '-')}.example/",
                          "body": (ROOT / d / "pages" / fname).read_text("utf-8"), "headers": lab.get("headers") or {}})
    rnd = random.Random(7)
    pages += [{"url": f"https://filler{i}.example/p", "body": filler(i, rnd)} for i in range(a.filler)]
    rnd.shuffle(pages)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    p = write_synthetic_warc(a.out, pages)
    print(f"wrote {p} ({len(pages)} pages, {p.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
