"""Learned second stage: a hashed n-gram logistic-regression scorer (pure Python, no numpy at inference).

Features (identical in ``extension/src/ml.ts``; tests/test_ml.py checks parity to 1e-9):

1. ``t = normalize_payload(text)`` (NFKC, invisible characters removed, lower-case, whitespace collapsed),
   truncated to ``max_chars`` code points.
2. Character n-grams of ``t`` padded with one space on each side, for n in ``char_ns`` (over code points), and
   word unigrams / bigrams of ``t`` split on runs of characters that are not letters or digits (Unicode classes
   ``\\p{L}\\p{N}``; implemented with ``str.isalnum`` in Python and ``/[\\p{L}\\p{N}]+/gu`` in TypeScript).
   Every feature string is prefixed (``c:`` / ``w:``) and hashed with **FNV-1a 32-bit over its UTF-8 bytes**,
   modulo ``2**bits``.
3. Values are ``1 + ln(count)`` per bucket, then L2-normalised. The score is
   ``sigmoid(bias + sum(w[b] * x[b]))`` with the sum taken over buckets in ascending order.

Weights live in ``data/ml_model.json`` (sparse: only non-zero buckets are stored), trained by
``scripts/train_ml.py``. See that script and reports/bench/README.md for data, splits and thresholds.

How the detector uses it (``detector.scan_candidates(ml=...)``): a candidate that the rules did not fire on is
also flagged when it is non-visible, has at least ``min_chars`` characters and its ML score reaches the model's
``threshold`` (chosen on the dev split only). Rules stay authoritative: the model can add findings, never remove
them.
"""
from __future__ import annotations

import itertools
import json
import math
import os
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any

from .textutil import clean_for_scoring, normalize_payload

FNV_OFFSET = 0x811C9DC5
FNV_PRIME = 0x01000193


def fnv1a32(s: str) -> int:
    h = FNV_OFFSET
    for b in s.encode("utf-8", "surrogatepass"):
        h ^= b
        h = (h * FNV_PRIME) & 0xFFFFFFFF
    return h


def _words(t: str) -> list[str]:
    out: list[str] = []
    cur: list[str] = []
    for ch in t:
        if ch.isalnum():
            cur.append(ch)
        elif cur:
            out.append("".join(cur))
            cur = []
    if cur:
        out.append("".join(cur))
    return out


@dataclass(frozen=True)
class FeatureConfig:
    bits: int = 18
    char_ns: tuple[int, ...] = (3, 4, 5)
    words: bool = True
    word_bigrams: bool = True
    max_chars: int = 1000

    def to_dict(self) -> dict[str, Any]:
        return {"bits": self.bits, "char_ns": list(self.char_ns), "words": self.words,
                "word_bigrams": self.word_bigrams, "max_chars": self.max_chars, "hash": "fnv1a32-utf8",
                "value": "1+ln(count), l2-normalised"}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FeatureConfig:
        return cls(int(d["bits"]), tuple(int(n) for n in d["char_ns"]), bool(d["words"]), bool(d["word_bigrams"]),
                   int(d["max_chars"]))


DEFAULT_FEATURES = FeatureConfig()


def features(text: str, cfg: FeatureConfig | None = None) -> list[tuple[int, float]]:
    """Sorted (bucket, value) pairs."""
    cfg = cfg or DEFAULT_FEATURES
    t = normalize_payload(text)
    cps = list(t)[: cfg.max_chars]
    t = "".join(cps)
    mask = (1 << cfg.bits) - 1
    counts: dict[int, int] = {}

    def add(f: str) -> None:
        b = fnv1a32(f) & mask
        counts[b] = counts.get(b, 0) + 1

    padded = [" ", *cps, " "]
    for n in cfg.char_ns:
        for i in range(len(padded) - n + 1):
            add("c:" + "".join(padded[i:i + n]))
    if cfg.words:
        ws = _words(t)
        for w in ws:
            add("w:" + w)
        if cfg.word_bigrams:
            for a, b in itertools.pairwise(ws):
                add("w:" + a + " " + b)
    if not counts:
        return []
    items = sorted((b, 1.0 + math.log(c)) for b, c in counts.items())
    norm = math.sqrt(sum(v * v for _, v in items))
    return [(b, v / norm) for b, v in items]


def sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


@dataclass
class Model:
    cfg: FeatureConfig
    bias: float
    weights: dict[int, float]
    threshold: float
    min_chars: int = 20
    meta: dict[str, Any] | None = None
    skip_locations: tuple[str, ...] = ("visible", "script")

    def score(self, text: str) -> float:
        z = self.bias
        w = self.weights
        for b, v in features(text, self.cfg):
            wb = w.get(b)
            if wb is not None:
                z += wb * v
        return sigmoid(z)

    def fires(self, text: str, location: str) -> tuple[float, bool]:
        """The detector's gate (mirrors iwMlFires in extension/src/ml.ts): non-visible, >= min_chars cleaned
        code points, location not in ``skip_locations`` (visible text and inline-script strings by default), score >=
        threshold. Returns (score, fired); score is 0.0 when the gate skips the text."""
        if location in self.skip_locations or len(clean_for_scoring(text)) < self.min_chars:
            return 0.0, False
        sc = self.score(text)
        return sc, sc >= self.threshold

    def to_json(self) -> dict[str, Any]:
        keys = sorted(self.weights)
        return {"format": "injectionwatch-ml/1", "features": self.cfg.to_dict(), "bias": self.bias,
                "threshold": self.threshold, "min_chars": self.min_chars, "skip_locations": list(self.skip_locations),
                "meta": self.meta or {},
                "buckets": keys, "weights": [self.weights[k] for k in keys]}

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> Model:
        if d.get("format") != "injectionwatch-ml/1":
            raise ValueError("unknown ml model format")
        return cls(FeatureConfig.from_dict(d["features"]), float(d["bias"]),
                   {int(b): float(w) for b, w in zip(d["buckets"], d["weights"], strict=True)},
                   float(d["threshold"]), int(d.get("min_chars", 20)), d.get("meta"),
                   tuple(d.get("skip_locations", ("visible", "script"))))


@lru_cache(maxsize=1)
def load_model() -> Model | None:
    """The bundled model, or None when ``data/ml_model.json`` is absent."""
    try:
        raw = resources.files("injectionwatch").joinpath("data/ml_model.json").read_text("utf-8")
    except (FileNotFoundError, OSError):
        return None
    return Model.from_json(json.loads(raw))


def ml_default_enabled() -> bool:
    """Default for ``scan_candidates(ml=None)``: the model's own ``default_on`` flag, overridable with the
    ``INJECTIONWATCH_ML`` environment variable (``1``/``0``)."""
    env = os.environ.get("INJECTIONWATCH_ML")
    if env is not None:
        return env.strip().lower() in ("1", "true", "yes", "on")
    m = load_model()
    return bool(m and (m.meta or {}).get("default_on"))
