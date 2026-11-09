// Mirror of injectionwatch/ml.py (hashed n-gram logistic regression). Parity: tests/test_ml.py (1e-9).
// Depends on iwNormalize from scorer.ts (same content-script world). The model is DATA (a JSON literal bundled
// as IW_ML by the build), never fetched or evaluated at runtime.

interface IwMlFeatures { bits: number; char_ns: number[]; words: boolean; word_bigrams: boolean; max_chars: number; }
interface IwMlModel {
  format: string; features: IwMlFeatures; bias: number; threshold: number; min_chars: number; skip_locations?: string[];
  buckets: number[]; weights: number[]; meta?: Record<string, unknown>;
}

const IW_FNV_OFFSET = 0x811c9dc5;
const IW_WORD_RE = /[\p{L}\p{N}]+/gu;
let iwMlWeights: Map<number, number> | null = null;
let iwMlFor: IwMlModel | null = null;

function iwFnv1a32(s: string): number {
  const bytes = new TextEncoder().encode(s);
  let h = IW_FNV_OFFSET;
  for (let i = 0; i < bytes.length; i++) {
    h ^= bytes[i];
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

function iwMlFeatures(text: string, cfg: IwMlFeatures): Array<[number, number]> {
  const cps = Array.from(iwNormalize(text)).slice(0, cfg.max_chars);
  const t = cps.join("");
  const mask = cfg.bits >= 32 ? 0xffffffff : (1 << cfg.bits) - 1;
  const counts = new Map<number, number>();
  const add = (f: string) => { const b = (iwFnv1a32(f) & mask) >>> 0; counts.set(b, (counts.get(b) || 0) + 1); };
  const padded = [" ", ...cps, " "];
  for (const n of cfg.char_ns) {
    for (let i = 0; i + n <= padded.length; i++) add("c:" + padded.slice(i, i + n).join(""));
  }
  if (cfg.words) {
    const ws = t.match(IW_WORD_RE) || [];
    for (const w of ws) add("w:" + w);
    if (cfg.word_bigrams) for (let i = 0; i + 1 < ws.length; i++) add("w:" + ws[i] + " " + ws[i + 1]);
  }
  if (!counts.size) return [];
  const items: Array<[number, number]> = Array.from(counts.entries())
    .sort((a, b) => a[0] - b[0]).map(([b, c]) => [b, 1 + Math.log(c)]);
  let ss = 0;
  for (const [, v] of items) ss += v * v;
  const norm = Math.sqrt(ss);
  return items.map(([b, v]) => [b, v / norm]);
}

function iwSigmoid(z: number): number {
  if (z >= 0) return 1 / (1 + Math.exp(-z));
  const e = Math.exp(z);
  return e / (1 + e);
}

function iwMlScore(text: string, model: IwMlModel): number {
  if (iwMlFor !== model) {
    iwMlWeights = new Map();
    for (let i = 0; i < model.buckets.length; i++) iwMlWeights.set(model.buckets[i], model.weights[i]);
    iwMlFor = model;
  }
  let z = model.bias;
  for (const [b, v] of iwMlFeatures(text, model.features)) {
    const w = iwMlWeights!.get(b);
    if (w !== undefined) z += w * v;
  }
  return iwSigmoid(z);
}

// Same gate as ml.Model.fires: location not skipped, >= min_chars cleaned code points, score >= threshold.
function iwMlFires(text: string, location: string, model: IwMlModel): { score: number; fired: boolean } {
  const skip = model.skip_locations ?? ["visible", "script"];
  if (skip.indexOf(location) >= 0 || Array.from(iwClean(text)).length < model.min_chars) return { score: 0, fired: false };
  const score = iwMlScore(text, model);
  return { score, fired: score >= model.threshold };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { iwFnv1a32, iwMlFeatures, iwMlScore, iwMlFires };
}
