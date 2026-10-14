// Mirror of injectionwatch/textutil.py + scorer.py + classify.HeuristicClassifier.
// Parity with Python is enforced by tests/test_rules.py (every fixture candidate, both languages).

const IW_ZW = /[​‌‍⁠﻿᠎­]/g;
const IW_TAGS = /[\u{E0000}-\u{E007F}]/gu;
const IW_ZW_IN_WORD = /[A-Za-z][​‌‍⁠﻿᠎]+[A-Za-z]/;
const IW_PRIORITY = ["data_exfiltration", "tool_invocation", "instruction_override", "concealment",
  "user_manipulation", "hiring_manipulation", "support_manipulation", "recommendation_manipulation",
  "summarizer_steering", "role_injection", "agent_promotion", "ai_restriction", "ai_optout"];
const IW_MALICIOUS = new Set(["data_exfiltration", "tool_invocation"]);
const IW_MANIPULATIVE = new Set(["instruction_override", "concealment", "role_injection", "user_manipulation",
  "hiring_manipulation", "support_manipulation", "recommendation_manipulation", "summarizer_steering"]);
const IW_SPINTAX = /\{[^{}|\n]{1,60}\|[^{}\n]{1,200}\}/g;
const IW_JSON_PAIR = /"[^"\n]{1,80}"\s*:/g;

// JSON app state or spintax template (mirrors scorer.is_state_blob)
function iwIsBlob(text: string): boolean {
  const t = text.replace(/^\s+/, "");
  const n = (re: RegExp) => (t.match(re) || []).length;
  if ((t[0] === "{" || t[0] === "[") && n(IW_JSON_PAIR) >= (IW_RULES.blob_min_json_pairs ?? 3)) return true;
  return n(IW_SPINTAX) >= (IW_RULES.blob_min_spintax ?? 3);
}

function iwClean(s: string): string {
  return s.normalize("NFKC").replace(IW_ZW, "").replace(IW_TAGS, "").replace(/\s+/g, " ").trim();
}
function iwNormalize(s: string): string { return iwClean(s).toLowerCase(); }
function iwHasZeroWidthObfuscation(s: string): boolean { return IW_ZW_IN_WORD.test(s); }
function iwDecodeTagRuns(s: string): string[] {
  const out: string[] = [];
  const re = /[\u{E0000}-\u{E007F}]{4,}/gu;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) {
    let t = "";
    for (const ch of m[0]) { const cp = ch.codePointAt(0)!; if (cp >= 0xE0020 && cp <= 0xE007E) t += String.fromCharCode(cp - 0xE0000); }
    if (t.trim()) out.push(t);
  }
  return out;
}
async function iwHash(s: string): Promise<string> {
  const data = new TextEncoder().encode(iwNormalize(s));
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function iwDefang(s: string): string {
  return s.replace(/\b(https?):\/\/([^\s"'<>]+)/gi, (_m, scheme: string, rest: string) => {
    const i = rest.indexOf("/");
    const host = i >= 0 ? rest.slice(0, i) : rest;
    const tail = i >= 0 ? rest.slice(i) : "";
    return scheme.toLowerCase().replace("http", "hxxp") + "://" + host.split(".").join("[.]") + tail;
  });
}
function iwExcerpt(s: string, n = 200): string {
  const t = iwDefang(iwClean(s));
  return t.length <= n ? t : t.slice(0, n - 1).trimEnd() + "…";
}

interface IwCompiled { rule: IwRule; re: RegExp; reAll: RegExp; }
let iwCompiled: IwCompiled[] | null = null;
let iwDiscussionRe: RegExp | null = null;
let iwQuoteRe: RegExp | null = null;
function iwRules(): IwCompiled[] {
  if (!iwCompiled) {
    iwCompiled = IW_RULES.rules.map((r) => {
      const p = r.pattern.normalize("NFKC");
      return { rule: r, re: new RegExp(p, "i"), reAll: new RegExp(p, "gi") };
    });
    iwDiscussionRe = new RegExp(IW_RULES.discussion_pattern.normalize("NFKC"), "i");
    iwQuoteRe = new RegExp(IW_RULES.quote_pattern.normalize("NFKC"), "gi");
  }
  return iwCompiled;
}

function iwLocationFactor(location: string, inCode: boolean, techniques: string[], discussion: boolean): number {
  let f = IW_RULES.location_factors[location] ?? 1.0;
  if (location === "visible") {
    if (inCode) f = IW_RULES.in_code_factor; else if (discussion) f *= IW_RULES.discussion_factor;
  } else {
    if (inCode) f *= IW_RULES.hidden_in_code_factor;
    if (discussion) f *= IW_RULES.hidden_discussion_factor;
  }
  if (techniques.includes("zero_width")) f = Math.max(f, IW_RULES.zero_width_min_factor);
  return f;
}

function iwAllMatches(re: RegExp, t: string): [number, number][] {
  const out: [number, number][] = [];
  re.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(t))) {
    out.push([m.index, m.index + m[0].length]);
    if (m[0].length === 0) re.lastIndex++;
  }
  return out;
}

function iwScore(text: string, location: string, inCode: boolean, techniques: string[], discussion: boolean) {
  const t = iwClean(text);
  const compiled = iwRules();
  let found: { c: IwCompiled; start: number; end: number }[] = [];
  for (const c of compiled) {
    const m = c.re.exec(t);
    if (m) found.push({ c, start: m.index, end: m.index + m[0].length });
  }
  // agent context: needs_context rules only count next to a context-category hit (v0.3)
  const ctxCats = new Set(IW_RULES.context_categories ?? []);
  const hasContext = found.some((f) => !f.c.rule.needs_context && ctxCats.has(f.c.rule.category));
  if (!hasContext) found = found.filter((f) => !f.c.rule.needs_context);
  // same-category overlapping matches count once (heaviest wins, ties keep file order)
  const order = found.map((_, i) => i).sort((a, b) => (found[b].c.rule.weight - found[a].c.rule.weight) || (a - b));
  const kept: number[] = [];
  for (const i of order) {
    const f = found[i];
    if (kept.some((k) => found[k].c.rule.category === f.c.rule.category && f.start < found[k].end && found[k].start < f.end)) continue;
    kept.push(i);
  }
  kept.sort((a, b) => a - b);
  const hits = kept.map((i) => found[i]);
  const nonCounting = new Set(IW_RULES.non_counting_categories);
  let raw = hits.reduce((a, h) => a + h.c.rule.weight, 0);
  const cats = new Set(hits.map((h) => h.c.rule.category));
  const substantive = [...cats].filter((c) => c !== "ai_addressing" && !nonCounting.has(c));
  if (cats.has("ai_addressing") && substantive.length) raw += IW_RULES.combo_bonus;
  let factor = iwLocationFactor(location, inCode, techniques, discussion);
  let mention = false;
  if (hits.length) {
    const spans = iwAllMatches(iwQuoteRe!, t);
    if (spans.length) {
      const inside = (s: number, e: number) => spans.some(([qs, qe]) => qs <= s && e <= qe);
      const allQuoted = hits.every((h) => iwAllMatches(h.c.reAll, t).every(([s, e]) => inside(s, e)));
      let outside = "", pos = 0;
      for (const [s, e] of spans) { outside += t.slice(pos, s); pos = e; }
      outside += t.slice(pos);
      if (allQuoted && outside.replace(/\s+/g, "").length >= IW_RULES.mention_min_outside_chars) {
        mention = true;
        factor *= IW_RULES.mention_factor;
      }
    }
  }
  const score = Math.round(raw * factor * 1000) / 1000;
  const single = new Set(IW_RULES.single_count_categories ?? []);
  let counting = hits.filter((h) => !nonCounting.has(h.c.rule.category) && !single.has(h.c.rule.category)).length;
  for (const c of single) if (cats.has(c)) counting++;
  const blob = hits.length > 0 && !cats.has("ai_addressing") && iwIsBlob(t);
  const fired = score >= IW_RULES.threshold && (hits.some((h) => h.c.rule.standalone) || counting >= 2) && !blob;
  let intent = "manipulative";
  if ([...cats].some((c) => IW_MALICIOUS.has(c))) intent = "malicious";
  else if ([...cats].some((c) => IW_MANIPULATIVE.has(c))) intent = "manipulative";
  else if (cats.has("agent_promotion")) intent = "promotional";
  else if (cats.has("ai_restriction") || cats.has("ai_optout")) intent = "defensive";
  const category = IW_PRIORITY.find((c) => cats.has(c)) ?? "other";
  const severity = intent === "defensive" && category === "ai_optout" ? "ai_optout" : intent;
  return { score, fired, intent, severity, category, mention, rules: hits.map((h) => h.c.rule.id) };
}

function iwIsDiscussion(visibleTexts: string[]): boolean {
  iwRules();
  return iwDiscussionRe!.test(iwClean(visibleTexts.join(" ")));
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { iwClean, iwNormalize, iwHash, iwScore, iwExcerpt, iwDefang, iwDecodeTagRuns, iwHasZeroWidthObfuscation, iwIsDiscussion };
}
