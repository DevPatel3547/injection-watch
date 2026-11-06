// Candidate collection and scoring for a Document, with no extension (browser-namespace) APIs, so the same code runs in the
// extension's content script and in the public site's X-ray playground (on a DOMParser document).
// Classic script (globals), loaded after rules.js, hidden_text.js and scorer.js.

const IW_TEXT_ATTRS = ["alt", "title", "aria-label", "aria-description", "placeholder"];

function iwCollect(doc: Document): IwCandidate[] {
  const cands: IwCandidate[] = injectionwatchHiddenText(doc).candidates.slice();
  const root = doc.documentElement;
  if (!root) return cands;
  // comments
  const w = doc.createTreeWalker(root, NodeFilter.SHOW_COMMENT);
  let n: Node | null;
  while ((n = w.nextNode())) {
    const t = (n.nodeValue || "").trim();
    if (t) cands.push({ text: t, location: "comment", techniques: ["html_comment"], path: "<!-- -->" });
  }
  // meta + title
  doc.querySelectorAll("meta[content]").forEach((m) => {
    const key = m.getAttribute("name") || m.getAttribute("property") || m.getAttribute("http-equiv") || "?";
    const c = m.getAttribute("content") || "";
    if (c.trim()) cands.push({ text: c, location: "meta", techniques: [`meta[${key.toLowerCase()}]`], path: `meta[${key}]` });
  });
  // attributes
  doc.querySelectorAll("*").forEach((el) => {
    for (const a of IW_TEXT_ATTRS) {
      const v = el.getAttribute(a);
      if (v && v.trim().length >= 12) cands.push({ text: v, location: "attribute", techniques: [`${el.tagName.toLowerCase()}@${a}`], path: el.tagName.toLowerCase() });
    }
  });
  // JSON-LD
  doc.querySelectorAll('script[type*="ld+json"]').forEach((s) => {
    try {
      const walk = (o: unknown): void => {
        if (typeof o === "string") { if (o.length >= 20) cands.push({ text: o, location: "jsonld", techniques: ["json-ld"], path: "ld+json" }); }
        else if (Array.isArray(o)) o.forEach(walk);
        else if (o && typeof o === "object") Object.values(o as Record<string, unknown>).forEach(walk);
      };
      walk(JSON.parse(s.textContent || ""));
    } catch { /* ignore malformed */ }
  });
  // Unicode tag smuggling
  for (const t of iwDecodeTagRuns(root.outerHTML)) {
    cands.push({ text: t, location: "invisible_unicode", techniques: ["unicode_tags"], path: "U+E00xx" });
  }
  for (const c of cands) if (iwHasZeroWidthObfuscation(c.text) && !c.techniques.includes("zero_width")) c.techniques.push("zero_width");
  return cands;
}

// Score the collected candidates (same rules and dedupe as the Python detector's stage 1).
async function iwScanCandidates(cands: IwCandidate[]): Promise<IwFinding[]> {
  const discussion = iwIsDiscussion(cands.filter((c) => c.location === "visible").map((c) => c.text));
  const findings: IwFinding[] = [];
  const seen = new Set<string>();
  for (const c of cands) {
    const r = iwScore(c.text, c.location, !!c.in_code, c.techniques, discussion);
    if (!r.fired) continue;
    const h = await iwHash(c.text);
    if (seen.has(h + c.location)) continue;
    seen.add(h + c.location);
    findings.push({ payload_hash: h, category: r.category, intent: r.intent, location: c.location,
      technique: c.techniques[0] || c.location, score: r.score, excerpt: iwExcerpt(c.text), rules: r.rules });
  }
  return findings;
}

async function iwScanDocument(doc: Document): Promise<IwFinding[]> {
  return iwScanCandidates(iwCollect(doc));
}

if (typeof module !== "undefined" && module.exports) module.exports = { iwCollect, iwScanCandidates, iwScanDocument };
