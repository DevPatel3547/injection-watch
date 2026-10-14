// Content script: extracts hidden / machine-targeted text locally, scores it, and tells the
// background worker how many findings there are. NOTHING leaves the browser from here.

const IW_TEXT_ATTRS = ["alt", "title", "aria-label", "aria-description", "placeholder"];

function iwCollect(): IwCandidate[] {
  const cands: IwCandidate[] = injectionwatchHiddenText(document).candidates.slice();
  // comments
  const w = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT);
  let n: Node | null;
  while ((n = w.nextNode())) {
    const t = (n.nodeValue || "").trim();
    if (t) cands.push({ text: t, location: "comment", techniques: ["html_comment"], path: "<!-- -->" });
  }
  // meta + title
  document.querySelectorAll("meta[content]").forEach((m) => {
    const key = m.getAttribute("name") || m.getAttribute("property") || m.getAttribute("http-equiv") || "?";
    const c = m.getAttribute("content") || "";
    if (c.trim()) cands.push({ text: c, location: "meta", techniques: [`meta[${key.toLowerCase()}]`], path: `meta[${key}]` });
  });
  // attributes
  document.querySelectorAll("*").forEach((el) => {
    for (const a of IW_TEXT_ATTRS) {
      const v = el.getAttribute(a);
      if (v && v.trim().length >= 12) cands.push({ text: v, location: "attribute", techniques: [`${el.tagName.toLowerCase()}@${a}`], path: el.tagName.toLowerCase() });
    }
  });
  // JSON-LD
  document.querySelectorAll('script[type*="ld+json"]').forEach((s) => {
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
  for (const t of iwDecodeTagRuns(document.documentElement.outerHTML)) {
    cands.push({ text: t, location: "invisible_unicode", techniques: ["unicode_tags"], path: "U+E00xx" });
  }
  for (const c of cands) if (iwHasZeroWidthObfuscation(c.text) && !c.techniques.includes("zero_width")) c.techniques.push("zero_width");
  return cands;
}

async function iwScan(): Promise<void> {
  const cands = iwCollect();
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
  chrome.runtime.sendMessage({ type: "iw-findings", findings });
}

iwScan();
setTimeout(iwScan, 3000); // one re-scan for client-rendered pages
