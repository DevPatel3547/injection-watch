// InjectionWatch static dashboard. No dependencies, no inline script, no innerHTML with data:
// every value from the feed (attacker-controlled excerpts included) goes through textContent.
"use strict";

const TRACKING = new Set(["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "gclid", "fbclid"]);
const PAGE = 50;
const state = { entries: [], filtered: [], page: 0, shardKeys: null };

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = String(text);
  if (cls) e.className = cls;
  return e;
}
function fmtInt(n) { return Number(n || 0).toLocaleString("en-US"); }
function day(iso) { return (iso || "").slice(0, 10); }

// Mirrors injectionwatch.db.normalize_url (scheme/host lower-cased, IDN -> punycode by URL(),
// default port dropped, fragment dropped, tracking params dropped, query sorted).
function normalizeUrl(raw) {
  const u = new URL(raw.trim());
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("only http(s) URLs");
  let host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (u.port) host += ":" + u.port;
  const params = [...u.searchParams.entries()].filter(([k]) => !TRACKING.has(k.toLowerCase()));
  params.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  const q = new URLSearchParams(params).toString();
  const path = u.pathname || "/";
  return { host, norm: u.protocol + "//" + host + path + (q ? "?" + q : ""), path };
}

async function sha256hex(s) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function checkUrl(raw) {
  const out = document.getElementById("check-result");
  out.replaceChildren();
  let n;
  try { n = normalizeUrl(raw); } catch (e) { out.append(el("div", "Not a valid http(s) URL.", "verdict neutral")); return; }
  if (!window.crypto || !crypto.subtle) { out.append(el("div", "This browser context cannot compute SHA-256 (needs HTTPS).", "verdict neutral")); return; }
  const key = (await sha256hex(n.host)).slice(0, 2);
  let hosts = {};
  // meta.json lists which shards exist, so absent hosts cost no request at all
  if (!state.shardKeys || state.shardKeys.has(key)) {
    try {
      const r = await fetch("lookup/" + key + ".json", { cache: "no-cache" });
      if (r.ok) hosts = (await r.json()).hosts || {};
    } catch (e) { /* offline: treat as not listed */ }
  }
  const list = hosts[n.host] || [];
  const exact = list.filter((e) => e.url_norm === n.norm);
  const samePath = list.filter((e) => e.url_norm.split("?")[0] === n.norm.split("?")[0]);
  const hits = exact.length ? exact : samePath;
  const flagged = hits.filter((e) => e.flagged);
  let box;
  if (flagged.length) {
    box = el("div", "", "verdict flagged");
    box.append(el("strong", "Flagged. "), el("span", flagged.length + " active entr" + (flagged.length === 1 ? "y" : "ies") +
      (exact.length ? " for this exact URL" : " for this path (different query string)") + ": " +
      [...new Set(flagged.map((e) => e.category))].join(", ") + ". Last seen " + day(flagged[0].last_seen) + "."));
  } else if (hits.length) {
    box = el("div", "Listed, but only with non-flagged (defensive/other) machine-targeted text.", "verdict neutral");
  } else if (list.length) {
    box = el("div", "This URL is not listed, but " + list.length + " entr" + (list.length === 1 ? "y" : "ies") +
      " exist for other pages on " + n.host + ".", "verdict neutral");
  } else {
    box = el("div", "Not listed. That only means it was not observed carrying an injection; it is not a safety verdict.", "verdict clear");
  }
  out.append(box);
}

function tiles(meta) {
  const s = meta.stats || {};
  const t = document.getElementById("tiles");
  const sig = meta.signals || {};
  const items = [
    [meta.count, meta.reviewed_only ? "published entries (human-reviewed)" : "published entries"],
    [meta.flagged, "flagged (malicious / manipulative)"],
    [meta.published_hosts, "hosts in feed"],
    [sig.ai_optout_entries, "AI opt-out signals (not injections)"],
    [s.urls_crawled, "URLs observed"],
  ];
  t.replaceChildren(...items.map(([v, k]) => { const d = el("div", "", "tile"); d.append(el("div", fmtInt(v), "v"), el("div", k, "k")); return d; }));
  const ml = document.getElementById("meta-line");
  ml.textContent = "Generated " + (meta.generated_at || "?") + " · feed v" + meta.version + " · rules v" + meta.rules_version +
    (meta.data_note ? " · " + meta.data_note : "");
}

function bars(id, counts) {
  const box = document.getElementById(id);
  const rows = Object.entries(counts || {}).sort((a, b) => b[1] - a[1]).slice(0, 10);
  if (!rows.length) { box.replaceChildren(el("p", "No data yet.", "empty")); return; }
  const max = rows[0][1] || 1;
  box.replaceChildren(...rows.map(([k, v]) => {
    const r = el("div", "", "bar-row");
    const track = el("div", "", "bar-track");
    const fill = el("div", "", "bar-fill");
    fill.style.width = Math.max(2, (100 * v) / max) + "%";
    track.append(fill);
    const lbl = el("span", k, "lbl"); lbl.title = k;
    r.append(lbl, track, el("span", fmtInt(v), "n"));
    return r;
  }));
}

function applyFilters() {
  const q = document.getElementById("q").value.trim().toLowerCase();
  const cat = document.getElementById("f-cat").value;
  const fl = document.getElementById("f-flag").value;
  state.filtered = state.entries.filter((e) => {
    if (cat && e.category !== cat) return false;
    if (fl && String(Number(!!e.flagged)) !== fl) return false;
    if (!q) return true;
    return [e.host, e.url, e.category, e.severity, e.intent, e.location, (e.techniques || []).join(" ")].join(" ").toLowerCase().includes(q);
  });
  state.page = 0;
  renderRows();
}

function renderRows() {
  const body = document.getElementById("rows");
  const start = state.page * PAGE;
  const slice = state.filtered.slice(start, start + PAGE);
  if (!slice.length) {
    const tr = el("tr"); const td = el("td", "No entries match.", "empty"); td.colSpan = 7; tr.append(td);
    body.replaceChildren(tr);
  } else {
    body.replaceChildren(...slice.map((e) => {
      const tr = el("tr");
      const intent = el("span", e.severity || e.intent, "pill" + (e.flagged ? " bad" : ""));
      const tdI = el("td"); tdI.append(intent);
      tr.append(el("td", e.host, "host"), el("td", e.category), tdI, el("td", e.location),
        el("td", Number(e.confidence || 0).toFixed(2), "num"), el("td", day(e.last_seen), "date"), el("td", e.payload_excerpt, "ex"));
      return tr;
    }));
  }
  const pages = Math.max(1, Math.ceil(state.filtered.length / PAGE));
  document.getElementById("page-info").textContent = "Page " + (state.page + 1) + " of " + pages + " · " + fmtInt(state.filtered.length) + " entries";
  document.getElementById("prev").disabled = state.page === 0;
  document.getElementById("next").disabled = state.page >= pages - 1;
}

async function main() {
  document.getElementById("check-form").addEventListener("submit", (ev) => { ev.preventDefault(); checkUrl(document.getElementById("check-url").value); });
  for (const id of ["q", "f-cat", "f-flag"]) document.getElementById(id).addEventListener("input", applyFilters);
  document.getElementById("prev").addEventListener("click", () => { state.page--; renderRows(); });
  document.getElementById("next").addEventListener("click", () => { state.page++; renderRows(); });
  try {
    const [meta, feed] = await Promise.all([fetch("meta.json").then((r) => r.json()), fetch("feed.json").then((r) => r.json())]);
    if (Array.isArray(meta.shard_keys)) state.shardKeys = new Set(meta.shard_keys);
    tiles(meta);
    bars("bars-severity", meta.published_by_severity);
    bars("bars-category", meta.published_by_category);
    bars("bars-location", meta.published_by_location);
    state.entries = feed.entries || [];
    const sel = document.getElementById("f-cat");
    for (const c of [...new Set(state.entries.map((e) => e.category))].sort()) sel.append(new Option(c, c));
    applyFilters();
  } catch (e) {
    document.getElementById("tiles").replaceChildren(el("p", "Could not load feed data.", "empty"));
  }
}

if (typeof module !== "undefined" && module.exports) { module.exports = { normalizeUrl }; } else { main(); }
