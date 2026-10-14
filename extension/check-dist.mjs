// Store-readiness checks for dist/: every file the manifest references exists, icons are real PNGs of
// the declared size, no remote code (no remote script URLs, eval, new Function, remote imports), and
// the manifest stays within Chrome Web Store limits. Exits non-zero on any problem.
import { readFileSync, existsSync, readdirSync } from "node:fs";

const problems = [];
const m = JSON.parse(readFileSync("dist/manifest.json", "utf8"));
const need = (p, why) => { if (!existsSync("dist/" + p)) problems.push(`missing ${p} (${why})`); };

if (m.manifest_version !== 3) problems.push("manifest_version must be 3");
if (!m.name || m.name.length > 75) problems.push("name missing or > 75 chars");
if (!m.description || m.description.length > 132) problems.push("description missing or > 132 chars");
if (!/^\d+(\.\d+){0,3}$/.test(m.version)) problems.push("bad version");
need(m.background.service_worker, "background");
need(m.action.default_popup, "popup");
need(m.options_ui.page, "options");
need("privacy.html", "privacy policy page");
for (const cs of m.content_scripts) for (const js of cs.js) need(js, "content script");
for (const [size, p] of Object.entries({ ...m.icons, ...m.action.default_icon })) {
  need(p, "icon");
  if (existsSync("dist/" + p)) {
    const b = readFileSync("dist/" + p);
    const png = b.slice(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
    const w = b.readUInt32BE(16), h = b.readUInt32BE(20);
    if (!png || w !== Number(size) || h !== Number(size)) problems.push(`${p} is not a ${size}x${size} PNG`);
  }
}
const perms = new Set(m.permissions || []);
for (const p of perms) if (!["storage"].includes(p)) problems.push(`unexpected permission ${p}`);
if (m.host_permissions && m.host_permissions.length) problems.push("no mandatory host_permissions expected");
const csp = (m.content_security_policy || {}).extension_pages || "";
if (!/script-src 'self'/.test(csp) || /unsafe-eval|http/.test(csp)) problems.push("extension_pages CSP must be script-src 'self' only");

for (const f of readdirSync("dist").filter((f) => f.endsWith(".js") || f.endsWith(".html"))) {
  const src = readFileSync("dist/" + f, "utf8");
  if (/\beval\s*\(|new\s+Function\s*\(|importScripts\s*\(|\bimport\s*\(\s*["'`]https?:/.test(src)) problems.push(`${f}: dynamic code`);
  if (/<script[^>]+src=["']https?:/i.test(src)) problems.push(`${f}: remote script`);
  if (/<script(?![^>]*\bsrc=)[^>]*>/i.test(src)) problems.push(`${f}: inline script (blocked by MV3 CSP)`);
  if (/\.innerHTML\s*=/.test(src)) problems.push(`${f}: innerHTML assignment`);
}
if (problems.length) { console.error("dist check FAILED:\n - " + problems.join("\n - ")); process.exit(1); }
console.log("dist check OK: " + readdirSync("dist").length + " entries, MV3, no remote code");
