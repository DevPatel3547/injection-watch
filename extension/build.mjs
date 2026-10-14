// Copies static files + the shared Python-package assets into dist/ (tsc has already emitted the .js files).
import { readFileSync, writeFileSync, copyFileSync, mkdirSync, existsSync } from "node:fs";

mkdirSync("dist/icons", { recursive: true });
const rules = JSON.parse(readFileSync("../injectionwatch/data/rules.json", "utf8"));
// Rules are bundled as DATA (a JSON literal), never fetched or evaluated at runtime.
writeFileSync("dist/rules.js", "var IW_RULES = " + JSON.stringify(rules) + ";\n");
copyFileSync("../injectionwatch/js/hidden_text.js", "dist/hidden_text.js");
for (const f of ["manifest.json", "popup.html", "options.html", "privacy.html", "ui.css"]) copyFileSync(f, "dist/" + f);
for (const s of [16, 32, 48, 128]) {
  const src = `icons/icon${s}.png`;
  if (!existsSync(src)) { console.error(`missing ${src} (run: python3 scripts/make_icons.py)`); process.exit(1); }
  copyFileSync(src, `dist/icons/icon${s}.png`);
}
console.log("extension built in dist/");
