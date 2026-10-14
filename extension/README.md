# InjectionWatch browser extension (Manifest V3)

Runs the same hidden-text extraction as the crawler (`injectionwatch/js/hidden_text.js`) and the same
rules (`injectionwatch/data/rules.json`, bundled as data) **locally in your browser**. It shows a red
badge with the number of injection-like findings on the current page. A test checks that the
TypeScript scorer matches the Python scorer exactly on every fixture candidate
(`tests/test_rules.py`).

## Build, check, package

```
python3 scripts/make_icons.py          # once; writes extension/icons/*.png (no dependencies)
cd extension
npm run build                          # tsc (strict) -> dist/, copies assets, runs check-dist.mjs
npm run package                        # zip of dist/ for the Chrome Web Store
```
`check-dist.mjs` fails the build if any of these hold:

* a manifest reference is missing
* an icon is not a PNG of its declared size
* a script uses `eval` / `new Function` / remote imports, or an HTML page has an inline or remote `<script>`
* `innerHTML` is assigned anywhere
* an unexpected permission or a non-`'self'` extension CSP is present

To load it unpacked: open `chrome://extensions`, turn on Developer mode, click *Load unpacked* and select `extension/dist`.

## Store-listing notes

* **Single purpose:** detect hidden text on web pages that targets AI agents.
* **Permissions:** `storage` (settings). A content script runs on http/https pages so it can scan the
  page locally. An *optional* host permission covers only the report endpoint the user configures.
* **Remote code:** none. Rules ship inside the package.
* **Privacy policy:** `privacy.html` is bundled and linked from the popup and options. Publish the
  same text at a public URL for the store listing.
* **Data use disclosure:** with the default settings no user data is collected. Opt-in reports send
  "website content" in the form of a URL path plus a hash; see below.

## Privacy: what is and is not sent

Scanning is 100% local. Nothing is sent unless **all** of these are true:

1. you enabled reporting on the **Options** page and saved an https endpoint (off and empty by default;
   Chrome then asks for permission to contact that one origin);
2. you clicked *Report* on a specific finding in the popup;
3. you confirmed the dialog that shows the exact JSON about to be sent;
4. the tab is not incognito.

| Sent (per report) | Never sent |
|---|---|
| `url` = scheme + host + path (query and fragment dropped; URLs with user:pass refused) | page HTML or text, the payload excerpt |
| `payload_hash` = sha256 of the normalized payload | cookies, auth headers (`credentials: "omit"`), referrer |
| `category`, `technique` (enum-like strings) | browsing history, other tabs, form contents |
| `extension_version` | any identifier for you or your browser |

The server strips query strings again, does not store client IPs, and keeps submissions in a separate
`submissions` table marked **unverified**. They are leads only. Nothing enters the public feed until the
project's crawler independently fetches the public URL (logged out) and observes the payload again.
