# Changelog

All notable changes to InjectionWatch. Dates are UTC.

## 0.4.0 (2026-11-09)

### Security and privacy
- **Real-web data re-redacted.** The committed sample hid the five affected hosts but still carried
  Common Crawl WARC names and offsets, full URL paths, exact capture times, a unique DOM path, and payload
  text naming a person, a firm, an app and a merchant. All of that is removed or reduced, and quoted page
  text no longer includes contact details. `tests/test_redaction.py` checks every tracked file
  structurally.
- **Disclosure holds when publishing.** A private hold file (`--hold FILE` or `$INJECTIONWATCH_HOLD_FILE`)
  makes `publish`, `export` and the HTTP API emit held sites only in redacted form. A missing hold file
  fails closed. Scan inputs (WARC names) are no longer published.
- `docs/threat-model.md`. Tests now cover rule regexes on adversarial floods and the dashboard rendering
  hostile feed text as text.

### Measurement and detection
- **IW-Bench** (`injectionwatch bench data|run`, `make bench-data`, `make bench`): recall on public injection
  datasets (InjecAgent, BIPIA, AgentDojo, Open-Prompt-Injection, greshake/llm-security, Lakera PINT
  examples) planted into real article pages with 25 hiding techniques, plus false-positive rates on
  unmodified real pages, benign hidden UI text and pages that discuss prompt injection. Sources are pinned
  git commits fetched at runtime. The v0.3 baseline was committed before any detector change.
- Results (test split, static + CSS): hidden-payload recall **12.4% → 33.2%**, 0/174 real pages flagged
  before and after. Rendered: 13.7% → 34.5%. BIPIA text attacks remain at 0%.
- Held-out v3 (`fixtures_holdout_v3/`, frozen before the v0.4 changes): recall 0.12 → 0.35, precision
  0.43 → 0.69. Its 4 false positives are not fixed. Held-out v2 is unchanged.
- Rules 0.4.0 (110 rules): paired weak signals for agent-directed requests (acting on "my" accounts or
  devices, sending to an address, moving money, injecting a code block into the reader's output, code that
  sends data out; each needs a second signal), the AgentDojo and misspelled-override templates.
- New extraction channels: prose-like inline-script strings (lower weight), CSS `::before`/`::after`
  `content`, `iframe srcdoc` (recursive), SVG `title`/`desc`.
- **Learned second stage, off by default (a negative result).** A hashed n-gram logistic regression
  (`injectionwatch/ml.py`, pure Python; `extension/src/ml.ts` matches it in a parity test; trained by
  `scripts/train_ml.py` with the `[train]` extra). It reaches 58.8% bench recall within-dataset, but only
  3.6% on a dataset it was not trained on, so it is opt-in (`scan_html(..., ml=True)`).
- Real-web recall tooling for the next crawl: `scripts/scan_cc.py --near-miss-sample N --public-out DIR`
  (strips locators and redacts held hosts), `scripts/sample_near_misses.py`, `scripts/label_stats.py
  --near-misses` (recall estimate) and `--kappa` (two-annotator agreement), and an offline labelling page
  `scripts/label_ui/`.

### Agent side (new)
- `injectionwatch.guard`: `fetch` (SSRF-safe: private, loopback, link-local and reserved addresses refused
  incl. IPv6/IPv4-mapped/NAT64 and legacy numeric hosts; connects to the vetted IP; every redirect
  re-vetted; 5 MB cap measured after decompression; HTML/text only; one total deadline), `sanitize`,
  `sanitize_text`, `scan_html`, `scan_text`. `safe_fetch()` is kept as a wrapper.
- `wrap_tool` decorator for any tool returning HTML or text, and a LangChain integration
  (`InjectionWatchTransformer`, `GuardedLoader`, `guard_tool`, `fetch_url_safely_tool`).
- MCP server: new `fetch_url_safely` and `scan_text` tools, tested end to end over stdio with the real MCP
  client.
- CLI: `guard`, `scan-site` (SARIF 2.1.0, `--fail-on`), `doctor`, global `--debug`, one-line errors with
  hints.
- Composite GitHub Action (`action.yml`) for site owners, self-tested in CI.

### LLM stage
- **Fixed:** with anthropic SDK 2.x every `--classifier anthropic` call raised TypeError (the
  `temperature` argument) and silently fell back to the heuristic classifier. A test now binds the exact
  request arguments to the installed SDK.
- The classifier has its own retry policy (`retry-after`, `retry-after-ms`, HTTP-date), a total deadline, and
  a breaker on 401/403/404. A mid-stream error event is retried. The fallback reason is recorded.
- `tool_choice` defaults to forcing the classification tool for every model. You can set it
  (`INJECTIONWATCH_TOOL_CHOICE=auto`), and the classifier switches to auto by itself if the API rejects
  forced tool use.
- Tested against local fake servers that speak the Anthropic Messages and OpenAI chat-completions wire
  formats (streaming, tool use, 429/529, timeouts). New `make demo-live` (asks before spending) and
  `make demo-live-fake`.

### Install, platforms, CI
- CI covers ubuntu and macOS on Python 3.11–3.13, Windows on Python 3.12, lint/types, Docker, and the
  Action.
- `.gitattributes` keeps LF checkouts, so the frozen held-out manifest matches on Windows.
- The extension builds with `npm ci` (TypeScript pinned in a lockfile, no global `tsc`). `collect.ts` is
  shared by the content script and the site.
- `INJECTIONWATCH_CHROMIUM` points the rendered pass at any Chromium or Chrome binary.
- New extras `langchain`, `train` and `all`. `make doctor`.
- The static CSS cascade's selector budget is counted in work, not wall-clock time, so the same page gives
  the same findings on any machine.
- `make demo` writes to `build/` and leaves the tree clean.

### Removed
- `docs/INTERVIEW_GUIDE.md` and `docs/maintainer-notes.md` (study notes, not project documentation).

## 0.3.0 (2026-10-12)

First public release: the static and rendered detector, 101 rules in 10 languages, Common Crawl WARC
scanner, real-web sample of 426,318 pages (7 reviewed true positives, precision 0.44), JSON/CSV/STIX feed,
static site, HTTP API, MCP server and MV3 extension. See `docs/BUILD_LOG.md`.
