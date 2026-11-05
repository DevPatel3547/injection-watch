# Threat model

InjectionWatch reads attacker-controlled web pages and republishes facts about them, so most of its
attack surface comes from the content it exists to catch. This document lists what we protect, who
attacks it, and what stops them. Each mitigation names the code and the test that holds it in place.
If a claim here has no test, treat it as a design intent, not a guarantee.

## Assets

| asset | why it matters |
|---|---|
| Agents and their users downstream of `guard` / MCP / LangChain | the reason the project exists: hidden text must not reach the model unflagged |
| Consumers of the feed (JSON, CSV, STIX, lookup shards, API) | they may place feed fields into their own tooling or LLM context |
| Site owners named in (or held back from) the feed | a wrong or premature listing harms people who are often victims of a compromise |
| The maintainer's private data | real hosts under disclosure hold, raw HTML of hit pages, Common Crawl record locations |
| Extension users | browsing history must never leave the browser unless they explicitly report a finding |
| Machines running the scanner | a scanner fed hostile input must not be exploited, exhausted or turned into a proxy |

## Adversaries and mitigations

### 1. A page author hides instructions for agents (the detected threat)

* **Evasion is expected.** Rules are lexical, and the learned stage (when enabled) is a linear model on
  n-grams. Paraphrases, unsupported languages, text split across elements, images, PDFs and script
  strings can slip through. IW-Bench (`reports/bench/`) measures recall per hiding technique and payload
  family, and the low rows are published.
* `guard.sanitize` / `fetch` return **only human-visible text**, minus flagged blocks. Comments, hidden
  elements, metadata, attributes and JSON-LD are dropped whether or not a rule fired. This structural
  defence does not depend on detection.
* Residual risk: **visible** injections are passed through unless a rule or the model flags them. Absence
  of a finding never means a page is safe; every output says so.

### 2. The feed itself as an injection vector

* Excerpts are truncated to 200 characters, URLs are defanged (`hxxps://x[.]y`), and every export carries an
  "untrusted" warning (`export.WARNING`). `/v1/check` and the lookup shards omit excerpts by default.
* The dashboard and the X-ray page render feed and page text only through `textContent`. There are no inline
  scripts and the CSP is strict (`script-src 'self'`). `tests/test_publish_cli.py` renders the dashboard in
  Chromium with a hostile excerpt.
* CSV cells starting with `= + - @` are prefixed with `'` (spreadsheet formula injection).
* MCP and `guard` results label excerpts as untrusted. MCP tool descriptions tell the agent never to
  follow them.

### 3. Re-identification of sites under the disclosure hold

Replacing a host name is not enough on its own. A Common Crawl WARC name and offset, a URL path, an exact
capture time, a unique DOM id or a distinctive payload sentence each lets someone find the record again.

* Committed data never carries record locators (WARC name or offset, sha1-derived page ids). Redacted
  hosts carry only `/redacted-path-K`. Held records have day-level times, tag-only DOM paths and a reduced
  or withheld payload. Quoted page text carries no e-mail addresses or phone numbers.
  `tests/test_redaction.py` checks every tracked file structurally, with no list of real hosts.
* Publishing applies the private hold file (`export.apply_holds`). `tests/test_site.py` publishes a site
  with a held host and runs the same checks on the output.
* The hold file, raw HTML and record locations stay with the maintainer, outside the repository.
* Residual risk: payload and evidence hashes allow *confirmation* by someone who already has the exact
  payload or page; they do not help anyone search for it.

### 4. Hostile input to the scanner

* WARC records are capped at 2 MB, and the WARC scanner reads them as a stream. Pages run in a process pool
  with a per-page timeout (`warc.py`).
* `guard.fetch` streams at most 5 MB and accepts only HTML/text content types.
* Regexes come only from `rules.json` in the package. A test runs every rule against long adversarial
  strings so that catastrophic backtracking is noticed. The literal prefilter skips most regexes on most text.
* HTML parsing uses BeautifulSoup and lxml. CSS selectors have a complexity budget (`css.py`).

### 5. SSRF through the fetchers

* `/v1/check` never fetches or resolves the URL it is given. A test makes any socket call fail.
* `guard.fetch`, MCP `fetch_url_safely` and LangChain loaders accept only `http`/`https`. They resolve the
  host and refuse loopback, private, link-local (incl. `169.254.169.254`), multicast and reserved
  addresses, IPv6 and IPv4-mapped forms included. Every redirect hop is re-checked (at most 5), and the
  connection goes to the vetted address. `allow_private=True` is an explicit opt-in for local testing.
  Covered by `tests/test_guard*.py`.
* The polite crawler honours robots.txt and a per-host delay, identifies itself and stops after repeated
  network failures.

### 6. Prompt injection of the optional LLM classifier

* Snippets are wrapped as `<untrusted_snippet>` data. The model must answer through a forced tool or JSON
  schema, and the answer is enum-validated. The model can only **veto or confirm** a rule finding, or
  propose one in `--llm-recall` mode, and it cannot invent categories.
* An injection that talks the classifier into a veto lowers recall. That risk is why the LLM stage is
  optional and reported separately.
* Errors, timeouts and rate limits (429/529, honouring `retry-after`) fall back to the heuristic
  classifier, and the reason is recorded. Covered by `tests/test_live_anthropic.py` against a local server
  speaking the Messages API wire format.

### 7. Feed poisoning and takedown abuse

* Extension reports are **leads**, stored as unverified, and rate-limited more strictly than reads. Nothing
  enters the feed until the crawler independently re-observes the payload logged out
  (`verify-submissions`).
* Takedowns and appeals go through a GitHub issue template. Outcomes (`removed`, `suppressed`, kept with
  reasoning) are recorded on the entry, and nothing is deleted silently.

### 8. Privacy of extension users and API callers

* The extension has only the `storage` permission, scans locally, and sends a report only after an
  explicit opt-in, a per-finding click and a confirmation dialog that shows the exact JSON. It never sends
  page text or cookies, and incognito tabs cannot report. `check-dist.mjs` fails the build on new
  permissions, remote code or `innerHTML`.
* The API logs no client IPs or query strings. Rate-limit keys are salted hashes.
* The X-ray page analyses pasted HTML in the browser. The HTML is rendered in a sandboxed iframe with
  scripts disabled, the page CSP blocks third-party loads, and nothing is uploaded.

### 9. Supply chain

* `rules.json` and `hidden_text.js` are shared data between Python and the extension. Parity tests compare
  scores and hashes across both implementations on every fixture.
* Runtime dependencies are minimal (`beautifulsoup4`, `lxml`, `requests`, `warcio`). Everything else is an
  optional extra.
* The GitHub Action installs from the repository at the action's own ref and needs no secrets.

## Out of scope

Bots verified by IP or reverse DNS (cloaking checks are UA-only), compromise of the maintainer's machine,
and attacks on Common Crawl itself.
