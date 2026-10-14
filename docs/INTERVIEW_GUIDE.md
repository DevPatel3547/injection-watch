# Interview guide

Questions an engineer or researcher is likely to ask about InjectionWatch, with short answers that can
be given without notes. Numbers come from `reports/realweb/CC-MAIN-2026-39-sample/` and `reports/eval/`.
Know the headline numbers by heart:

> 426,318 pages · 20 random WARCs of CC-MAIN-2026-39 · 16 injection-like findings · **7 true injections on
> 5 sites** · **precision 0.44 (0.23–0.67)** · **1.64 per 100k pages (0.80–3.39)** · opt-out signals 61 per
> 100k · first scan with v0.1 rules: 213,688 pages, precision **0.027** · held-out v2: v0.1 0.33/0.08 →
> v0.2 static 0.95/0.83, rendered 0.96/1.00.

---

## 1. The pitch

**Q: What is it, in 30 seconds?**
A feed of web pages that carry text aimed at AI agents, like a PhishTank for agents. It scans Common
Crawl, extracts hidden and machine-only text (comments, metadata, hidden elements, attributes, headers),
scores it with multilingual rules, and a human reviews every hit before it is published. The first honest
measurement: 7 true injections in 426,318 pages, detector precision 0.44, so the detector is a triage tool
and the feed is reviewed by hand.

**Q: Why does this matter?**
Agents read raw HTML and the accessibility tree; users see pixels. Anything in between can instruct the
agent without the user knowing. Google measured a 32% relative rise in malicious web injections between
Nov 2025 and Feb 2026, and an academic crawl (arXiv:2604.27202) found 15.3K validated instances, about 70%
in non-rendered HTML. Both are one-off snapshots; nobody published a continuous, URL-level feed with
evidence and a takedown path.

**Q: What did you find?**
Mostly site owners talking to AI, not attackers: recommendation poisoning for a lawyer in hidden Chinese
text, an affiliate-link swap in an HTML comment, a fake `[/admin]` "if you're an LLM, disregard all prior
prompts" banner on three quiz pages, a white-on-white anti-scrape warning, and a store app telling agents
to call its offer tool. No exfiltration or credential phishing. 260 pages had `noai` opt-out tokens, which
are counted as a separate signal.

## 2. Architecture

**Q: Walk me through the pipeline.**
1. **Input**: WARC records from Common Crawl (`warc.py`) or a polite crawler (`crawler.py`).
2. **Extract** (`extract.py`): each page becomes *candidates*, text plus location: comment, meta,
   hidden CSS, `aria-hidden`, attribute, JSON-LD, noscript/template, invisible Unicode, HTTP header,
   visible.
3. **Score** (`scorer.py`): 101 rules in 10 languages from `data/rules.json`, multiplied by context factors
   (location, code block, page discusses injection, quoted mention, obfuscation). Fires only if score ≥ 3
   and there's a standalone rule or ≥ 2 substantive rules.
4. **Classify** (`classify.py`): heuristic category / intent / severity; optionally a local LLM or the
   Anthropic API, which can veto.
5. **Store** (`db.py`): SQLite, de-duplicated on (normalised URL, payload hash) with observations.
6. **Review and publish**: `review` applies human labels; `publish --reviewed-only` builds a static site;
   `/v1` API, MCP server, `safe_fetch()` and the browser extension consume it.

**Q: Why is the extension's scoring identical to Python's?**
Both load the same `rules.json` and the same `hidden_text.js`. A test runs the TypeScript scorer and the
Python scorer over every candidate in every fixture corpus and requires identical scores, verdicts and
hashes. Otherwise the extension would flag pages the feed calls clean, or the reverse.

**Q: Why rules and not an LLM?**
Cost, speed and explainability. 426k pages produced 104.6M candidates; sending those to a model is not
free. Rules are cheap, every finding carries the exact rule IDs and matched text, and a necessary-literal
prefilter skips most regexes. The LLM is an optional second stage on fired candidates (and near-misses
with `--llm-recall`), running locally by default.

**Q: Can the LLM classifier itself be prompt-injected?**
Yes, it reads attacker text. Mitigations: snippets are wrapped as `<untrusted_snippet>`, output is forced
into an enum and validated, and the model can only veto or label a finding, not create actions. That
reduces the risk; it doesn't eliminate it.

**Q: What is the necessary-literal prefilter?**
For each regex, derive a literal substring that every match must contain (the RE2/Hyperscan idea). If the
literal is absent, skip the regex. It's exact, not heuristic: a test asserts gated and ungated scoring give
identical results on every fixture candidate.

## 3. Static vs rendered

**Q: Why scan static HTML instead of rendering pages?**
* Common Crawl stores HTML and headers, not a rendered DOM, and rarely the CSS.
* Rendering costs far more per page; a static scan of 426k pages took about 2 hours on a laptop.
* The arXiv study found about 70% of payloads in non-rendered HTML (comments, headers, metadata), which a
  static scan sees fully.

**Q: What does static miss?**
Text hidden by an external stylesheet and text inserted by JavaScript. On held-out v2 that's exactly the
gap: static recall 0.83 (4 misses: 3 external-CSS, 1 JS), 0.96 with linked CSS supplied, 1.00 rendered.
The plan is to re-render only candidate URLs (hits and near-misses), not the whole crawl.

**Q: How do you decide what is "hidden" statically?**
A static cascade over inline `<style>` blocks (and external sheets if supplied) with real selector
matching (soupsieve) and `!important`, plus inline styles: display:none, visibility, opacity, zero font,
zero size, off-screen, clip, colour matching the background, transparent text. It's an approximation:
no full inheritance, no pseudo-elements, and a budget on complex selectors.

## 4. The WARC pipeline

**Q: How does `scan-warc` work?**
* `warcio` streams one record at a time; only `response` records with HTTP 200 and HTML are scanned;
  payloads are capped at 2 MB and truncation is counted.
* The parent process does WARC framing; detection runs in a process pool with at most 4 × workers pages
  in flight, so memory is bounded.
* **Resumable**: the checkpoint is the byte offset of the first record not yet fully written. Results are
  written in file order, completed files are skipped, and re-processing a record doesn't inflate
  `seen_count` (observations are idempotent).
* **Provenance**: `first_seen`/`last_seen` are the WARC capture dates; JSONL output carries WARC file,
  record ID and offset, so anyone can fetch the exact capture.

**Q: How did you choose the sample?**
`scripts/scan_cc.py` picks WARC paths uniformly at random from the crawl's `warc.paths.gz` with a fixed
seed (20261012), excluding the 10 files of the first sample. Files are downloaded, scanned and deleted
one at a time, so disk use stayed under 2.5 GB.

**Q: Why the per-page timeout and error counters?**
Real HTML is hostile to parsers. In the second scan, malformed CSS numbers like `'.1.25'` raised
`ValueError` on 8 pages; they were counted with samples in `scan_stats.json` and the parser was fixed
afterwards. Two pages hit the 20 s timeout. Counting failures keeps the denominator honest.

## 5. Measurement: precision, recall, Wilson intervals

**Q: Define precision and recall here.**
Precision = of the findings the detector raised, the share a human judged to be real injections
(7/16 = 0.44). Recall = of all real injections on the scanned pages, the share the detector raised. In the
synthetic evaluation a true positive must also be at the **expected location**: finding a hidden payload
but calling it "visible" counts as a miss.

**Q: Why Wilson intervals?**
With small counts the normal (Wald) interval breaks: 0 successes gives a zero-width interval, and
intervals can leave [0, 1]. Wilson inverts the score test instead:

    centre = (p + z²/2n) / (1 + z²/n)
    half   = z · sqrt(p(1−p)/n + z²/4n²) / (1 + z²/n),    z = 1.96

So 7/16 gives 0.23–0.67, not ±0.24 around 0.44, and 0 malicious pages out of 426,318 still gives an
upper bound of 0.90 per 100k. Implemented in `scripts/label_stats.py`, with tests.

**Q: Is 7 true positives enough to say anything?**
Enough to bound things, not to rank them. The overall rate is 0.80–3.39 per 100k; the per-severity rates
overlap heavily. And the page-level intervals assume independent pages, which is false: 3 of the 5
manipulative pages are on one host. At host level there are 5 sites. The README says all of this next to
the numbers.

**Q: Why is recall not measured, and how would you measure it?**
Only pages the detector raised were labelled. Labelling random pages to find misses is hopeless at this
base rate: at 1.64 per 100k you'd expect one true injection per roughly 61,000 pages. Instead:
1. **Seeded canaries**: insert known payloads, in many techniques and languages, into real captured pages
   and measure the detection rate.
2. **Label a random sample of near-misses**: pages that matched a rule but stayed under the threshold
   (31,320 matched any rule; 337 crossed the threshold). Misses concentrate there.
3. **Re-render** candidate pages to estimate the external-CSS / JS gap.

**Q: So what does "1.64 per 100k" mean?**
A **lower bound** on what a static, rule-based scan of this crawl can see: recall is unknown, external-CSS
and JS payloads are invisible, rules are lexical, and Common Crawl isn't a uniform sample of the web.

**Q: Why did precision fall from 0.95 to 0.027?**
The synthetic negatives were imagined; the real ones weren't. In the first real scan's labelled sample of
150, 75 benign findings were `noai` robots tokens and 37 were hidden login / sign-up / password-reset
modals where "email ... password" tripped the exfiltration rule. Vocabulary isn't intent. v0.3 made opt-out
a separate signal and required **agent context** (text that addresses an AI, or an override, role token or
concealment) before credential or policy phrasing counts. On a fresh sample, precision was 0.44.

**Q: How do you keep yourself honest about evaluation?**
* Held-out v2 was written and **frozen with a SHA-256 manifest** (checked by a test) before any v0.2
  tuning, and the v0.1 result on it (0.33 / 0.08) was recorded first.
* Tuning happened on separate dev corpora.
* Sets are declared **burned** once their failures shape the design (held-out v1), and partial loss of
  independence is stated (v0.3's fix for `n16` touches a class in held-out v2).
* The real-web regression corpus is labelled **in-sample**; the published precision comes from a **fresh**
  sample that was not used for tuning, and its 9 false positives were left unfixed.

## 6. Why the feed needs human review

**Q: Why not publish what the detector finds?**
At precision 0.44, more than half of the published entries would be false accusations against real sites.
A false listing can hurt a site owner, and an untrustworthy feed is useless to consumers. So the detector
is triage and a human is the classifier: `injectionwatch review` applies labels, `publish --reviewed-only`
ships only reviewed true positives, and every entry keeps its `reasons` so a reviewer or appellant can see
why it fired.

**Q: Doesn't that limit scale?**
Yes, to the reviewer's throughput. That's the honest trade. Ways to scale: template clustering (review one
template, apply to all hosts carrying it), a local LLM pre-screen, a second annotator for agreement, and
better precision from regression fixtures.

## 7. SSRF safety of `/v1/check`

**Q: Your API takes a URL. Why isn't that an SSRF hole?**
Because `/v1/check` is a **pure lookup**. It validates the URL as data (http/https only, no credentials,
no control characters, valid IDNA host and port, length limit) and looks up the normalised URL in the
database. It never resolves DNS or opens a connection. A test patches `socket.create_connection` and
`socket.getaddrinfo` to raise, then checks cloud-metadata (`169.254.169.254`), loopback, `[::1]` and
`localhost` URLs return `unknown` without any network access. `SECURITY.md` lists "a way to make `/check`
fetch" as an in-scope bug.

**Q: What about `/v1/submit`?**
It stores extension leads (URL with query stripped, hash, category) as **unverified** and fetches nothing.
Verification is an operator-run job (`verify-submissions`) using the polite crawler: own UA, robots.txt,
per-host delay, logged out.

**Q: How else could the feed be an attack surface?**
The feed is full of attacker-written text aimed at LLMs. So: excerpts truncated to 200 characters, URLs
defanged, `/check` and lookup shards omit excerpts unless asked, every export carries an "untrusted" warning,
the dashboard renders text only with `textContent` under a strict CSP, the MCP tools return metadata or
labelled excerpts, and CSV export is formula-injection safe.

## 8. Privacy design of the extension

**Q: What does the extension send?**
Nothing by default. It scans locally with the bundled rules. A report is sent only if the user (1) turned
on reporting and saved an https endpoint (Chrome then asks for that one origin), (2) clicked *Report* on a
finding, (3) confirmed a dialog showing the exact JSON, and (4) is not in incognito. The report holds the
URL without query string or fragment (URLs with credentials refused), the payload hash, category,
technique and extension version. Never page text, the excerpt, cookies (`credentials: "omit"`), the
referrer or any identifier.

**Q: Why hashes instead of text?**
The hash identifies the payload well enough for the crawler to confirm it (same normalisation in Python
and TypeScript), without shipping page content, which could contain personal data. Reports are leads;
nothing enters the feed until the crawler re-observes the payload on the public, logged-out page.

**Q: How do you keep it store-safe?**
Only the `storage` permission and an optional host permission; extension CSP `script-src 'self'`; no
remote code. `check-dist.mjs` fails the build on `eval`/`new Function`, remote imports, inline scripts,
`innerHTML`, unexpected permissions, missing manifest references or wrong-size icons.

**Q: And the server side?**
No client IPs stored; rate-limit keys and logs use a salted hash; logs never contain query strings, so a
URL someone checked is never written to a log.

## 9. Ethics

**Q: Isn't publishing URLs of sites with injections a form of shaming?**
It can be, so the rules are: quote only enough to show the technique, truncate and defang, leave out site
and person names in reports, and treat compromised sites as victims. For anything that looks like a
compromise, notify the owner privately and hold publication for 14 days (up to 90 if they engage). Anyone
can appeal through an issue template with a re-check within 7 days; upheld appeals become `suppressed`
and a benign look-alike fixture is added. In this sample all seven true positives appear to be written by
the site operators themselves.

**Q: What about the data source?**
Common Crawl's public captures: no requests to the sites, no logins, no paywalls, no forms. The optional
crawler identifies itself, honours robots.txt (403 means disallow, 5xx means stay away), waits 5 s per
host and never rotates identities. When the first crawl hit blocked egress, the circuit breaker stopped it
after 8 failures instead of retrying.

**Q: Cloaking checks send other bots' user agents. Is that OK?**
It's the one exception, and it's constrained: candidate URLs only, very low volume, robots.txt honoured for
the impersonated token, and UA-only (IP-verified bots can't be impersonated and we don't try). The UA
strings were written offline; the ones marked `approximate` must be checked against vendor docs first.

## 10. What's next

**Q: If you had another month?**
1. **Recall**: seeded canaries and a labelled near-miss sample.
2. **A second annotator** and inter-rater agreement; more WARCs for tighter intervals.
3. The 9 false-positive templates from the fresh sample as regression fixtures, and a held-out v3 written
   before the next tuning round.
4. **Re-render candidates** in Chromium to close the external-CSS / JS gap.
5. **Template clustering** across hosts (app templates like the offer-button one can appear on many stores),
   which also scales review.
6. Benchmark local models as the stage-2 classifier and calibrate confidence (today it's a scaled rule
   score, not a probability).
7. Activate the monthly publish job; signed releases; TAXII 2.1.

**Q: What would you do differently?**
Collect real negatives before writing rules. The synthetic held-out set measured generalisation across
*my* phrasings, not across the web; a small real sample on day one would have shown the login-modal and
`noai` templates immediately.

**Q: How did you use AI tools to build it?**
Answer specifically and honestly: Claude was a pair-programmer that helped write code, tests, fixtures and
documentation; you are the author and you were the sole reviewer of every real-web
label (stated in the report and the README's "How this was built" section). Be ready to explain any file
in the repo without the AI, because that is what the follow-up questions will test.
