# Ethics, operations and takedown policy

InjectionWatch publishes URLs of real web pages together with evidence that the page carries text
aimed at AI agents. Publishing a URL can hurt a site owner, and the feed itself could become an attack
channel. This document lists the rules the project follows. Code and process both enforce them: tests
cover crawl politeness, payload truncation, URL stripping and the extension privacy model.

## 1. What we collect, and from where

| Source | What | Notes |
|---|---|---|
| Common Crawl WARC files (primary) | Already-public captures of public pages | We do not fetch anything for these. Each capture carries the Common Crawl date, and that date is our `first_seen`/`last_seen`. |
| Our own polite crawler (secondary) | Homepages from a public ranking list (Tranco) | See section 2. |
| Browser extension reports | Leads only: URL (scheme + host + path), payload hash, category | Never published until our crawler re-observes the payload logged out (section 6). |

We never collect content that requires an account, a login, a paywall bypass, a CAPTCHA solution or
any form submission.

## 2. Polite crawling

* **Identifies itself.** The User-Agent is `InjectionWatchBot/<version>` with a project URL and contact
  address (`injectionwatch/config.py`. **The contact placeholder must be filled in before any public crawl.**)
* **Honours robots.txt** for `InjectionWatchBot`. 401/403 on robots.txt means disallow. 5xx means stay
  away. 404 means allowed (standard semantics).
* **Rate limited.** At most one request per host every 5 s (configurable upward only in practice).
  Homepages only by default. Responses are capped at 2 MB.
* **No evasion.** We never rotate User-Agents or IP addresses to get around blocks, never solve
  challenges, and never retry 401/403/429/503 with a different identity. These responses are recorded and
  the crawler moves on. A circuit breaker stops the run when our egress is failing.
* **No logged-in scraping.** No cookies and no credentials are sent, and no forms are submitted.
* **Cloaking checks** are the one place we send other user-agent strings. To detect cloaking we fetch a
  page as a browser and as published AI-agent UAs. This runs only on candidate URLs, at very low volume,
  and honours robots.txt *for the impersonated token*. It is UA-only. Bots verified by IP or reverse DNS
  can't be impersonated, and we don't try. Some UA strings in `config.AGENT_UAS` are marked
  `approximate`. They still need checking against vendor documentation.

## 3. Payload handling (the feed must not become an attack vector)

* Excerpts are **truncated to 200 characters** and **URLs are defanged**
  (`https://evil.example` -> `hxxps://evil[.]example`).
* `/v1/check` and the static lookup shards omit excerpts by default (`include_payload=true` to opt in).
* Every export carries an explicit "untrusted, attacker-controlled text" warning. Consumers must not
  place excerpts in an LLM context without isolation. The dashboard renders them with `textContent` only.
* We do not store full page bodies. We keep a SHA-256 *evidence hash* of the captured body. Anyone with
  the same capture (for example, the Common Crawl record) can verify it.

## 4. False positives

The detector is precision-first and every entry carries `reasons`: the rule IDs, the matched text,
where on the page it was found and the context adjustments that applied. Known false-positive classes,
and how we handle them:

* **Educational and security content**: articles, quizzes and docs that *quote* injections. Pages that
  discuss prompt injection are down-weighted, quoted mentions (`"ignore previous instructions"`) are
  down-weighted, and so are code blocks.
* **Defensive notices** (`noai`, "AI training prohibited"). These are recorded with `intent=defensive` and
  never counted as `flagged`.
* **Research or test pages.** On appeal these are marked `disputed`/`suppressed`, and the page pattern is
  added to the fixture corpus as a benign look-alike so the regression test covers it.

Entries that a later capture no longer shows become `removed` automatically. They stay in history but
drop out of the default feed.

## 5. Takedown and appeal process

Anyone can ask for an entry to be reviewed. Site owners don't need an account anywhere except GitHub.

1. Open an issue with the **"Takedown / appeal"** template (`.github/ISSUE_TEMPLATE/takedown.yml`), or
   email the contact in `config.py` if you can't use GitHub. Include the URL or entry ID and say whether
   the payload was (a) removed, (b) never malicious or (c) placed by an attacker without your knowledge.
2. **Within 7 days** a maintainer re-checks: a fresh polite fetch of the public URL, logged out.
   * Payload gone -> `removed` (`injectionwatch status <id> removed --note "..."`).
   * False positive -> `suppressed`. The entry is hidden from every export, including
     `include_inactive`, and a benign look-alike fixture is added to the test corpus.
   * Payload still present and malicious -> the entry stays `active`. The issue records the reasoning,
     and the owner can appeal again after changing the page.
3. While a case is under review the entry can be set to `disputed`. Consumers can see this through
   the `status` field.
4. Decisions are published in the issue (minus anything private the requester asks us to omit).

These response times are a commitment of the project once it publishes. Until then they are targets.

## 6. Responsible disclosure for compromised sites

Many hidden injections are planted on sites that were **compromised** (CMS plugin vulnerabilities, injected
SEO spam, poisoned third-party widgets). The site owner is a victim, not an attacker. For entries that
look like third-party compromise (for example, a payload in a footer widget of an unrelated small business):

* Before first publication, where a security contact can be found (`/.well-known/security.txt`,
  `security@`, the hosting provider's abuse contact), we notify the owner privately and wait **14 days**.
  If the owner engages, we wait up to 90 days. Feed entries for that host are held back during that time.
* The notice includes the URL, the location of the hidden text (for example, an element path), the
  payload hash and the capture date, so the owner can find and remove it. It never includes exploit
  instructions.
* If there is no contact or no response, the entry is published normally and the owner can still use
  the takedown process.
* Mass campaigns, where the same payload template appears on many hosts, are reported to the affected
  CMS or plugin vendor and the relevant CERT, not only to individual sites.

## 7. Browser extension privacy

Scanning runs 100% locally. Nothing is sent unless the user has turned on reporting in the options page
(off by default), clicked *Report* on a specific finding and confirmed a dialog that shows the exact JSON.
A report contains the URL without its query string or fragment, the payload hash, the category, the
technique and the extension version. It never contains page text, the excerpt, cookies or identifiers.
Reports from incognito windows are refused. See `extension/privacy.html`.

## 8. Server-side privacy

The API does not store client IP addresses. Rate-limit keys and logs use a salted hash. Logs never
contain query strings, so a URL someone checked is never written to a log.

## 9. Data licence and attribution

Feed data is published under **CC BY 4.0** (`LICENSE-DATA.md`). Code is Apache-2.0 (`LICENSE`). Common
Crawl data is used under the Common Crawl terms of use.
