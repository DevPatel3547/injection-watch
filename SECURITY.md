# Security policy

## Reporting a vulnerability in InjectionWatch

Please **do not open a public issue** for security problems. Use GitHub's private vulnerability
reporting ("Security" tab -> "Report a vulnerability"), or email the contact in `injectionwatch/config.py`.
We aim to acknowledge reports within 3 working days and to give an initial assessment within 10.

In scope:

* the API (`injectionwatch/api.py`): auth bypass on future write routes, SSRF (note that `/v1/check`
  never fetches the URL it is given; a way to make it fetch would be a bug), injection, DoS beyond
  the documented rate limits;
* the static site / dashboard: XSS through feed content (all feed text is attacker-controlled and must
  only ever be rendered as text);
* the detector itself being turned against consumers, e.g. payloads that survive excerpt truncation and
  defanging in a way that makes the *feed* an injection vector;
* the browser extension: anything that sends more data than documented, remote code, or privilege abuse;
* the MCP server and `safe_fetch` helper.

Out of scope: detector *evasions* (a payload the rules miss). Those are welcome as normal issues with a
minimal synthetic fixture. Please do not include live malicious URLs in public issues.

## Reporting a URL that should be in (or out of) the feed

* A site carrying an injection: open an issue with the "Report an injection" template, or use the browser
  extension's opt-in report button.
* A false positive, or your own site is listed: see the takedown / appeal process in `docs/ethics.md`.

## If your site is listed

A listing means our detector found text on that page that addresses AI agents with instructions (with
evidence in the `reasons` field). Most such text we see on legitimate sites was **planted by an attacker**
through a compromised plugin, widget or comment system. Search the page source for the excerpt or the
element path in the entry, remove it, then file a takedown request so we re-check.

## Supported versions

Only the latest release receives fixes.
