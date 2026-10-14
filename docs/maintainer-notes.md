# Maintainer notes: concepts to be able to explain

1. **Direct vs indirect prompt injection**, and why hidden text matters: agents read DOM, raw HTML or
   the accessibility tree, but humans see only rendered pixels. Each location in the table above is a
   gap between the two.
2. **Why precision first:** a public feed that blocks legitimate pages loses trust fast. Visible text,
   code blocks and pages *about* injection get down-weighted. Look at the held-out FP (a quiz that
   quotes an injection) and explain how you'd fix it (context features, LLM veto).
3. **Why the 1.00 isn't real**, and how you'd build an honest eval: sample real crawl hits, have two
   annotators label them, report precision on the sample, and estimate recall with seeded canaries.
4. **Two-stage design and cost:** regexes are cheap and explainable. The LLM is called only on hits.
   Recall mode trades API cost for paraphrase coverage. Prompt-injecting the classifier itself is
   mitigated by delimiters, a forced tool schema and enum validation, but not eliminated.
5. **The feed as an attack surface:** truncation, defanging, payload-free /check, and untrusted-data
   warnings.
6. **Dedupe and lifecycle:** (normalized URL, normalized payload hash), observations,
   first_seen/last_seen, removed vs suppressed.
7. **Cloaking-check limits:** UA vs IP verification, noise baselining, and the ethics of impersonating
   bot UAs.
8. **Extension privacy model:** what's sent, why query strings are dropped, and why reports are leads,
   not entries.
9. **STIX 2.1 basics:** indicator, pattern, identity, custom `x_` properties. Why CTI tools want it.
10. **Crawl politeness** (robots.txt semantics for 4xx vs 5xx, per-host delay, circuit breaker) and why
    the real crawl was not forced through the block.

11. **v0.2 additions:** use-vs-mention (quoted payloads), same-category overlap dedupe, the necessary-literal
    prefilter (why it is exact and why the whole-document prefilter was removed), WARC resume semantics
    (checkpoint = first unhandled record; idempotent observations), and why held-out v2 was frozen with a manifest.
