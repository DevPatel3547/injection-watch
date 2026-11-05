# Held-out v3 (frozen)

Written and frozen (MANIFEST.sha256) **before** any v0.4 detector change; never tuned against.

* `p*` pages: payloads are short samples of **test-split** items from public datasets, planted into small pages written for this corpus. Sources (all MIT): InjecAgent (Zhan et al. 2024, uiuc-kang-lab/InjecAgent), BIPIA (Yi et al. 2023, microsoft/BIPIA), AgentDojo (Debenedetti et al. 2024, ethz-spylab/agentdojo), Open-Prompt-Injection (Liu et al. 2024, liu00222/Open-Prompt-Injection). Pinned commits: `injectionwatch/bench/sources.py`. Each label's note names the dataset and bench item id. E-mail addresses inside payloads were replaced by attacker@example.com; nothing else was changed.
* `n*` pages: benign pages written for this corpus: the nine real-web false-positive template types from the second Common Crawl sample (new wording, nothing copied from a page), other benign hidden UI, and pages that discuss prompt injection.
