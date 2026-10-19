"""Project-wide constants: crawler identity and the AI-agent user-agent catalog."""
from __future__ import annotations

from dataclasses import dataclass

VERSION = "0.3.0"
BOT_TOKEN = "InjectionWatchBot"
CONTACT = "mailto:CONTACT_PLACEHOLDER@example.org"  # TODO(Dev): real contact before any public crawl
PROJECT_URL = "https://github.com/DevPatel3547/injection-watch"
CRAWLER_UA = f"Mozilla/5.0 (compatible; {BOT_TOKEN}/{VERSION}; +{PROJECT_URL}; {CONTACT})"

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/141.0.0.0 Safari/537.36")

FEED_LICENSE = "CC-BY-4.0"


@dataclass(frozen=True)
class AgentUA:
    name: str
    operator: str
    kind: str            # training_crawler | search_crawler | user_fetcher | robots_token_only
    user_agent: str | None
    ua_status: str       # "documented": string matches vendor docs as of the author's knowledge
                         # "approximate": token is real but full string is a best guess - verify
    verification: str    # how a SITE can verify the real bot: ip_ranges | reverse_dns | none_known | n/a


# NOTE: written offline (the build sandbox had no general web access). Re-check every
# string against the vendor's crawler documentation before relying on results.
AGENT_UAS: list[AgentUA] = [
    AgentUA("GPTBot", "OpenAI", "training_crawler",
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.1; +https://openai.com/gptbot)",
            "documented", "ip_ranges"),
    AgentUA("OAI-SearchBot", "OpenAI", "search_crawler",
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot",
            "documented", "ip_ranges"),
    AgentUA("ChatGPT-User", "OpenAI", "user_fetcher",
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
            "documented", "ip_ranges"),
    AgentUA("ClaudeBot", "Anthropic", "training_crawler",
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
            "documented", "none_known"),
    AgentUA("Claude-User", "Anthropic", "user_fetcher",
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; "
            "+Claude-User@anthropic.com)",
            "approximate", "none_known"),
    AgentUA("Claude-SearchBot", "Anthropic", "search_crawler",
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-SearchBot/1.0; "
            "+Claude-SearchBot@anthropic.com)",
            "approximate", "none_known"),
    AgentUA("PerplexityBot", "Perplexity", "search_crawler",
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
            "documented", "ip_ranges"),
    AgentUA("Perplexity-User", "Perplexity", "user_fetcher",
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)",
            "documented", "ip_ranges"),
    AgentUA("Googlebot", "Google", "search_crawler",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "documented", "reverse_dns"),
    AgentUA("Google-Extended", "Google", "robots_token_only", None, "documented", "n/a"),
    AgentUA("Applebot-Extended", "Apple", "robots_token_only", None, "documented", "n/a"),
    AgentUA("CCBot", "Common Crawl", "training_crawler", "CCBot/2.0 (https://commoncrawl.org/faq/)",
            "approximate", "none_known"),
    AgentUA("Bytespider", "ByteDance", "training_crawler",
            "Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 "
            "(compatible; Bytespider; spider-feedback@bytedance.com)", "approximate", "none_known"),
    AgentUA("meta-externalagent", "Meta", "training_crawler",
            "meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)",
            "approximate", "none_known"),
]


def fetchable_agents(names: list[str] | None = None) -> list[AgentUA]:
    out = [a for a in AGENT_UAS if a.user_agent]
    if names:
        wanted = {n.lower() for n in names}
        out = [a for a in out if a.name.lower() in wanted]
    return out
