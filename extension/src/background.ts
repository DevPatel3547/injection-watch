// Service worker: badge + opt-in reporting. Keeps findings in memory only.
const IW_VERSION = "0.3.0";
const IW_FLAG_INTENTS = new Set(["malicious", "manipulative"]);
const iwTabFindings = new Map<number, IwFinding[]>();

async function iwSettings(): Promise<{ consent: boolean; endpoint: string }> {
  const s = await chrome.storage.local.get({ consent: false, endpoint: "" });
  return { consent: !!s.consent, endpoint: String(s.endpoint || "") };
}

/** Only scheme + host + path. Query strings and fragments can carry tokens/PII and are dropped. */
function iwReportableUrl(raw: string): string | null {
  try {
    const u = new URL(raw);
    if (u.protocol !== "https:" && u.protocol !== "http:") return null;
    if (u.username || u.password) return null;
    return u.origin + u.pathname;
  } catch { return null; }
}

chrome.runtime.onMessage.addListener((msg: any, sender: any, sendResponse: (r: unknown) => void) => {
  if (msg?.type === "iw-findings" && sender.tab?.id !== undefined) {
    const tabId = sender.tab.id as number;
    iwTabFindings.set(tabId, msg.findings as IwFinding[]);
    const flagged = (msg.findings as IwFinding[]).filter((f) => IW_FLAG_INTENTS.has(f.intent)).length;
    chrome.action.setBadgeText({ tabId, text: flagged ? String(flagged) : "" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#b42318" });
    return false;
  }
  if (msg?.type === "iw-get") {
    sendResponse({ findings: iwTabFindings.get(msg.tabId) || [] });
    return false;
  }
  if (msg?.type === "iw-report") {
    (async () => {
      const { consent, endpoint } = await iwSettings();
      if (!consent || !endpoint.startsWith("https://")) return sendResponse({ ok: false, error: "reporting not enabled in Options" });
      if (msg.incognito) return sendResponse({ ok: false, error: "reporting disabled in incognito" });
      const url = iwReportableUrl(msg.tabUrl);
      const f = msg.finding as IwFinding;
      if (!url || !/^[0-9a-f]{64}$/.test(f.payload_hash)) return sendResponse({ ok: false, error: "not reportable" });
      // EXACTLY these fields are sent. No page text, no excerpt, no cookies, no account data.
      const body = { url, payload_hash: f.payload_hash, category: f.category, technique: f.technique, extension_version: IW_VERSION };
      try {
        const r = await fetch(endpoint.replace(/\/$/, "") + "/v1/submit", {
          method: "POST", credentials: "omit", referrerPolicy: "no-referrer", cache: "no-store",
          headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
        });
        sendResponse({ ok: r.ok, status: r.status, sent: body });
      } catch (e) {
        sendResponse({ ok: false, error: String(e) });
      }
    })();
    return true; // async response
  }
  return false;
});

chrome.tabs.onRemoved.addListener((tabId: number) => iwTabFindings.delete(tabId));
