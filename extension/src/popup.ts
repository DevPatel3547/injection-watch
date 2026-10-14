// Popup: shows local findings; per-finding "Report" only when reporting was enabled in Options.
function iwEl<K extends keyof HTMLElementTagNameMap>(tag: K, text?: string): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text; // textContent only: never innerHTML with page data
  return e;
}

async function iwPopup(): Promise<void> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const settings = await chrome.storage.local.get({ consent: false, endpoint: "" });
  const reporting = !!settings.consent && !!settings.endpoint;
  document.getElementById("consent-line")!.textContent = reporting
    ? "Reporting is on (opt-in). Each report shows you the exact data before sending."
    : "Reporting is off. You can opt in from Options.";

  const list = document.getElementById("findings")!;
  const { findings } = await chrome.runtime.sendMessage({ type: "iw-get", tabId: tab.id });
  if (!findings.length) { list.appendChild(iwEl("p", "No injection-like hidden text found on this page.")); return; }
  for (const f of findings as IwFinding[]) {
    const card = iwEl("div"); card.className = "card " + f.intent;
    card.appendChild(iwEl("div", `${f.category} · ${f.intent} · ${f.location} (${f.technique}) · score ${f.score}`));
    card.appendChild(iwEl("blockquote", f.excerpt));
    if (reporting && !tab.incognito) {
      const btn = iwEl("button", "Report hash to feed…");
      btn.addEventListener("click", async () => {
        let u = ""; try { const x = new URL(tab.url); u = x.origin + x.pathname; } catch { /* not reportable */ }
        const preview = JSON.stringify({ url: u, payload_hash: f.payload_hash, category: f.category, technique: f.technique }, null, 1);
        if (!confirm("This exact data will be sent to " + settings.endpoint + ":\n" + preview)) return;
        const r = await chrome.runtime.sendMessage({ type: "iw-report", tabUrl: tab.url, incognito: tab.incognito, finding: f });
        btn.textContent = r.ok ? "Reported ✓" : "Not sent: " + (r.error || r.status);
        btn.disabled = true;
      });
      card.appendChild(btn);
    }
    list.appendChild(card);
  }
}
iwPopup();
