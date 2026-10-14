// Options page: explicit opt-in for reporting + endpoint (https only, per-origin permission).
async function iwOptions(): Promise<void> {
  const consent = document.getElementById("consent") as HTMLInputElement;
  const endpoint = document.getElementById("endpoint") as HTMLInputElement;
  const status = document.getElementById("status")!;
  const s = await chrome.storage.local.get({ consent: false, endpoint: "" });
  consent.checked = !!s.consent;
  endpoint.value = String(s.endpoint || "");
  document.getElementById("save")!.addEventListener("click", async () => {
    const v = endpoint.value.trim().replace(/\/+$/, "");
    if (v) {
      let u: URL;
      try { u = new URL(v); } catch { status.textContent = "Not a valid URL."; return; }
      if (u.protocol !== "https:" || u.username || u.password) { status.textContent = "Endpoint must be an https:// URL without credentials."; return; }
      const granted = await chrome.permissions.request({ origins: [u.origin + "/*"] });
      if (!granted) { status.textContent = "Permission for that origin was not granted; not saved."; return; }
    }
    await chrome.storage.local.set({ consent: consent.checked && !!v, endpoint: v });
    if (consent.checked && !v) consent.checked = false;
    status.textContent = consent.checked ? "Saved. Reporting is ON (each report still needs your confirmation)." : "Saved. Reporting is OFF.";
  });
}
iwOptions();
