// Content script: collects hidden / machine-targeted text locally (collect.js), scores it, and tells the
// background worker how many findings there are. NOTHING leaves the browser from here.

async function iwScan(): Promise<void> {
  const findings = await iwScanDocument(document);
  chrome.runtime.sendMessage({ type: "iw-findings", findings });
}

iwScan();
setTimeout(iwScan, 3000); // one re-scan for client-rendered pages
