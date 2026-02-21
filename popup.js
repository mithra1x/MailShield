// popup.js

const scanBtn = document.getElementById("scanBtn");
const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");
const riskLevelEl = document.getElementById("riskLevel");
const riskScoreEl = document.getElementById("riskScore");
const reasonsEl = document.getElementById("reasons");
const linksEl = document.getElementById("links");
const copyBtn = document.getElementById("copyBtn");
const optionsLink = document.getElementById("optionsLink");

let lastScan = null;

if (optionsLink) {
  optionsLink.addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });
}

scanBtn.addEventListener("click", async () => {
  setStatus("Scanning current email…");
  hideResult();

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) throw new Error("No active tab found.");
    if (!tab.url || !tab.url.startsWith("https://mail.google.com/")) {
      throw new Error("Open a Gmail tab and try again.");
    }

    let resp;
    try {
      resp = await chrome.tabs.sendMessage(tab.id, { type: "PMD_SCAN_EMAIL" });
    } catch (e) {
      // Content script not loaded (e.g. tab opened before extension, or not refreshed)
      if (e?.message?.includes("Receiving end does not exist")) {
        await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          files: ["detector.js", "content.js"],
        });
        resp = await chrome.tabs.sendMessage(tab.id, { type: "PMD_SCAN_EMAIL" });
      } else {
        throw e;
      }
    }

    if (!resp?.ok) throw new Error(resp?.error || "Scan failed.");

    lastScan = resp;
    render(resp.data, resp.result);
    setStatus("");
  } catch (e) {
    setStatus(`Error: ${String(e?.message || e)}`);
  }
});

copyBtn.addEventListener("click", async () => {
  if (!lastScan) return;

  const { data, result } = lastScan;
  const report = buildReport(data, result);

  try {
    await navigator.clipboard.writeText(report);
    setStatus("Copied report to clipboard ✅");
    setTimeout(() => setStatus(""), 1200);
  } catch {
    setStatus("Clipboard copy failed (try manual copy).");
  }
});

function render(data, result) {
  resultEl.classList.remove("hidden");

  riskLevelEl.textContent = result.level;
  riskScoreEl.textContent = String(result.score);

  // Reasons
  reasonsEl.innerHTML = "";
  const reasons = Array.isArray(result.reasons) ? result.reasons : [];
  for (const r of reasons) {
    const li = document.createElement("li");
    li.textContent = r;
    reasonsEl.appendChild(li);
  }

  // Links
  linksEl.innerHTML = "";
  const sus = Array.isArray(result.suspiciousLinks) ? result.suspiciousLinks : [];
  if (sus.length === 0) {
    const li = document.createElement("li");
    li.textContent = "None detected.";
    linksEl.appendChild(li);
  } else {
    for (const s of sus.slice(0, 8)) {
      const li = document.createElement("li");
      li.textContent = s.href;
      linksEl.appendChild(li);
    }
  }

  copyBtn.disabled = false;
}

function buildReport(data, result) {
  const lines = [];
  lines.push("=== Phishing Mail Detector Report ===");
  lines.push(`Risk: ${result.level} (${result.score}/100)`);
  lines.push("");
  lines.push("Indicators:");
  for (const r of (result.reasons || [])) lines.push(`- ${r}`);
  lines.push("");
  lines.push("Suspicious URLs:");
  const urls = (result.suspiciousLinks || []).map((x) => x.href);
  if (urls.length === 0) lines.push("- None");
  else for (const u of urls) lines.push(`- ${u}`);
  lines.push("");
  lines.push("Context:");
  lines.push(`Subject: ${data.subject || ""}`);
  if (data.from) lines.push(`From: ${data.from}`);
  if (data.replyTo) lines.push(`Reply-To: ${data.replyTo}`);
  if (data.date) lines.push(`Date: ${data.date}`);
  return lines.join("\n");
}

function setStatus(text) {
  if (!text) {
    statusEl.classList.add("hidden");
    statusEl.textContent = "";
    return;
  }
  statusEl.classList.remove("hidden");
  statusEl.textContent = text;
}

function hideResult() {
  resultEl.classList.add("hidden");
  copyBtn.disabled = true;
}