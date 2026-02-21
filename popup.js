// popup.js

const scanBtn = document.getElementById("scanBtn");
const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");
const reasonsEl = document.getElementById("reasons");
const linksEl = document.getElementById("links");
const copyBtn = document.getElementById("copyBtn");
const optionsLink = document.getElementById("optionsLink");
const gaugeSectionEl = document.getElementById("gaugeSection");
const gaugeProgressEl = document.getElementById("gaugeProgress");
const gaugeScoreEl = document.getElementById("gaugeScore");
const gaugeBadgeEl = document.getElementById("gaugeBadge");
const riskBarContainerEl = document.getElementById("risk-bar-container");
const riskBarFillEl = document.getElementById("risk-bar-fill");

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

  // Risk score gauge (above reasons list); hide if no score data
  renderGauge(result?.score, result?.level);

  // Risk bar (directly below gauge/score row)
  renderRiskBar(result?.score, result?.level);

  // Reasons
  reasonsEl.innerHTML = "";
  const reasons = Array.isArray(result?.reasons) ? result.reasons : [];
  for (const r of reasons) {
    const li = document.createElement("li");
    li.textContent = r;
    reasonsEl.appendChild(li);
  }

  // Links
  linksEl.innerHTML = "";
  const sus = Array.isArray(result?.suspiciousLinks) ? result.suspiciousLinks : [];
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
  lines.push(`Risk: ${result?.level ?? "—"} (${result?.score ?? 0}/100)`);
  lines.push("");
  lines.push("Indicators:");
  for (const r of (result?.reasons || [])) lines.push(`- ${r}`);
  lines.push("");
  lines.push("Suspicious URLs:");
  const urls = (result?.suspiciousLinks || []).map((x) => x.href);
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

/**
 * Renders the risk score gauge: circular SVG ring, center score, and level pill.
 * Animates the ring from 0 to score over ~400ms. Hides gauge if score is missing.
 * @param {number} [score] - 0–100; if undefined/null, gauge is hidden
 * @param {string} [level] - "Low" | "Medium" | "High"
 */
function renderGauge(score, level) {
  const section = gaugeSectionEl;
  const ring = gaugeProgressEl;
  const scoreEl = gaugeScoreEl;
  const badgeEl = gaugeBadgeEl;

  if (score == null || section == null || ring == null) {
    if (section) section.classList.add("hidden");
    return;
  }

  const value = Math.max(0, Math.min(100, Number(score)));
  const levelNorm = (level && ["Low", "Medium", "High"].includes(level)) ? level : "Low";

  // Circle r=42 in viewBox "0 0 100 100"
  const r = 42;
  const circumference = 2 * Math.PI * r;
  const dashOffsetFull = circumference * (1 - value / 100);

  // Level colors (CSS variables)
  const colors = {
    Low: "var(--gauge-low)",
    Medium: "var(--gauge-medium)",
    High: "var(--gauge-high)",
  };
  const color = colors[levelNorm];

  section.classList.remove("hidden");
  section.style.setProperty("--gauge-circumference", String(circumference));

  // Ring and badge color
  ring.style.stroke = color;
  badgeEl.style.setProperty("--gauge-badge-bg", color);
  badgeEl.textContent = levelNorm;

  // Start from 0% for animation, then animate to value
  ring.style.strokeDasharray = String(circumference);
  ring.style.strokeDashoffset = String(circumference);
  scoreEl.textContent = String(Math.round(value));

  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      ring.style.strokeDashoffset = String(dashOffsetFull);
    });
  });
}

/**
 * Renders the horizontal risk bar: fill width from score, color from level.
 * Called from render() when result card is shown; hide is done in hideResult().
 * Score missing → 0%; level unknown → neutral color. Smooth 0.4s animation.
 * @param {number} [score] - 0–100; missing → 0
 * @param {string} [level] - "Low" | "Medium" | "High"; unknown → neutral
 */
function renderRiskBar(score, level) {
  if (!riskBarContainerEl || !riskBarFillEl) return;

  const value = Math.max(0, Math.min(100, Number(score) || 0));
  const levelNorm = (level && ["Low", "Medium", "High"].includes(level)) ? level : null;

  riskBarContainerEl.classList.remove("hidden");
  riskBarFillEl.style.width = `${value}%`;

  riskBarFillEl.classList.remove("risk-low", "risk-medium", "risk-high", "risk-neutral");
  if (levelNorm === "Low") riskBarFillEl.classList.add("risk-low");
  else if (levelNorm === "Medium") riskBarFillEl.classList.add("risk-medium");
  else if (levelNorm === "High") riskBarFillEl.classList.add("risk-high");
  else riskBarFillEl.classList.add("risk-neutral");
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
  if (riskBarContainerEl) riskBarContainerEl.classList.add("hidden");
}