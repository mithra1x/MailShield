// content.js
// Extract opened email (subject/body/links), run detector, highlight suspicious links,
// and respond to popup via chrome.runtime messaging.

const STYLE_ID = "pmd-style";
const MARK_ATTR = "data-pmd-marked";
const TOOLTIP_CLASS = "pmd-tooltip";

injectStylesOnce();
setupAutoScan();

function setupAutoScan() {
  let timeoutId = null;
  function runAutoScan() {
    if (timeoutId) clearTimeout(timeoutId);
    timeoutId = setTimeout(async () => {
      const { autoScan } = await chrome.storage.sync.get("autoScan");
      if (!autoScan) return;
      try {
        const data = await extractEmailDataWithOptions();
        if (!data.subject && !data.bodyText) return;
        const result = window.analyzeEmail ? window.analyzeEmail(data) : null;
        if (result) {
          chrome.runtime.sendMessage({ type: "PMD_BADGE_UPDATE", result });
        }
      } catch (_) { /* ignore */ }
      timeoutId = null;
    }, 1500);
  }
  window.addEventListener("hashchange", runAutoScan);
  if (document.readyState === "complete") runAutoScan();
  else window.addEventListener("load", runAutoScan);
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || msg.type !== "PMD_SCAN_EMAIL") return;

  (async () => {
    try {
      const data = await extractEmailDataWithOptions();
      const result = window.analyzeEmail ? window.analyzeEmail(data) : fallbackError();

      clearHighlights();
      highlightSuspiciousLinks(result.suspiciousLinks || []);

      sendResponse({ ok: true, data, result });
    } catch (e) {
      sendResponse({ ok: false, error: String(e?.message || e) });
    }
  })();
  return true;
});

function fallbackError() {
  return {
    score: 0,
    level: "Low",
    reasons: ["Detector not loaded (analyzeEmail missing)"],
    suspiciousLinks: []
  };
}

function normalizeSenderEmail(raw) {
  if (!raw || typeof raw !== "string") return "";
  let s = raw.trim();
  try { s = decodeURIComponent(s); } catch (_) { /* keep s */ }
  const inBrackets = s.match(/<([^>]+)>/);
  if (inBrackets) return inBrackets[1].trim().toLowerCase();
  const emailOnly = s.match(/\S+@[\w.-]+\.\w+/);
  if (emailOnly) return emailOnly[0].trim().toLowerCase();
  return s.toLowerCase();
}

function extractEmailData() {
  const subjectEl = document.querySelector("h2.hP") || document.querySelector("h2");
  const subject = subjectEl?.innerText?.trim() || "";

  const bodyEls = Array.from(document.querySelectorAll("div.a3s"));
  const bodyText = bodyEls.map((el) => el.innerText).join("\n").trim();

  const linkNodes = bodyEls.length
    ? bodyEls.flatMap((root) => Array.from(root.querySelectorAll("a[href]")))
    : Array.from(document.querySelectorAll("a[href]"));
  const links = linkNodes
    .map((a) => ({
      href: a.getAttribute("href") || a.href || "",
      text: (a.innerText || a.textContent || "").trim()
    }))
    .filter((l) => l.href);

  let from = "";
  let replyTo = "";
  let date = "";
  const fromSpan = document.querySelector('span[email]');
  if (fromSpan && fromSpan.getAttribute("email")) from = fromSpan.getAttribute("email").trim();
  if (!from) {
    const fromLink = document.querySelector('div.gs a[href^="mailto:"]') ||
      document.querySelector('span.gD a[href^="mailto:"]') ||
      document.querySelector('[role="main"] a[href^="mailto:"]');
    if (fromLink && fromLink.href) from = fromLink.href.replace(/^mailto:/i, "").trim();
  }
  from = normalizeSenderEmail(from);
  const header = document.querySelector(".h7") || document.querySelector('[role="main"]');
  if (header) {
    const text = header.innerText || "";
    if (!from || !from.includes("@")) {
      const emailInHeader = text.match(/\S+@[\w.-]+\.\w+/);
      if (emailInHeader) from = emailInHeader[0].trim().toLowerCase();
    }
    const replyMatch = text.match(/reply-to\s*[:=]\s*(\S+@\S+)/i);
    if (replyMatch) replyTo = replyMatch[1].trim();
    const dateMatch = text.match(/(?:date|sent)\s*[:=]\s*([^\n]+)/i) || text.match(/(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\w{3},?\s+\w{3}\s+\d{1,2},?\s+\d{4})/);
    if (dateMatch) date = dateMatch[1].trim();
  }
  if (!date) {
    const dateEl = document.querySelector('span.g3') || document.querySelector('[data-date]');
    if (dateEl) date = (dateEl.getAttribute("data-date") || dateEl.innerText || "").trim();
  }

  return { subject, bodyText, links, from, replyTo, date };
}

async function extractEmailDataWithOptions() {
  const data = extractEmailData();
  const { userTrustedDomains, userTrustedSenders } = await chrome.storage.sync.get(["userTrustedDomains", "userTrustedSenders"]);
  data.userTrustedDomains = Array.isArray(userTrustedDomains) ? userTrustedDomains : (typeof userTrustedDomains === "string" ? userTrustedDomains.split(/\n/).map((s) => s.trim()).filter(Boolean) : []);
  data.userTrustedSenders = Array.isArray(userTrustedSenders) ? userTrustedSenders : (typeof userTrustedSenders === "string" ? userTrustedSenders.split(/\n/).map((s) => s.trim().toLowerCase()).filter(Boolean) : []);
  return data;
}

function highlightSuspiciousLinks(suspiciousLinks) {
  if (!Array.isArray(suspiciousLinks) || suspiciousLinks.length === 0) return;

  // Map href->reasons text for tooltips
  const reasonMap = new Map();
  for (const s of suspiciousLinks) {
    const href = String(s.href || "");
    const label = humanizeLinkReasons(s.reasons || []);
    reasonMap.set(href, label || "Suspicious link");
  }

  // Only highlight links in opened email body
  const bodyEls = Array.from(document.querySelectorAll("div.a3s"));
  const roots = bodyEls.length ? bodyEls : [document.body];

  for (const root of roots) {
    const anchors = Array.from(root.querySelectorAll("a[href]"));
    for (const a of anchors) {
      const href = a.getAttribute("href") || a.href || "";
      if (!href) continue;

      if (reasonMap.has(href)) {
        // Mark and style
        a.setAttribute(MARK_ATTR, "1");
        a.classList.add("pmd-suspicious-link");

        // Tooltip
        const tip = reasonMap.get(href);
        a.setAttribute("title", tip);
      }
    }
  }
}

function clearHighlights() {
  const marked = document.querySelectorAll(`a[${MARK_ATTR}="1"]`);
  for (const a of marked) {
    a.removeAttribute(MARK_ATTR);
    a.classList.remove("pmd-suspicious-link");
    // keep existing titles if any? We'll remove only if we set it.
    // For MVP: remove title if it matches our pattern
    // (simple)
  }
}

function humanizeLinkReasons(reasons) {
  const set = new Set(reasons);
  const out = [];
  if (set.has("domain_mismatch")) out.push("Domain mismatch");
  if (set.has("url_shortener")) out.push("URL shortener");
  if (set.has("ip_based_url")) out.push("IP-based URL");
  if (set.has("dangerous_scheme")) out.push("Dangerous scheme");
  if (set.has("non_https_http")) out.push("Non-HTTPS (http)");
  if (set.has("lookalike_domain")) out.push("Lookalike domain");
  if (set.has("unparseable_url")) out.push("Unparseable URL");
  return out.join(" • ");
}

function injectStylesOnce() {
  if (document.getElementById(STYLE_ID)) return;
  const style = document.createElement("style");
  style.id = STYLE_ID;
  style.textContent = `
    a.pmd-suspicious-link {
      text-decoration: underline !important;
      text-decoration-thickness: 2px !important;
      text-decoration-style: wavy !important;
    }
  `;
  document.documentElement.appendChild(style);
}