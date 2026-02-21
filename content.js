// content.js
// Extract opened email (subject/body/links), run detector, highlight suspicious links,
// and respond to popup via chrome.runtime messaging.
//Salam123

const STYLE_ID = "pmd-style";
const MARK_ATTR = "data-pmd-marked";
const TOOLTIP_CLASS = "pmd-tooltip";

injectStylesOnce();

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || msg.type !== "PMD_SCAN_EMAIL") return;

  try {
    const data = extractEmailData();
    const result = window.analyzeEmail ? window.analyzeEmail(data) : fallbackError();

    // Highlight after scoring
    clearHighlights();
    highlightSuspiciousLinks(result.suspiciousLinks || []);

    sendResponse({
      ok: true,
      data,
      result
    });
  } catch (e) {
    sendResponse({
      ok: false,
      error: String(e?.message || e)
    });
  }

  // async response not needed, but keep true for safety
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

function extractEmailData() {
  // Gmail DOM changes often; use best-effort selectors.
  // Subject commonly in: h2.hP
  const subjectEl = document.querySelector("h2.hP") || document.querySelector("h2");
  const subject = subjectEl?.innerText?.trim() || "";

  // Email body often inside div.a3s (can be multiple)
  const bodyEls = Array.from(document.querySelectorAll("div.a3s"));
  const bodyText = bodyEls.map((el) => el.innerText).join("\n").trim();

  // Links inside body containers
  const linkNodes = bodyEls.length
    ? bodyEls.flatMap((root) => Array.from(root.querySelectorAll("a[href]")))
    : Array.from(document.querySelectorAll("a[href]"));

  const links = linkNodes
    .map((a) => ({
      href: a.getAttribute("href") || a.href || "",
      text: (a.innerText || a.textContent || "").trim()
    }))
    .filter((l) => l.href);

  return { subject, bodyText, links };
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