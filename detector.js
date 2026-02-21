// detector.js
// Rule-based phishing detector for hackathon MVP.
// Input: { subject: string, bodyText: string, links: [{href, text}] }
// Output: { score, level, reasons[], suspiciousLinks[] }

import { fileURLToPath } from "url";
import { resolve } from "path";

export function analyzeEmail(input) {
    const subject = normalizeText(input?.subject || "");
    const body = normalizeText(input?.bodyText || "");
    const links = Array.isArray(input?.links) ? input.links : [];
  
    const fullText = `${subject} ${body}`.trim();
  
    const reasons = [];
    let score = 0;
  
    // ---- Text-based rules (subject+body) ----
    scoreAdd(
      reasons,
      containsUrgency(fullText),
      10,
      "Urgency/pressure words detected"
    );
  
    scoreAdd(
      reasons,
      containsCredentialRequest(fullText),
      20,
      "Credential/OTP/login request phrases detected"
    );
  
    scoreAdd(
      reasons,
      containsAttachmentBait(fullText),
      10,
      "Attachment bait phrases detected"
    );
  
    // ---- Link-based rules (per link) ----
    const suspiciousLinks = [];
  
    const uniqueExternalDomains = new Set();
  
    for (const l of links) {
      const href = (l?.href || "").trim();
      const text = (l?.text || "").trim();
  
      if (!href) continue;
  
      const linkFindings = [];
      let linkPoints = 0;
  
      const urlInfo = safeParseUrl(href);
      if (urlInfo) {
        uniqueExternalDomains.add(urlInfo.host);
  
        // Suspicious schemes
        if (isDangerousScheme(urlInfo.protocol)) {
          linkPoints += 30;
          linkFindings.push("dangerous_scheme");
        }
  
        // Non-https (http)
        if (urlInfo.protocol === "http:") {
          linkPoints += 10;
          linkFindings.push("non_https_http");
        }
  
        // IP-based host
        if (isIpHost(urlInfo.host)) {
          linkPoints += 25;
          linkFindings.push("ip_based_url");
        }
  
        // Shortener host
        if (isShortener(urlInfo.host)) {
          linkPoints += 15;
          linkFindings.push("url_shortener");
        }
  
        // Mismatch: link text domain vs href domain
        const textDomain = extractDomainFromText(text);
        if (textDomain && textDomain !== urlInfo.host) {
          linkPoints += 25;
          linkFindings.push("domain_mismatch");
        }
  
        // Lookalike-ish domain (lightweight)
        if (isLookalike(urlInfo.host)) {
          linkPoints += 15;
          linkFindings.push("lookalike_domain");
        }
      } else {
        // If URL can't be parsed, treat as suspicious a bit
        linkPoints += 10;
        linkFindings.push("unparseable_url");
      }
  
      if (linkPoints > 0) {
        suspiciousLinks.push({
          href,
          text,
          points: linkPoints,
          reasons: linkFindings,
        });
        score += linkPoints;
      }
    }
  
    // Many external domains rule (global)
    if (uniqueExternalDomains.size >= 3) {
      score += 10;
      reasons.push("Many external link domains detected (3+ unique domains)");
    }
  
    // Add some high-level reasons based on suspiciousLinks findings
    // (avoid duplicates + keep popup clean)
    const highLevel = summarizeLinkFindings(suspiciousLinks);
    for (const r of highLevel) reasons.push(r);
  
    // Clamp and level
    score = clamp(score, 0, 100);
    const level = scoreToLevel(score);
  
    // Keep reasons 3–6 ideally; in hackathon MVP we cap at 6
    const finalReasons = dedupe(reasons).slice(0, 6);
  
    // Sort suspicious links by points desc (nice for UI)
    suspiciousLinks.sort((a, b) => (b.points || 0) - (a.points || 0));
  
    return {
      score,
      level,
      reasons: finalReasons,
      suspiciousLinks,
    };
  }
  
  // ---------------- Helpers ----------------
  
  function normalizeText(s) {
    return String(s)
      .toLowerCase()
      .replace(/\s+/g, " ")
      .trim();
  }
  
  function clamp(n, min, max) {
    return Math.max(min, Math.min(max, n));
  }
  
  function scoreToLevel(score) {
    if (score >= 60) return "High";
    if (score >= 30) return "Medium";
    return "Low";
  }
  
  function dedupe(arr) {
    const seen = new Set();
    const out = [];
    for (const x of arr) {
      const key = String(x);
      if (!seen.has(key)) {
        seen.add(key);
        out.push(x);
      }
    }
    return out;
  }
  
  function scoreAdd(reasons, condition, points, reasonText) {
    if (!condition) return 0;
    reasons.push(reasonText);
    return points;
  }
  
  // NOTE: We add points via scoreAdd return only where used.
  // For clarity in analyzeEmail we directly increment score for per-link.
  // For text rules we use this:
  function containsAny(text, patterns) {
    return patterns.some((p) => (p instanceof RegExp ? p.test(text) : text.includes(p)));
  }
  
  // ---- Rules: text ----
  
  function containsUrgency(text) {
    const patterns = [
      "urgent",
      "immediately",
      "verify now",
      "act now",
      "action required",
      "account suspended",
      "suspended",
      "unusual activity",
      "security alert",
      "within 24 hours",
      "24 hours",
      "limited time",
    ];
    return containsAny(text, patterns);
  }
  
  function containsCredentialRequest(text) {
    const patterns = [
      "password",
      "otp",
      "one-time password",
      "verification code",
      "2fa code",
      "login to confirm",
      "log in to confirm",
      "sign in to confirm",
      "verify your account",
      "confirm your account",
      "reset your password",
    ];
    return containsAny(text, patterns);
  }
  
  function containsAttachmentBait(text) {
    const patterns = [
      "invoice attached",
      "attached invoice",
      "payment failed",
      "attached document",
      "open the attached",
      "scan the attached",
      "see attachment",
      "attached file",
    ];
    return containsAny(text, patterns);
  }
  
  // ---- Rules: URL parsing ----
  
  function safeParseUrl(href) {
    try {
      const u = new URL(href);
      return {
        protocol: u.protocol, // "https:"
        host: normalizeHost(u.hostname), // without trailing dot
        href: u.href,
      };
    } catch {
      return null;
    }
  }
  
  function normalizeHost(host) {
    return String(host || "")
      .toLowerCase()
      .replace(/\.$/, "");
  }
  
  function isDangerousScheme(protocol) {
    return protocol === "javascript:" || protocol === "data:";
  }
  
  function isIpHost(host) {
    // Basic IPv4 check
    if (!host) return false;
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  }
  
  function isShortener(host) {
    const shorteners = new Set([
      "bit.ly",
      "tinyurl.com",
      "t.co",
      "goo.gl",
      "is.gd",
      "cutt.ly",
      "ow.ly",
      "rebrand.ly",
    ]);
    return shorteners.has(host);
  }
  
  function extractDomainFromText(text) {
    const t = String(text || "").trim();
    if (!t) return null;
  
    // find something like paypal.com or sub.domain.co.uk (simple)
    const m = t.match(/([a-z0-9-]+\.)+[a-z]{2,}/i);
    if (!m) return null;
  
    return normalizeHost(m[0]);
  }
  
  // ---- Lookalike domain (lightweight, hackathon-friendly) ----
  // Not perfect; gives "wow" factor without heavy algorithms.
  function isLookalike(host) {
    if (!host) return false;
  
    // obvious digit substitutions often used in lookalikes
    if (/[0]/.test(host)) return true;
  
    // suspicious mix of l/I in brand-ish strings is hard; do a light check:
    // if domain contains "paypa" but isn't paypal.com, flag
    const brands = [
      { key: "paypal", legit: ["paypal.com"] },
      { key: "microsoft", legit: ["microsoft.com"] },
      { key: "google", legit: ["google.com"] },
      { key: "apple", legit: ["apple.com"] },
    ];
  
    for (const b of brands) {
      if (host.includes(b.key.slice(0, 4)) && !b.legit.includes(host)) {
        // e.g. "paypaI.com" often still includes "paypa"
        return true;
      }
    }
  
    return false;
  }
  
  // ---- Summarize link findings into clean popup reasons ----
  function summarizeLinkFindings(suspiciousLinks) {
    const flags = new Set();
    for (const l of suspiciousLinks) {
      for (const r of l.reasons || []) flags.add(r);
    }
  
    const out = [];
    if (flags.has("domain_mismatch"))
      out.push("Domain mismatch detected (visible text vs real link domain)");
    if (flags.has("url_shortener"))
      out.push("Shortened URL detected (often used to hide destination)");
    if (flags.has("ip_based_url"))
      out.push("IP-based URL detected (unusual for legitimate services)");
    if (flags.has("dangerous_scheme"))
      out.push("Dangerous URL scheme detected (javascript/data)");
    if (flags.has("non_https_http"))
      out.push("Non-HTTPS link detected (http)");
    if (flags.has("lookalike_domain"))
      out.push("Possible lookalike/typosquatted domain detected");
  
    return out;
  }
  
  // ---------------- Quick self-test when run directly ----------------
  const __filename = fileURLToPath(import.meta.url);
  const isRunDirectly =
    typeof process !== "undefined" &&
    process.argv[1] &&
    resolve(process.argv[1]) === __filename;
  if (isRunDirectly) {
    const sample = analyzeEmail({
      subject: "URGENT: Account Suspended",
      bodyText: "Verify now. Enter your password and OTP within 24 hours.",
      links: [
        { href: "http://bit.ly/abcd", text: "paypal.com" },
        { href: "https://paypaI.com/login", text: "paypal.com" },
      ],
    });
    console.log("Phishing detector result:", JSON.stringify(sample, null, 2));
  }