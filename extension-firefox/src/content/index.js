/**
 * LinkShield Content Script — Self-contained (no imports)
 *
 * Features:
 * 1. Check current page safety → show block page if dangerous
 * 2. Scan all links → add safety badges (green/yellow/red)
 * 3. Hover tooltips with details
 * 4. Listen for context menu commands
 * 5. MutationObserver for dynamic content (SPA, Gmail)
 * 6. Gmail/Outlook aha-moment detection
 */

const BADGE_CLASS = "ls-badge";
const SCANNED_ATTR = "data-ls-scanned";
let _scanTimeout = null;

// ═══════════════════════════════════════════════════
// 1. CHECK CURRENT PAGE
// ═══════════════════════════════════════════════════

(async function checkCurrentPage() {
  try {
    const domain = window.location.hostname.toLowerCase();
    if (!domain || domain === "localhost" || domain === "") return;

    const response = await chrome.runtime.sendMessage({
      type: "CHECK_DOMAINS",
      domains: [domain],
    });

    if (response && response.results && response.results[0]) {
      if (response.results[0].level === "dangerous") {
        showBlockPage(response.results[0]);
      }
    }
  } catch (e) {
    // Extension context might not be available
  }
})();

// ═══════════════════════════════════════════════════
// 2. LINK SCANNING
// ═══════════════════════════════════════════════════

function extractPageLinks() {
  const links = document.querySelectorAll("a[href]:not([" + SCANNED_ATTR + "])");
  const external = [];
  for (const link of links) {
    try {
      const url = new URL(link.href);
      if (url.protocol === "javascript:" || url.protocol === "mailto:" || url.protocol === "tel:" || url.hostname === window.location.hostname) continue;
      external.push({ element: link, domain: url.hostname.toLowerCase() });
    } catch (e) {}
  }
  return external;
}

async function scanPage() {
  const links = extractPageLinks();
  if (links.length === 0) return;

  const domainMap = new Map();
  for (const link of links) {
    if (!domainMap.has(link.domain)) domainMap.set(link.domain, []);
    domainMap.get(link.domain).push(link.element);
  }

  const domains = [...domainMap.keys()];

  for (let i = 0; i < domains.length; i += 50) {
    const batch = domains.slice(i, i + 50);
    try {
      const response = await chrome.runtime.sendMessage({ type: "CHECK_DOMAINS", domains: batch });
      if (response && response.results) {
        for (const result of response.results) {
          const elements = domainMap.get(result.domain) || [];
          for (const el of elements) addBadge(el, result);
        }
      }
    } catch (e) {}
  }
}

// ═══════════════════════════════════════════════════
// 3. BADGES
// ═══════════════════════════════════════════════════

function addBadge(linkEl, result) {
  if (linkEl.querySelector("." + BADGE_CLASS)) return;
  linkEl.setAttribute(SCANNED_ATTR, "true");

  const badge = document.createElement("span");
  badge.className = BADGE_CLASS;

  if (result.level === "safe") {
    badge.classList.add("ls-safe");
    badge.textContent = "\u2713";
    badge.title = "Safe";
  } else if (result.level === "caution") {
    badge.classList.add("ls-caution");
    badge.textContent = "\u26A0";
    badge.title = "Caution (score: " + result.score + ")";
  } else {
    badge.classList.add("ls-dangerous");
    badge.textContent = "\u2717";
    badge.title = "Dangerous (score: " + result.score + ")";
  }

  // Tooltip
  const tooltip = document.createElement("div");
  tooltip.className = "ls-tooltip";
  const reasons = (result.reasons || []).slice(0, 3).map(function(r) {
    return '<div style="font-size:11px;color:#d1d5db;margin:2px 0;">\u2022 ' + r.detail + '</div>';
  }).join("");
  const colors = { safe: "#22c55e", caution: "#f59e0b", dangerous: "#ef4444" };
  const labels = { safe: "Safe", caution: "Caution", dangerous: "Dangerous" };
  tooltip.innerHTML = '<div class="ls-tooltip-inner"><div class="ls-tooltip-header"><span class="ls-dot" style="background:' + colors[result.level] + '"></span><strong>' + labels[result.level] + '</strong><span class="ls-score">Score: ' + result.score + '/100</span></div><div class="ls-domain">' + result.domain + '</div>' + reasons + '<div class="ls-footer">LinkShield</div></div>';
  badge.appendChild(tooltip);

  linkEl.style.position = "relative";
  linkEl.appendChild(badge);
}

// ═══════════════════════════════════════════════════
// 4. BLOCK PAGE
// ═══════════════════════════════════════════════════

function showBlockPage(result) {
  if (document.getElementById("ls-block-overlay")) return;

  const reasons = (result.reasons || []).slice(0, 4).map(function(r) {
    return '<div style="display:flex;align-items:flex-start;gap:8px;margin:8px 0;"><span style="color:#ef4444;">\u26A0</span><span>' + r.detail + '</span></div>';
  }).join("");

  const overlay = document.createElement("div");
  overlay.id = "ls-block-overlay";
  overlay.innerHTML = '<div style="position:fixed;inset:0;z-index:2147483647;background:#0f172aee;backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,sans-serif;color:#e2e8f0;"><div style="max-width:480px;text-align:center;padding:40px 24px;"><div style="width:80px;height:80px;border-radius:50%;background:#ef444420;margin:0 auto 24px;display:flex;align-items:center;justify-content:center;font-size:40px;">\uD83D\uDEE1</div><h1 style="font-size:28px;font-weight:800;color:#f8fafc;margin:0 0 8px;">Dangerous Site Detected</h1><p style="font-size:16px;color:#94a3b8;margin:0 0 24px;">LinkShield identified <strong style="color:#ef4444;">' + result.domain + '</strong> as a threat (score: ' + result.score + '/100)</p><div style="background:#1e293b;border-radius:12px;padding:16px;text-align:left;margin-bottom:24px;font-size:14px;border:1px solid #ef444440;">' + (reasons || '<div style="color:#94a3b8;">Multiple risk signals detected</div>') + '</div><div style="display:flex;flex-direction:column;gap:12px;"><button id="ls-go-back" style="background:#22c55e;color:#052e16;border:none;border-radius:10px;padding:14px 32px;font-size:16px;font-weight:700;cursor:pointer;">\u2190 Go Back (Recommended)</button><button id="ls-proceed" style="background:transparent;color:#64748b;border:1px solid #334155;border-radius:10px;padding:12px 32px;font-size:14px;cursor:pointer;opacity:0.5;" disabled>Proceed anyway (3s)</button></div><p style="font-size:11px;color:#475569;margin-top:20px;">\uD83D\uDD12 Warning by LinkShield extension</p></div></div>';

  document.body.appendChild(overlay);
  document.body.style.overflow = "hidden";

  document.getElementById("ls-go-back").onclick = function() { history.back(); };

  // Countdown before allowing proceed
  var countdown = 3;
  var proceedBtn = document.getElementById("ls-proceed");
  var iv = setInterval(function() {
    countdown--;
    if (countdown <= 0) {
      clearInterval(iv);
      proceedBtn.textContent = "I understand the risk \u2014 proceed anyway";
      proceedBtn.disabled = false;
      proceedBtn.style.opacity = "1";
      proceedBtn.onclick = function() {
        overlay.remove();
        document.body.style.overflow = "";
      };
    } else {
      proceedBtn.textContent = "Proceed anyway (" + countdown + "s)";
    }
  }, 1000);
}

// ═══════════════════════════════════════════════════
// 5. FLOATING RESULT (context menu response)
// ═══════════════════════════════════════════════════

function showFloatingResult(result) {
  var existing = document.getElementById("ls-floating-result");
  if (existing) existing.remove();

  var colors = { safe: "#22c55e", caution: "#f59e0b", dangerous: "#ef4444" };
  var icons = { safe: "\u2713", caution: "\u26A0", dangerous: "\u2717" };
  var labels = { safe: "Safe", caution: "Caution", dangerous: "Dangerous" };
  var reasons = (result.reasons || []).slice(0, 3).map(function(r) {
    return '<div style="font-size:11px;color:#d1d5db;margin:2px 0;">\u2022 ' + r.detail + '</div>';
  }).join("");

  var div = document.createElement("div");
  div.id = "ls-floating-result";
  div.innerHTML = '<div style="position:fixed;top:20px;right:20px;z-index:999999;background:#1f2937;border-radius:12px;padding:16px 20px;box-shadow:0 8px 24px rgba(0,0,0,0.4);font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,sans-serif;color:#f3f4f6;max-width:320px;border:1px solid ' + colors[result.level] + '40;"><div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;"><span style="width:28px;height:28px;border-radius:50%;background:' + colors[result.level] + '20;color:' + colors[result.level] + ';display:flex;align-items:center;justify-content:center;font-size:16px;">' + icons[result.level] + '</span><div><strong style="font-size:14px;">' + labels[result.level] + '</strong><span style="color:#9ca3af;font-size:12px;margin-left:8px;">Score: ' + result.score + '/100</span></div><span id="ls-float-close" style="margin-left:auto;cursor:pointer;color:#6b7280;font-size:18px;">\u00D7</span></div><div style="font-size:12px;color:#94a3b8;margin-bottom:6px;">' + result.domain + '</div>' + reasons + '<div style="font-size:10px;color:#4b5563;margin-top:8px;text-align:right;">LinkShield</div></div>';

  document.body.appendChild(div);
  document.getElementById("ls-float-close").onclick = function() { div.remove(); };
  setTimeout(function() { if (div.parentNode) div.remove(); }, 8000);
}

// ═══════════════════════════════════════════════════
// 6. PRIVACY AUDIT (inline)
// ═══════════════════════════════════════════════════

function runPrivacyAudit() {
  var TRACKER_DOMAINS = ["google-analytics.com","googletagmanager.com","hotjar.com","mixpanel.com","segment.com","amplitude.com","clarity.ms","doubleclick.net","googlesyndication.com","googleadservices.com","facebook.net","connect.facebook.net","criteo.com","outbrain.com","taboola.com"];

  var pageHost = window.location.hostname;
  var trackers = [];
  var seen = {};
  document.querySelectorAll("script[src],iframe[src]").forEach(function(el) {
    try {
      var h = new URL(el.src).hostname;
      if (h !== pageHost && !seen[h]) {
        for (var t of TRACKER_DOMAINS) {
          if (h === t || h.endsWith("." + t)) { trackers.push(h); seen[h] = true; break; }
        }
      }
    } catch(e){}
  });

  var cookies = document.cookie.split(";").filter(function(c) { return c.trim(); }).length;

  var sensitiveFields = 0;
  var patterns = [/email/i, /password/i, /phone|tel/i, /card|credit/i, /ssn/i];
  document.querySelectorAll("input").forEach(function(inp) {
    var combined = (inp.name || "") + " " + (inp.type || "") + " " + (inp.placeholder || "");
    for (var p of patterns) { if (p.test(combined)) { sensitiveFields++; break; } }
  });

  var fingerprinting = false;
  var html = document.documentElement.innerHTML;
  if ((html.includes("toDataURL") && html.includes("fillText")) || html.includes("AudioContext")) fingerprinting = true;

  // Grade
  var score = 100;
  score -= Math.min(trackers.length * 3, 40);
  score -= Math.min(cookies * 2, 20);
  score -= Math.min(sensitiveFields * 5, 25);
  if (fingerprinting) score -= 15;
  score = Math.max(0, Math.min(100, score));
  var grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 65 ? "C" : score >= 50 ? "D" : "F";

  var result = { grade: grade, domain: pageHost, trackers: trackers.length, cookies: cookies, sensitiveFields: sensitiveFields, fingerprinting: fingerprinting };

  // Send to background for storage
  chrome.runtime.sendMessage({ type: "PRIVACY_AUDIT_RESULT", result: result });

  // Show overlay
  showAuditOverlay(result);
}

function showAuditOverlay(r) {
  var existing = document.getElementById("ls-audit-result");
  if (existing) existing.remove();

  var gradeColors = { A: "#22c55e", B: "#86efac", C: "#f59e0b", D: "#f97316", F: "#ef4444" };
  var color = gradeColors[r.grade] || "#6b7280";

  var div = document.createElement("div");
  div.id = "ls-audit-result";
  div.innerHTML = '<div style="position:fixed;top:20px;right:20px;z-index:999999;background:#1f2937;border-radius:12px;padding:20px;box-shadow:0 8px 24px rgba(0,0,0,0.4);font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,sans-serif;color:#f3f4f6;width:300px;border:1px solid ' + color + '40;"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;"><div style="display:flex;align-items:center;gap:10px;"><span style="font-size:32px;font-weight:bold;color:' + color + ';">' + r.grade + '</span><div><div style="font-size:14px;font-weight:600;">Privacy Audit</div><div style="font-size:11px;color:#94a3b8;">' + r.domain + '</div></div></div><span id="ls-audit-close" style="cursor:pointer;color:#6b7280;font-size:18px;">\u00D7</span></div><div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px;"><div style="background:#111827;border-radius:8px;padding:8px;text-align:center;"><div style="font-size:18px;font-weight:bold;">' + r.trackers + '</div><div style="color:#94a3b8;font-size:10px;">Trackers</div></div><div style="background:#111827;border-radius:8px;padding:8px;text-align:center;"><div style="font-size:18px;font-weight:bold;">' + r.cookies + '</div><div style="color:#94a3b8;font-size:10px;">Cookies</div></div><div style="background:#111827;border-radius:8px;padding:8px;text-align:center;"><div style="font-size:18px;font-weight:bold;">' + r.sensitiveFields + '</div><div style="color:#94a3b8;font-size:10px;">Data fields</div></div><div style="background:#111827;border-radius:8px;padding:8px;text-align:center;"><div style="font-size:18px;font-weight:bold;">' + (r.fingerprinting ? "Yes" : "No") + '</div><div style="color:#94a3b8;font-size:10px;">Fingerprinting</div></div></div><div style="font-size:10px;color:#4b5563;margin-top:10px;text-align:center;">\uD83D\uDD12 Ran 100% on your device</div></div>';

  document.body.appendChild(div);
  document.getElementById("ls-audit-close").onclick = function() { div.remove(); };
  setTimeout(function() { if (div.parentNode) div.remove(); }, 15000);
}

// ═══════════════════════════════════════════════════
// 7. MESSAGE LISTENER
// ═══════════════════════════════════════════════════

chrome.runtime.onMessage.addListener(function(message) {
  if (message.type === "SHOW_CHECK_RESULT") showFloatingResult(message.result);
  if (message.type === "RUN_PRIVACY_AUDIT") runPrivacyAudit();
  if (message.type === "SHOW_WEEKLY_REPORT") {
    generateWeeklyReport().then(function(report) { showWeeklyReport(report); });
  }
  if (message.type === "SHOW_SECURITY_SCORE") {
    calculateSecurityScore().then(function(scoreData) { showSecurityScore(scoreData); });
  }
  if (message.type === "SHOW_BREACH_CHECK") {
    showBreachCheckOverlay();
  }
});

// ═══════════════════════════════════════════════════
// 8. INIT
// ═══════════════════════════════════════════════════

scanPage();

// MutationObserver for dynamic content
var observer = new MutationObserver(function(mutations) {
  var hasNew = false;
  for (var m of mutations) {
    for (var n of m.addedNodes) {
      if (n.nodeType === Node.ELEMENT_NODE && (n.tagName === "A" || (n.querySelector && n.querySelector("a")))) {
        hasNew = true; break;
      }
    }
    if (hasNew) break;
  }
  if (hasNew) {
    if (_scanTimeout) clearTimeout(_scanTimeout);
    _scanTimeout = setTimeout(scanPage, 500);
  }
});
observer.observe(document.body, { childList: true, subtree: true });

// Gmail/Outlook aha-moment
var host = window.location.hostname;
if (host.includes("mail.google.com") || host.includes("outlook.live.com") || host.includes("outlook.office")) {
  chrome.runtime.sendMessage({ type: "EMAIL_PAGE_DETECTED" });
}
