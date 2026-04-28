/**
 * Cleanway Content Script
 *
 * 1. Scan all links → add safety badges
 * 2. Check current page → block if dangerous
 * 3. Listen for commands (context menu, keyboard)
 */

var BADGE_CLASS = "ls-badge";
var SCANNED_ATTR = "data-ls-scanned";
var _scanTimeout = null;
var _debugMode = true; // Set false in production

function _log() {
  if (_debugMode) console.log.apply(console, ["[Cleanway]"].concat(Array.from(arguments)));
}

// ═══════════════════════════════════════════════════
// 1. SCAN LINKS
// ═══════════════════════════════════════════════════

function extractLinks() {
  var links = document.querySelectorAll("a[href]:not([" + SCANNED_ATTR + "])");
  var results = [];
  for (var i = 0; i < links.length; i++) {
    var link = links[i];
    try {
      var url = new URL(link.href);
      if (url.protocol === "javascript:" || url.protocol === "mailto:" || url.protocol === "tel:") continue;
      if (url.hostname === window.location.hostname) continue;
      if (!url.hostname || url.hostname.length < 4) continue;
      results.push({ element: link, domain: url.hostname.toLowerCase() });
    } catch (e) {}
  }
  return results;
}

async function scanPage() {
  var links = extractLinks();
  if (links.length === 0) return;
  _log("Scanning", links.length, "links");

  var domainMap = new Map();
  for (var i = 0; i < links.length; i++) {
    var link = links[i];
    if (!domainMap.has(link.domain)) domainMap.set(link.domain, []);
    domainMap.get(link.domain).push(link.element);
  }

  var domains = Array.from(domainMap.keys());

  for (var i = 0; i < domains.length; i += 30) {
    var batch = domains.slice(i, i + 30);
    var results = await checkDomains(batch);
    if (results) {
      for (var j = 0; j < results.length; j++) {
        var r = results[j];
        var elements = domainMap.get(r.domain) || [];
        for (var k = 0; k < elements.length; k++) {
          addBadge(elements[k], r);
        }
      }
    }
  }
}

async function checkDomains(domains) {
  var results = [];

  // ALWAYS score locally first — guaranteed to work
  for (var i = 0; i < domains.length; i++) {
    try {
      var lr = localScore(domains[i]);
      results.push(lr);
      _log("Local score:", domains[i], "→ score=" + lr.score, lr.level);
    } catch (e) {
      _log("localScore error for", domains[i], e);
      results.push({ domain: domains[i], score: 0, level: "safe", reasons: [], source: "error" });
    }
  }

  // Try to get better results from background (async, don't wait too long)
  try {
    var response = await chrome.runtime.sendMessage({ type: "CHECK_DOMAINS", domains: domains });
    if (response && response.results && response.results.length > 0) {
      _log("Background returned", response.results.length, "results, merging");
      // Use background results where they have higher score (more info)
      for (var j = 0; j < response.results.length; j++) {
        var bgr = response.results[j];
        for (var k = 0; k < results.length; k++) {
          if (results[k].domain === bgr.domain && bgr.score >= results[k].score) {
            results[k] = bgr;
            _log("Upgraded from background:", bgr.domain, "→ score=" + bgr.score, bgr.level);
          }
        }
      }
    }
  } catch (e) {
    _log("Background unavailable (using local scores):", e.message);
  }

  return results;
}

// ═══════════════════════════════════════════════════
// 2. BADGES
// ═══════════════════════════════════════════════════

function addBadge(linkEl, result) {
  if (linkEl.querySelector("." + BADGE_CLASS)) return;
  linkEl.setAttribute(SCANNED_ATTR, "true");

  // Show ALL badges — safe (green), caution (yellow), dangerous (red)
  _log("Adding badge:", result.domain, "score=" + result.score, "level=" + result.level);

  var badge = document.createElement("span");
  badge.className = BADGE_CLASS;

  if (result.level === "safe") {
    badge.classList.add("ls-safe");
    badge.textContent = "\u2713";
    badge.title = "Safe (score: " + result.score + ")";
  } else if (result.level === "caution") {
    badge.classList.add("ls-caution");
    badge.textContent = "\u26A0";
    badge.title = "Caution (score: " + result.score + ")";
  } else {
    badge.classList.add("ls-dangerous");
    badge.textContent = "\u2717";
    badge.title = "DANGEROUS (score: " + result.score + ")";
  }

  // Tooltip
  var tooltip = document.createElement("div");
  tooltip.className = "ls-tooltip";
  var reasons = (result.reasons || []).slice(0, 3).map(function(r) {
    return '<div style="font-size:11px;color:#d1d5db;margin:2px 0;">\u2022 ' + r.detail + '</div>';
  }).join("");
  var colors = { safe: "#22c55e", caution: "#f59e0b", dangerous: "#ef4444" };
  var labels = { safe: "Safe", caution: "Caution", dangerous: "Dangerous" };
  tooltip.innerHTML = '<div class="ls-tooltip-inner">' +
    '<div class="ls-tooltip-header">' +
    '<span class="ls-dot" style="background:' + (colors[result.level] || "#666") + '"></span>' +
    '<strong>' + (labels[result.level] || "Unknown") + '</strong>' +
    '<span class="ls-score">Score: ' + result.score + '/100</span></div>' +
    '<div class="ls-domain">' + result.domain + '</div>' +
    reasons +
    '<div class="ls-footer">Cleanway</div></div>';
  badge.appendChild(tooltip);

  linkEl.style.position = "relative";
  linkEl.appendChild(badge);
  _log("Badge added:", result.domain, result.level, result.score);
}

// ═══════════════════════════════════════════════════
// 3. BLOCK PAGE
// ═══════════════════════════════════════════════════

function showBlockPage(result) {
  if (document.getElementById("ls-block-overlay")) return;
  var reasons = (result.reasons || []).slice(0, 4).map(function(r) {
    return '<div style="display:flex;align-items:flex-start;gap:8px;margin:8px 0;"><span style="color:#ef4444;">\u26A0</span><span>' + r.detail + '</span></div>';
  }).join("");

  var overlay = document.createElement("div");
  overlay.id = "ls-block-overlay";
  overlay.innerHTML = '<div style="position:fixed;inset:0;z-index:2147483647;background:#0f172aee;backdrop-filter:blur(8px);display:flex;align-items:center;justify-content:center;font-family:-apple-system,sans-serif;color:#e2e8f0;"><div style="max-width:480px;text-align:center;padding:40px 24px;"><div style="font-size:64px;margin-bottom:20px;">\u{1F6E1}</div><h1 style="font-size:28px;font-weight:800;color:#f8fafc;margin:0 0 8px;">Dangerous Site</h1><p style="font-size:16px;color:#94a3b8;margin:0 0 24px;">Cleanway blocked <strong style="color:#ef4444;">' + result.domain + '</strong> (score: ' + result.score + '/100)</p><div style="background:#1e293b;border-radius:12px;padding:16px;text-align:left;margin-bottom:24px;font-size:14px;border:1px solid #ef444440;">' + (reasons || 'Multiple risk signals detected') + '</div><button id="ls-go-back" style="background:#22c55e;color:#052e16;border:none;border-radius:10px;padding:14px 32px;font-size:16px;font-weight:700;cursor:pointer;width:100%;margin-bottom:8px;">\u2190 Go Back</button><button id="ls-proceed" style="background:transparent;color:#64748b;border:1px solid #334155;border-radius:10px;padding:12px 32px;font-size:14px;cursor:pointer;width:100%;opacity:0.5;" disabled>Proceed anyway (3s)</button></div></div>';

  document.body.appendChild(overlay);
  document.body.style.overflow = "hidden";
  document.getElementById("ls-go-back").onclick = function() { history.back(); };

  var cd = 3;
  var btn = document.getElementById("ls-proceed");
  var iv = setInterval(function() {
    cd--;
    if (cd <= 0) {
      clearInterval(iv);
      btn.textContent = "I understand \u2014 proceed";
      btn.disabled = false;
      btn.style.opacity = "1";
      btn.onclick = function() { overlay.remove(); document.body.style.overflow = ""; };
    } else {
      btn.textContent = "Proceed anyway (" + cd + "s)";
    }
  }, 1000);
}

// ═══════════════════════════════════════════════════
// 4. FLOATING RESULT (for context menu)
// ═══════════════════════════════════════════════════

function showFloatingResult(result) {
  var old = document.getElementById("ls-floating-result");
  if (old) old.remove();

  var c = { safe: "#22c55e", caution: "#f59e0b", dangerous: "#ef4444" };
  var icons = { safe: "\u2713", caution: "\u26A0", dangerous: "\u2717" };
  var labels = { safe: "Safe", caution: "Caution", dangerous: "Dangerous" };
  var reasons = (result.reasons || []).slice(0, 3).map(function(r) {
    return '<div style="font-size:11px;color:#d1d5db;margin:2px 0;">\u2022 ' + r.detail + '</div>';
  }).join("");

  var div = document.createElement("div");
  div.id = "ls-floating-result";
  div.innerHTML = '<div style="position:fixed;top:20px;right:20px;z-index:999999;background:#1f2937;border-radius:12px;padding:16px 20px;box-shadow:0 8px 24px rgba(0,0,0,0.4);font-family:-apple-system,sans-serif;color:#f3f4f6;max-width:320px;border:1px solid ' + (c[result.level] || "#333") + '40;animation:ls-slide-in 0.3s ease-out;"><div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;"><span style="width:28px;height:28px;border-radius:50%;background:' + (c[result.level] || "#333") + '20;color:' + (c[result.level] || "#999") + ';display:flex;align-items:center;justify-content:center;font-size:16px;">' + (icons[result.level] || "?") + '</span><strong style="font-size:14px;">' + (labels[result.level] || "?") + '</strong><span style="color:#9ca3af;font-size:12px;margin-left:auto;">Score: ' + result.score + '</span><span id="ls-float-close" style="cursor:pointer;color:#6b7280;font-size:18px;margin-left:8px;">\u00D7</span></div><div style="font-size:12px;color:#94a3b8;margin-bottom:6px;">' + result.domain + '</div>' + reasons + '</div>';

  document.body.appendChild(div);
  document.getElementById("ls-float-close").onclick = function() { div.remove(); };
  setTimeout(function() { if (div.parentNode) div.remove(); }, 8000);
}

// ═══════════════════════════════════════════════════
// 5. PRIVACY AUDIT (inline)
// ═══════════════════════════════════════════════════

function runPrivacyAudit() {
  var trackers = [];
  var seen = {};
  var TRACKER_DOMAINS = ["google-analytics.com","googletagmanager.com","hotjar.com","mixpanel.com","doubleclick.net","facebook.net","connect.facebook.net","criteo.com","clarity.ms","amplitude.com","segment.com"];
  var host = window.location.hostname;

  document.querySelectorAll("script[src],iframe[src]").forEach(function(el) {
    try {
      var h = new URL(el.src).hostname;
      if (h !== host && !seen[h]) {
        for (var t of TRACKER_DOMAINS) {
          if (h === t || h.endsWith("." + t)) { trackers.push(h); seen[h] = true; break; }
        }
      }
    } catch(e){}
  });

  var cookies = document.cookie.split(";").filter(function(c) { return c.trim(); }).length;
  var sensitive = 0;
  var pats = [/email/i, /password/i, /phone|tel/i, /card|credit/i];
  document.querySelectorAll("input").forEach(function(inp) {
    var s = (inp.name || "") + " " + (inp.type || "") + " " + (inp.placeholder || "");
    for (var p of pats) { if (p.test(s)) { sensitive++; break; } }
  });

  var fp = false;
  var html = document.documentElement.innerHTML;
  if ((html.includes("toDataURL") && html.includes("fillText")) || html.includes("AudioContext")) fp = true;

  var score = 100 - Math.min(trackers.length * 3, 40) - Math.min(cookies * 2, 20) - Math.min(sensitive * 5, 25) - (fp ? 15 : 0);
  score = Math.max(0, Math.min(100, score));
  var grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 65 ? "C" : score >= 50 ? "D" : "F";
  var gradeColors = { A: "#22c55e", B: "#86efac", C: "#f59e0b", D: "#f97316", F: "#ef4444" };
  var color = gradeColors[grade] || "#666";

  var old = document.getElementById("ls-audit-result");
  if (old) old.remove();

  // Build share URL — viral asset on cleanway.ai/audit/{host}/grade/{letter}.
  // OG image + canonical landing page exist at this path; the button
  // opens that page in a new tab so the user can share it socially.
  var shareUrl = "https://cleanway.ai/audit/" + encodeURIComponent(host) + "/grade/" + grade;

  var div = document.createElement("div");
  div.id = "ls-audit-result";
  div.innerHTML = '<div style="position:fixed;top:20px;right:20px;z-index:999999;background:#1f2937;border-radius:12px;padding:20px;box-shadow:0 8px 24px rgba(0,0,0,0.4);font-family:-apple-system,sans-serif;color:#f3f4f6;width:300px;border:1px solid ' + color + '40;animation:ls-slide-in 0.3s ease-out;"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;"><div style="display:flex;align-items:center;gap:10px;"><span style="font-size:32px;font-weight:bold;color:' + color + ';">' + grade + '</span><div><div style="font-size:14px;font-weight:600;">Privacy Audit</div><div style="font-size:11px;color:#94a3b8;">' + host + '</div></div></div><span id="ls-audit-close" style="cursor:pointer;color:#6b7280;font-size:18px;">\u00D7</span></div><div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px;"><div style="background:#111827;border-radius:8px;padding:8px;text-align:center;"><div style="font-size:18px;font-weight:bold;">' + trackers.length + '</div><div style="color:#94a3b8;font-size:10px;">Trackers</div></div><div style="background:#111827;border-radius:8px;padding:8px;text-align:center;"><div style="font-size:18px;font-weight:bold;">' + cookies + '</div><div style="color:#94a3b8;font-size:10px;">Cookies</div></div><div style="background:#111827;border-radius:8px;padding:8px;text-align:center;"><div style="font-size:18px;font-weight:bold;">' + sensitive + '</div><div style="color:#94a3b8;font-size:10px;">Data fields</div></div><div style="background:#111827;border-radius:8px;padding:8px;text-align:center;"><div style="font-size:18px;font-weight:bold;">' + (fp ? "Yes" : "No") + '</div><div style="color:#94a3b8;font-size:10px;">Fingerprint</div></div></div><div style="font-size:10px;color:#475569;margin-top:10px;text-align:center;"><button id="ls-audit-share" style="margin-top:12px;width:100%;background:' + color + ';color:#0a0e15;border:none;padding:8px 12px;border-radius:8px;font-weight:700;font-size:12px;cursor:pointer;">Share grade</button><div style="font-size:10px;color:#475569;margin-top:10px;text-align:center;">\uD83D\uDD12 Ran on your device</div></div>';

  document.body.appendChild(div);
  document.getElementById("ls-audit-close").onclick = function() { div.remove(); };
  var shareBtn = document.getElementById("ls-audit-share");
  if (shareBtn) {
    shareBtn.onclick = function() {
      // Ask the background to open the tab — content scripts can't reliably
      // open windows on every host (popup blockers, sandboxed contexts).
      try {
        if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({ type: "OPEN_TAB", url: shareUrl });
          return;
        }
      } catch (e) {}
      window.open(shareUrl, "_blank", "noopener");
    };
  }
  setTimeout(function() { if (div.parentNode) div.remove(); }, 15000);
}

// ═══════════════════════════════════════════════════
// 6. MESSAGE LISTENER
// ═══════════════════════════════════════════════════

chrome.runtime.onMessage.addListener(function(message) {
  _log("Message received:", message.type);
  if (message.type === "SHOW_CHECK_RESULT") showFloatingResult(message.result);
  if (message.type === "RUN_PRIVACY_AUDIT") runPrivacyAudit();
  if (message.type === "SHOW_WEEKLY_REPORT" && typeof generateWeeklyReport === "function") {
    generateWeeklyReport().then(function(r) { showWeeklyReport(r); });
  }
  if (message.type === "SHOW_SECURITY_SCORE" && typeof calculateSecurityScore === "function") {
    calculateSecurityScore().then(function(s) { showSecurityScore(s); });
  }
  if (message.type === "SHOW_BREACH_CHECK" && typeof showBreachCheckOverlay === "function") {
    showBreachCheckOverlay();
  }
});

// ═══════════════════════════════════════════════════
// 7. INIT
// ═══════════════════════════════════════════════════

_log("Content script loaded on", window.location.hostname);

// Check current page first
(async function() {
  try {
    var domain = window.location.hostname.toLowerCase();
    if (!domain || domain === "localhost" || domain.length < 4) return;

    var results = await checkDomains([domain]);
    if (results && results[0] && results[0].level === "dangerous") {
      showBlockPage(results[0]);
    }
  } catch(e) {
    _log("Page check error:", e);
  }
})();

// Scan links
setTimeout(function() {
  scanPage();
}, 500);

// Watch for new links (SPA, dynamic content)
var observer = new MutationObserver(function(mutations) {
  var hasNew = false;
  for (var m of mutations) {
    for (var n of m.addedNodes) {
      if (n.nodeType === 1 && (n.tagName === "A" || (n.querySelector && n.querySelector("a")))) {
        hasNew = true; break;
      }
    }
    if (hasNew) break;
  }
  if (hasNew) {
    if (_scanTimeout) clearTimeout(_scanTimeout);
    _scanTimeout = setTimeout(scanPage, 800);
  }
});
observer.observe(document.body, { childList: true, subtree: true });

// Gmail/Outlook detection
var h = window.location.hostname;
if (h.includes("mail.google.com") || h.includes("outlook")) {
  try { chrome.runtime.sendMessage({ type: "EMAIL_PAGE_DETECTED" }); } catch(e) {}
}

// Inject animation CSS
var style = document.createElement("style");
style.textContent = "@keyframes ls-slide-in{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}";
document.head.appendChild(style);
