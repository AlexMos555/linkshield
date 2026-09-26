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
var _debugMode = false; // Audit extension-mv3 medium: ship quiet in prod

// Skill persona, read once and cached. Regular / Kids / Granny never see a
// raw numeric score anywhere in the product (the popup and block page
// already hide it) — Pro is the one persona that wants the number.
// Defaults to "regular" until storage answers, so the very first badges
// painted are jargon-free rather than flashing a score.
var _skillLevel = "regular";
try {
  chrome.storage.local.get(["skill_level"], function (d) {
    _skillLevel = (d && d.skill_level) || "regular";
  });
} catch (e) { /* storage unavailable — stay regular */ }

function _log() {
  if (_debugMode) console.log.apply(console, ["[Cleanway]"].concat(Array.from(arguments)));
}

/**
 * HTML-escape an untrusted string before it lands inside an innerHTML
 * template. Used for any value that originates from the API response
 * (r.detail, result.domain) or the page (host) — both are reachable
 * by an attacker if a malicious domain is checked or a malicious
 * /check response is injected by a network MITM on a misconfigured
 * box. Audit finding extension-mv3 HIGH (XSS via r.detail innerHTML).
 *
 * Always returns a string. Null/undefined becomes "" so the template
 * still renders sensibly when an optional field is missing.
 */
function _esc(s) {
  if (s == null) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Localised string in the browser's language (chrome.i18n). The text lives
 * in packages/i18n-strings (extension.badge / extension.privacy_audit);
 * scripts/test-extension-core.mjs fails CI if a key used here is missing
 * from any locale, so the key itself is only ever a last-ditch fallback.
 */
function _t(key, subs) {
  try {
    return chrome.i18n.getMessage(key, subs || []) || key;
  } catch (e) {
    return key;
  }
}

var LEVEL_LABEL_KEYS = {
  safe: "badge_label_safe",
  caution: "badge_label_caution",
  dangerous: "badge_label_dangerous",
  user_content: "badge_label_user_content",
};

function _levelLabel(level) {
  return _t(LEVEL_LABEL_KEYS[level] || "badge_label_unknown");
}

// Pro is the only persona that sees the number (see _skillLevel above), and
// only when there is one: a user-content verdict is not a risk score.
function _scoreText(result) {
  if (_skillLevel !== "pro" || typeof result.score !== "number") return "";
  return _t("badge_score", [String(Math.round(result.score))]);
}

// Reason lines in the browser's language (content/reason-labels.js); the
// English detail is the fallback for a code nobody has mapped yet.
function _reasonText(reason) {
  var labels = window.__cleanwayReasons;
  return labels ? labels.text(reason) : (reason && reason.detail) || "";
}

function _reasonsHtml(result) {
  return (result.reasons || []).slice(0, 3).map(function(r) {
    return '<div style="font-size:11px;color:#d1d5db;margin:2px 0;">\u2022 ' + _esc(_reasonText(r)) + '</div>';
  }).join("");
}

// ═══════════════════════════════════════════════════
// 1. SCAN LINKS
// ═══════════════════════════════════════════════════

// Where a link really goes. google.com/url?q=…, vk.com/away.php?to=… and
// friends are unwrapped (utils/link-target.js), so the badge judges the
// destination instead of an official wrapper. null means "nothing honest to
// badge": not a web link, or a redirector that hides its destination.
function _linkHost(href) {
  var linkTarget = window.cleanwayLinkTarget;
  if (linkTarget) {
    var target = linkTarget.resolveLinkHost(href);
    return target && target.host ? target.host : null;
  }
  try {
    var url = new URL(href);
    return /^https?:$/.test(url.protocol) ? url.hostname.toLowerCase() : null;
  } catch (e) {
    return null;
  }
}

function extractLinks() {
  var links = document.querySelectorAll("a[href]:not([" + SCANNED_ATTR + "])");
  var results = [];
  for (var i = 0; i < links.length; i++) {
    var host = _linkHost(links[i].href);
    if (!host || host.length < 4 || host === window.location.hostname) continue;
    results.push({ element: links[i], domain: host });
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

// `page` marks the check of the page the user is on, as opposed to links on
// it: the background counts a dangerous link as a warning, and only a block
// page actually shown (see _reportBlockedPage) as a blocked scam.
async function checkDomains(domains, page) {
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
    var response = await chrome.runtime.sendMessage({ type: "CHECK_DOMAINS", domains: domains, page: page === true });
    if (response && response.results && response.results.length > 0) {
      _log("Background returned", response.results.length, "results, merging");
      // Use background results where they have higher score (more info)
      for (var j = 0; j < response.results.length; j++) {
        var bgr = response.results[j];
        for (var k = 0; k < results.length; k++) {
          // The backend verdict (source:"api") is authoritative — it must win in BOTH
          // directions, so it can also CORRECT a local false-positive downward
          // (e.g. local flags a legit ccTLD bank; the API says safe). So is the
          // user-content rule (source:"platform", background/trusted-hosts.js):
          // on docs.google.com the offline score would call a page nobody
          // checked "safe". The background's own local fallback (a weaker
          // scorer) is not treated as an upgrade.
          if (results[k].domain === bgr.domain && (bgr.source === "api" || bgr.source === "platform")) {
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

// Safe (green tick), caution (yellow triangle), dangerous (red cross) and
// user content (neutral "i": anyone can publish on that host, so nobody
// checked the page).
var BADGE_STYLES = {
  safe: { cls: "ls-safe", glyph: "\u2713", aria: "badge_aria_safe", color: "#22c55e" },
  caution: { cls: "ls-caution", glyph: "\u26A0", aria: "badge_aria_caution", color: "#f59e0b" },
  dangerous: { cls: "ls-dangerous", glyph: "\u2717", aria: "badge_aria_dangerous", color: "#ef4444" },
  user_content: { cls: "ls-neutral", glyph: "i", aria: "badge_aria_user_content", color: "#94a3b8" },
};

function addBadge(linkEl, result) {
  // Already-badged check needs to look at the SIBLING after the link,
  // not inside it (we no longer inject as a child — see comment below).
  var existingNext = linkEl.nextElementSibling;
  if (existingNext && existingNext.classList && existingNext.classList.contains(BADGE_CLASS)) return;
  // A level we have no badge for is skipped, never painted red by default.
  var style = BADGE_STYLES[result.level];
  if (!style) return;
  linkEl.setAttribute(SCANNED_ATTR, "true");

  _log("Adding badge:", result.domain, "score=" + result.score, "level=" + result.level);

  var badge = document.createElement("span");
  badge.className = BADGE_CLASS;
  badge.classList.add(style.cls);
  badge.textContent = style.glyph;
  badge.setAttribute("aria-label", _t(style.aria));
  badge.setAttribute("role", "img");

  // Tooltip
  var tooltip = document.createElement("div");
  tooltip.className = "ls-tooltip";
  var score = _scoreText(result);
  tooltip.innerHTML = '<div class="ls-tooltip-inner">' +
    '<div class="ls-tooltip-header">' +
    '<span class="ls-dot" style="background:' + style.color + '"></span>' +
    '<strong>' + _esc(_levelLabel(result.level)) + '</strong>' +
    (score ? '<span class="ls-score">' + _esc(score) + '</span>' : '') + '</div>' +
    '<div class="ls-domain">' + _esc(result.domain) + '</div>' +
    _reasonsHtml(result) +
    '<div class="ls-footer">Cleanway</div></div>';
  badge.appendChild(tooltip);

  // ── Sibling, not child — was breaking real sites ──
  // The pre-fix version did:
  //     linkEl.style.position = "relative";
  //     linkEl.appendChild(badge);
  // Two real problems on production sites:
  //   1. Forced `position: relative` on every <a> overrode site CSS.
  //      Nav menus and dropdown items that relied on
  //      `position: absolute` lost their positioning → visible layout
  //      shift ("плыла вёрстка").
  //   2. Badge as CHILD of the link meant clicks could land on the
  //      badge span and event-delegated handlers like
  //      target.closest('a') would still bubble correctly, BUT sites
  //      using strict `event.target.matches(...)` checks treated the
  //      span as the click target and ignored it → "buttons don't
  //      click".
  // insertAdjacentElement('afterend') puts the badge OUTSIDE the
  // link entirely. Site layout untouched, click target unaffected.
  linkEl.insertAdjacentElement("afterend", badge);
  _log("Badge added:", result.domain, result.level, result.score);
}

// ════════════════════════════════════════════════════
// 3. BLOCK PAGE
// ════════════════════════════════════════════════════
//
// The full-screen block overlay is rendered by block-page.js (annotated
// evidence cards, cultural scam explainer, confidence chip, and the
// granny / kids / pro skill personas). It loads as a classic content
// script immediately BEFORE this one and publishes the entry point on
// the shared isolated-world global as window.__cleanwayShowBlockPage.
// The page-check in section 7 calls it. This file no longer ships its
// own stripped-down duplicate overlay.

// ═══════════════════════════════════════════════════
// 4. FLOATING RESULT (for context menu)
// ═══════════════════════════════════════════════════

function showFloatingResult(result) {
  var old = document.getElementById("ls-floating-result");
  if (old) old.remove();

  var c = { safe: "#22c55e", caution: "#f59e0b", dangerous: "#ef4444", user_content: "#94a3b8" };
  var icons = { safe: "\u2713", caution: "\u26A0", dangerous: "\u2717", user_content: "i" };
  var reasons = _reasonsHtml(result);

  var div = document.createElement("div");
  div.id = "ls-floating-result";
  div.innerHTML = '<div style="position:fixed;top:20px;right:20px;z-index:999999;background:#1f2937;border-radius:12px;padding:16px 20px;box-shadow:0 8px 24px rgba(0,0,0,0.4);font-family:-apple-system,sans-serif;color:#f3f4f6;max-width:320px;border:1px solid ' + (c[result.level] || "#333") + '40;animation:ls-slide-in 0.3s ease-out;"><div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;"><span style="width:28px;height:28px;border-radius:50%;background:' + (c[result.level] || "#333") + '20;color:' + (c[result.level] || "#999") + ';display:flex;align-items:center;justify-content:center;font-size:16px;">' + (icons[result.level] || "?") + '</span><strong style="font-size:14px;">' + _esc(_levelLabel(result.level)) +'</strong><span style="color:#9ca3af;font-size:12px;margin-left:auto;">' + _esc(_scoreText(result)) + '</span><span id="ls-float-close" style="cursor:pointer;color:#6b7280;font-size:18px;margin-left:8px;">\u00D7</span></div><div style="font-size:12px;color:#94a3b8;margin-bottom:6px;">' + _esc(result.domain) + '</div>' + reasons + '</div>';

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
  // `host` is window.location.hostname \u2014 attacker can craft a hostile
  // domain to inject HTML through it. Same defense-in-depth as the
  // block page and floating result above. (Audit extension-mv3 HIGH.)
  div.innerHTML = '<div style="position:fixed;top:20px;right:20px;z-index:999999;background:#1f2937;border-radius:12px;padding:20px;box-shadow:0 8px 24px rgba(0,0,0,0.4);font-family:-apple-system,sans-serif;color:#f3f4f6;width:300px;border:1px solid ' + color + '40;animation:ls-slide-in 0.3s ease-out;"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;"><div style="display:flex;align-items:center;gap:10px;"><span style="font-size:32px;font-weight:bold;color:' + color + ';">' + _esc(grade) + '</span><div><div style="font-size:14px;font-weight:600;">' + _esc(_t("audit_title")) + '</div><div style="font-size:11px;color:#94a3b8;">' + _esc(host) + '</div></div></div><span id="ls-audit-close" style="cursor:pointer;color:#6b7280;font-size:18px;">\u00D7</span></div><div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px;"><div style="background:#111827;border-radius:8px;padding:8px;text-align:center;"><div style="font-size:18px;font-weight:bold;">' + (parseInt(trackers.length, 10) || 0) + '</div><div style="color:#94a3b8;font-size:10px;">' + _esc(_t("audit_trackers")) + '</div></div><div style="background:#111827;border-radius:8px;padding:8px;text-align:center;"><div style="font-size:18px;font-weight:bold;">' + (parseInt(cookies, 10) || 0) + '</div><div style="color:#94a3b8;font-size:10px;">' + _esc(_t("audit_cookies")) + '</div></div><div style="background:#111827;border-radius:8px;padding:8px;text-align:center;"><div style="font-size:18px;font-weight:bold;">' + (parseInt(sensitive, 10) || 0) + '</div><div style="color:#94a3b8;font-size:10px;">' + _esc(_t("audit_data_fields")) + '</div></div><div style="background:#111827;border-radius:8px;padding:8px;text-align:center;"><div style="font-size:18px;font-weight:bold;">' + _esc(_t(fp ? "audit_yes" : "audit_no")) + '</div><div style="color:#94a3b8;font-size:10px;">' + _esc(_t("audit_fingerprint")) + '</div></div></div><div style="font-size:10px;color:#475569;margin-top:10px;text-align:center;"><button id="ls-audit-share" style="margin-top:12px;width:100%;background:' + color + ';color:#0a0e15;border:none;padding:8px 12px;border-radius:8px;font-weight:700;font-size:12px;cursor:pointer;">' + _esc(_t("audit_share")) + '</button><div style="font-size:10px;color:#475569;margin-top:10px;text-align:center;">\uD83D\uDD12 ' + _esc(_t("audit_on_device")) + '</div></div>';

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

// Tell the background a block page is on screen for this page. That — not
// a red badge on a link — is what counts as a blocked scam: the background
// bumps the "Scams blocked" tally once per site per day, puts this tab's
// credential guard into strict mode and, for a signed-in user and only when
// the API itself said "dangerous", syncs the account counter and alerts the
// family.
function _reportBlockedPage(domain) {
  try {
    chrome.runtime.sendMessage({ type: "PAGE_BLOCKED", domain: domain }).catch(function() {});
  } catch (e) {
    _log("Could not report the block:", e);
  }
}

_log("Content script loaded on", window.location.hostname);

// Check current page first
(async function() {
  try {
    var domain = window.location.hostname.toLowerCase();
    if (!domain || domain === "localhost" || domain.length < 4) return;

    // ── Never auto-block our own domains ──
    // Defense-in-depth: if api.cleanway.ai ever returns level="dangerous"
    // for cleanway.ai itself (server-side bug, ML false-positive, race
    // during a deploy), the user would see our scary full-page block
    // overlay on our own marketing / pricing page. Game over for trust.
    // The tiny client-side allow-list catches that worst case without
    // affecting normal API verdicts for any other domain.
    if (domain === "cleanway.ai" || domain.endsWith(".cleanway.ai")) return;

    var results = await checkDomains([domain], true);
    if (results && results[0] && results[0].level === "dangerous") {
      // Rich overlay lives in block-page.js, which loads as a classic
      // content script before this one and publishes the renderer on the
      // shared isolated-world global. Guard defensively: if it somehow
      // failed to load we skip the overlay rather than throw (which would
      // also kill the link-scanning below).
      if (typeof window.__cleanwayShowBlockPage === "function") {
        window.__cleanwayShowBlockPage(results[0]);
        _reportBlockedPage(domain);
      } else {
        _log("block-page.js not loaded — block overlay unavailable for", domain);
      }
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
