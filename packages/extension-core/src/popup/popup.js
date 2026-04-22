/**
 * Cleanway Popup — Regular Mode (default) v2
 * Логика: 1 главный статус + 2 secondary + expandable more.
 * Никакого жаргона. i18n через chrome.i18n.getMessage с fallback.
 */

// ─── i18n helpers ─────────────────────────────────────────────
// chrome.i18n.getMessage читает из _locales/<lang>/messages.json
// Fallback: inline English для preview panel и dev.

var FALLBACK_EN = {
  status_scanning: "Checking this page…",
  status_safe_title: "This page is safe",
  status_safe_subtitle: "No scam links found on $1",
  status_warning_title: "Some links look suspicious",
  status_warning_subtitle: "$1 links on this page need a closer look",
  status_danger_title: "This is a scam site",
  status_danger_subtitle: "$1 is pretending to be someone else to steal your information",
  status_unknown_title: "Couldn't check this page",
  status_unknown_subtitle: "Try again in a moment",
  aha_found_scams: "I found $1 scam links your browser missed",
  upgrade_free_count: "Free: $1 of $2 checks today",
  recent_empty: "Nothing found yet — browse normally, I'm watching.",
  // static i18n keys (for applyI18n fallback when chrome.i18n isn't available)
  popup_brand: "Cleanway",
  popup_settings_title: "Settings",
  action_close_tab: "Close this page",
  action_audit: "What this site collects",
  action_week: "My week",
  action_more: "More",
  action_breach: "Check email leak",
  action_score: "My safety level",
  action_trust: "Always trust this site",
  action_report: "Report wrong result",
  stats_label_blocked: "Scams blocked",
  stats_label_warned: "Warnings",
  stats_label_checked: "Links checked",
  upgrade_cta: "Upgrade",
  onboarding_welcome: "Welcome to Cleanway!",
  onboarding_tip: "I'll check every link you see. Dangerous ones get a red mark. Try right-clicking a link → \"Check with Cleanway\".",
  offline_warning: "Offline — using basic protection",
  trust_footer: "Your data never leaves this device",
};

function interpolate(str, subs) {
  if (!subs || !subs.length) return str;
  var out = str;
  for (var i = 0; i < subs.length; i++) {
    out = out.replace("$" + (i + 1), subs[i]);
  }
  return out;
}

function t(key, substitutions) {
  // Try chrome.i18n first (runs in real extension context)
  try {
    if (typeof chrome !== "undefined" && chrome.i18n && chrome.i18n.getMessage) {
      var msg = chrome.i18n.getMessage(key, substitutions || []);
      if (msg) return msg;
    }
  } catch (e) { /* preview panel / no chrome API */ }
  // Fallback: inline English with $1/$2 interpolation
  return interpolate(FALLBACK_EN[key] || key, substitutions);
}

// Apply data-i18n attributes on static elements
function applyI18n() {
  var nodes = document.querySelectorAll("[data-i18n]");
  for (var i = 0; i < nodes.length; i++) {
    var key = nodes[i].getAttribute("data-i18n");
    var msg = t(key);
    if (msg && msg !== key) nodes[i].textContent = msg;
  }
  var titled = document.querySelectorAll("[data-i18n-title]");
  for (var j = 0; j < titled.length; j++) {
    var tkey = titled[j].getAttribute("data-i18n-title");
    var tmsg = t(tkey);
    if (tmsg && tmsg !== tkey) titled[j].setAttribute("title", tmsg);
  }
}

// ─── Icons for status states ──────────────────────────────────
var STATUS_ICONS = {
  safe: "\u2713",      // ✓
  warning: "\u26A0",   // ⚠
  danger: "\u2717",    // ✗
  unknown: "?",
};

// ─── Small DOM helpers ────────────────────────────────────────
function $(id) { return document.getElementById(id); }
function fmt(n) { return (n || 0).toLocaleString(); }

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, function(c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}

function fmtRelative(ts) {
  if (!ts) return "";
  var diff = (Date.now() - ts) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return Math.floor(diff / 60) + "m";
  if (diff < 86400) return Math.floor(diff / 3600) + "h";
  return Math.floor(diff / 86400) + "d";
}

// ─── State machine: set main status card ──────────────────────
function setStatus(state, title, subtitle) {
  var card = $("status-card");
  var icon = $("status-icon");
  var titleEl = $("status-title");
  var subEl = $("status-subtitle");
  var primary = $("primary-action");

  card.setAttribute("data-state", state);

  if (state === "scanning") {
    icon.innerHTML = '<div class="spinner"></div>';
  } else {
    icon.textContent = STATUS_ICONS[state] || "?";
  }
  titleEl.textContent = title;
  subEl.textContent = subtitle || "";

  // "Close this page" only on danger
  primary.hidden = state !== "danger";
}

function levelToState(level) {
  if (level === "safe") return "safe";
  if (level === "caution" || level === "suspicious") return "warning";
  if (level === "dangerous" || level === "phishing") return "danger";
  return "unknown";
}

// ─── Stats ────────────────────────────────────────────────────
async function loadStats() {
  try {
    var stats = await chrome.runtime.sendMessage({ type: "GET_STATS" });
    if (!stats) return;
    $("total-checks").textContent = fmt(stats.total_checks);
    $("threats-blocked").textContent = fmt(stats.threats_blocked);
    $("threats-warned").textContent = fmt(stats.threats_warned);
  } catch (e) { /* background not ready */ }
}

// ─── Check current tab ────────────────────────────────────────
async function loadPageStatus() {
  var tabs = [];
  try { tabs = await chrome.tabs.query({ active: true, currentWindow: true }); } catch (e) {}
  var tab = tabs[0];
  if (!tab || !tab.url) {
    setStatus("unknown", t("status_unknown_title"), t("status_unknown_subtitle"));
    return;
  }

  var url;
  try { url = new URL(tab.url); } catch (e) {
    setStatus("unknown", t("status_unknown_title"), t("status_unknown_subtitle"));
    return;
  }

  // chrome:// and about: aren't checkable
  if (!/^https?:$/.test(url.protocol)) {
    setStatus("safe", t("status_safe_title"), "");
    return;
  }

  var domain = url.hostname;

  try {
    var resp = await chrome.runtime.sendMessage({ type: "CHECK_DOMAINS", domains: [domain] });
    var r = resp && resp.results && resp.results[0];
    if (!r) {
      setStatus("unknown", t("status_unknown_title"), t("status_unknown_subtitle"));
      return;
    }
    var state = levelToState(r.level);
    var title, subtitle;
    if (state === "safe") {
      title = t("status_safe_title");
      subtitle = t("status_safe_subtitle", [domain]);
    } else if (state === "warning") {
      title = t("status_warning_title");
      subtitle = t("status_warning_subtitle", [String((r.suspicious_links_count || 0) || 1)]);
    } else if (state === "danger") {
      title = t("status_danger_title");
      subtitle = t("status_danger_subtitle", [domain]);
    } else {
      title = t("status_unknown_title");
      subtitle = t("status_unknown_subtitle");
    }
    setStatus(state, title, subtitle);
  } catch (e) {
    setStatus("unknown", t("status_unknown_title"), t("status_unknown_subtitle"));
    $("offline-banner").hidden = false;
  }
}

// ─── Recent threats (last 5) ──────────────────────────────────
async function loadRecentThreats() {
  var container = $("recent-threats");
  try {
    var data = await chrome.storage.local.get(["recent_threats"]);
    var threats = (data.recent_threats || []).slice(0, 5);
    if (!threats.length) {
      container.innerHTML = '<div class="threat-item" style="color:var(--text-dim);justify-content:center;font-size:11px;">' +
        escapeHtml(t("recent_empty")) + '</div>';
      return;
    }
    container.innerHTML = threats.map(function(th) {
      return '<div class="threat-item">' +
        '<span style="color:var(--red-text)" aria-hidden="true">&#x26A0;</span>' +
        '<span class="threat-domain">' + escapeHtml(th.domain) + '</span>' +
        '<span class="threat-time">' + fmtRelative(th.ts) + '</span>' +
        '</div>';
    }).join("");
  } catch (e) { /* storage not available */ }
}

// ─── Aha-moment banner ────────────────────────────────────────
async function loadAhaBanner() {
  try {
    var data = await chrome.storage.local.get(["aha_count", "aha_dismissed"]);
    if (data.aha_dismissed) return;
    var count = data.aha_count || 0;
    if (count > 0) {
      $("aha-banner").hidden = false;
      $("aha-text").textContent = t("aha_found_scams", [String(count)]);
    }
  } catch (e) {}
}

// ─── Upgrade banner for free users near threshold ─────────────
async function loadUpgradeBanner() {
  try {
    var data = await chrome.storage.local.get(["checks_today", "tier"]);
    if (data.tier && data.tier !== "free") return;
    var used = data.checks_today || 0;
    var limit = 10;
    if (used >= limit - 3) {
      $("upgrade-banner").hidden = false;
      $("upgrade-text").textContent = t("upgrade_free_count", [String(used), String(limit)]);
    }
  } catch (e) {}
}

// ─── Onboarding tip (first open only) ─────────────────────────
async function loadOnboardingTip() {
  try {
    var data = await chrome.storage.local.get(["onboarding_done"]);
    if (!data.onboarding_done) $("onboarding-tip").hidden = false;
  } catch (e) {}
  var dismissBtn = $("dismiss-tip");
  if (!dismissBtn) return;
  dismissBtn.addEventListener("click", async function() {
    $("onboarding-tip").hidden = true;
    try { await chrome.storage.local.set({ onboarding_done: true }); } catch (e) {}
  });
}

// ─── Button wiring ────────────────────────────────────────────
async function sendToActiveTab(message) {
  try {
    var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs[0]) await chrome.tabs.sendMessage(tabs[0].id, message);
  } catch (e) { /* tab unreachable */ }
}

function wireButtons() {
  var settings = $("btn-settings");
  if (settings) settings.addEventListener("click", function() {
    try { chrome.runtime.openOptionsPage(); } catch (e) {}
  });

  var closeBtn = $("btn-close-tab");
  if (closeBtn) closeBtn.addEventListener("click", async function() {
    try {
      var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs[0]) await chrome.tabs.remove(tabs[0].id);
    } catch (e) {}
  });

  var audit = $("btn-audit");
  if (audit) audit.addEventListener("click", async function() {
    await sendToActiveTab({ type: "SHOW_AUDIT" });
    window.close();
  });

  var week = $("btn-week");
  if (week) week.addEventListener("click", async function() {
    await sendToActiveTab({ type: "SHOW_WEEKLY_REPORT" });
    window.close();
  });

  var breach = $("btn-breach");
  if (breach) breach.addEventListener("click", async function() {
    await sendToActiveTab({ type: "SHOW_BREACH_CHECK" });
    window.close();
  });

  var score = $("btn-score");
  if (score) score.addEventListener("click", async function() {
    await sendToActiveTab({ type: "SHOW_SECURITY_SCORE" });
    window.close();
  });

  var trust = $("btn-trust");
  if (trust) trust.addEventListener("click", async function() {
    try {
      var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tabs[0] || !tabs[0].url) return;
      var domain = new URL(tabs[0].url).hostname;
      var data = await chrome.storage.local.get(["trusted_domains"]);
      var trusted = data.trusted_domains || [];
      if (trusted.indexOf(domain) === -1) {
        trusted.push(domain);
        await chrome.storage.local.set({ trusted_domains: trusted });
      }
    } catch (e) {}
  });

  var report = $("btn-report");
  if (report) report.addEventListener("click", async function() {
    await sendToActiveTab({ type: "SHOW_REPORT_DIALOG" });
    window.close();
  });
}

// ─── Health check (offline indicator) ─────────────────────────
async function checkApiHealth() {
  var base = (typeof window !== "undefined" && window.CLEANWAY_API_BASE)
    ? window.CLEANWAY_API_BASE
    : "https://api.cleanway.ai";
  try {
    var r = await fetch(base + "/health", { method: "GET" });
    if (!r.ok) $("offline-banner").hidden = false;
  } catch (e) {
    $("offline-banner").hidden = false;
  }
}

// ─── Preview mode: simulate states for Launch preview panel ───
// When running standalone (not loaded as real extension), show a demo state
// so reviewer can see the design без real chrome.* APIs.
function isPreviewMode() {
  return typeof chrome === "undefined" || !chrome.tabs;
}

function runPreviewDemo() {
  // Default to "safe" state for preview; add ?state=safe|warning|danger|scanning in URL to switch
  var params = new URLSearchParams(window.location.search);
  var state = params.get("state") || "safe";
  var demos = {
    scanning: { title: t("status_scanning"), subtitle: "" },
    safe: { title: t("status_safe_title"), subtitle: t("status_safe_subtitle", ["example.com"]) },
    warning: { title: t("status_warning_title"), subtitle: t("status_warning_subtitle", ["3"]) },
    danger: { title: t("status_danger_title"), subtitle: t("status_danger_subtitle", ["fake-bank.com"]) },
  };
  var d = demos[state] || demos.safe;
  setStatus(state, d.title, d.subtitle);
  $("total-checks").textContent = "247";
  $("threats-blocked").textContent = "12";
  $("threats-warned").textContent = "34";
  var recent = $("recent-threats");
  if (recent) recent.innerHTML =
    '<div class="threat-item"><span style="color:var(--red-text)">&#x26A0;</span>' +
    '<span class="threat-domain">fake-paypal.co</span><span class="threat-time">5m</span></div>' +
    '<div class="threat-item"><span style="color:var(--red-text)">&#x26A0;</span>' +
    '<span class="threat-domain">sberbank-ru.io</span><span class="threat-time">2h</span></div>';
  if (state === "danger") {
    $("aha-banner").hidden = false;
    $("aha-text").textContent = t("aha_found_scams", ["3"]);
  }
}

// ─── Skill Level — font scale + mode-aware CSS class ─────────
function applySkillLevelStyles() {
  try {
    chrome.storage.local.get(["skill_level", "font_scale"], function(data) {
      var skill = (data && data.skill_level) || "regular";
      var scale = (data && typeof data.font_scale === "number") ? data.font_scale : 1.0;
      // Clamp defensively — reject corrupted storage values
      if (scale < 0.8 || scale > 2.5) { scale = 1.0; }
      // Mode-aware hook for CSS (e.g. body.skill-granny { … })
      document.body.classList.remove(
        "skill-kids", "skill-regular", "skill-granny", "skill-pro"
      );
      document.body.classList.add("skill-" + skill);
      // Font scaling via CSS custom property
      document.documentElement.style.setProperty("--cleanway-font-scale", scale);
      document.documentElement.style.fontSize = (16 * scale) + "px";
    });
  } catch (e) {
    // Preview mode (no chrome.storage) — just apply default
    document.documentElement.style.setProperty("--cleanway-font-scale", 1.0);
  }
}

// ─── Init ─────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", function() {
  applySkillLevelStyles();
  applyI18n();
  wireButtons();

  if (isPreviewMode()) {
    runPreviewDemo();
    return;
  }

  // Real extension mode — kick off loads in parallel
  loadPageStatus();
  loadStats();
  loadRecentThreats();
  loadAhaBanner();
  loadUpgradeBanner();
  loadOnboardingTip();
  checkApiHealth();
});
