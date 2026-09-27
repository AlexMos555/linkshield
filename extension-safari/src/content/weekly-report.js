/**
 * Weekly Report — 100% On-Device Generation
 *
 * Generates a weekly security report from local check history.
 * Only aggregate NUMBERS are sent to server (for percentile).
 * Full details stay on device.
 */

/**
 * Generate weekly report from local storage
 * @returns {WeeklyReport}
 */
async function generateWeeklyReport() {
  var data = await chrome.storage.local.get(["stats", "recent_threats"]);
  var stats = data.stats || {};
  var threats = data.recent_threats || [];

  // Calculate this week's stats
  var now = new Date();
  var weekAgo = new Date(now - 7 * 24 * 60 * 60 * 1000);

  var weekThreats = threats.filter(function(t) {
    return new Date(t.time) >= weekAgo;
  });

  var dangerousCount = weekThreats.filter(function(t) { return t.level === "dangerous"; }).length;
  var cautionCount = weekThreats.filter(function(t) { return t.level === "caution"; }).length;

  // Top threatened domains
  var domainCounts = {};
  weekThreats.forEach(function(t) {
    domainCounts[t.domain] = (domainCounts[t.domain] || 0) + 1;
  });
  var topThreats = Object.entries(domainCounts)
    .sort(function(a, b) { return b[1] - a[1]; })
    .slice(0, 5)
    .map(function(e) { return { domain: e[0], count: e[1] }; });

  return {
    period: {
      start: weekAgo.toISOString().split("T")[0],
      end: now.toISOString().split("T")[0],
    },
    totalChecks: stats.total_checks || 0,
    threatsBlocked: dangerousCount,
    warnings: cautionCount,
    topThreats: topThreats,
    generatedAt: now.toISOString(),
    onDevice: true,
  };
}

// Text in the browser's language (packages/i18n-strings extension.weekly).
// Named per file: content scripts share one global scope.
function _weeklyT(key, subs) {
  try {
    return chrome.i18n.getMessage(key, subs || []) || key;
  } catch (e) {
    return key;
  }
}

function _weeklyEsc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, function(c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}

// "2026-09-20" \u2192 the date as the reader writes it (20.09.2026 in Russian).
function _weeklyDate(isoDay) {
  try {
    return new Date(isoDay + "T00:00:00").toLocaleDateString(chrome.i18n.getUILanguage());
  } catch (e) {
    return isoDay;
  }
}

/**
 * Show weekly report as floating overlay
 */
function showWeeklyReport(report) {
  var existing = document.getElementById("ls-weekly-report");
  if (existing) existing.remove();

  var threatList = report.topThreats.map(function(t) {
    return '<div style="display:flex;justify-content:space-between;padding:4px 0;font-size:13px;"><span style="color:#94a3b8;">' + _weeklyEsc(t.domain) + '</span><span style="color:#ef4444;">' + (parseInt(t.count, 10) || 0) + '\u00D7</span></div>';
  }).join("") || '<div style="color:#22c55e;font-size:13px;">' + _weeklyEsc(_weeklyT("weekly_no_threats")) + '</div>';

  var div = document.createElement("div");
  div.id = "ls-weekly-report";
  div.innerHTML = '<div style="position:fixed;inset:0;z-index:999999;background:#0f172aee;display:flex;align-items:center;justify-content:center;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,sans-serif;color:#e2e8f0;">' +
    '<div style="background:#1e293b;border-radius:16px;padding:32px;max-width:400px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,0.5);">' +
    '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">' +
    '<h2 style="font-size:20px;font-weight:700;margin:0;">' + _weeklyEsc(_weeklyT("weekly_title")) + '</h2>' +
    '<span id="ls-report-close" style="cursor:pointer;color:#6b7280;font-size:20px;">\u00D7</span></div>' +
    '<div style="font-size:12px;color:#64748b;margin-bottom:16px;">' + _weeklyEsc(_weeklyDate(report.period.start)) + ' \u2014 ' + _weeklyEsc(_weeklyDate(report.period.end)) + '</div>' +
    '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:20px;">' +
    '<div style="background:#111827;border-radius:10px;padding:12px;text-align:center;"><div style="font-size:24px;font-weight:bold;">' + (parseInt(report.totalChecks, 10) || 0) + '</div><div style="font-size:10px;color:#64748b;">' + _weeklyEsc(_weeklyT("weekly_checked")) + '</div></div>' +
    '<div style="background:#111827;border-radius:10px;padding:12px;text-align:center;"><div style="font-size:24px;font-weight:bold;color:#ef4444;">' + (parseInt(report.threatsBlocked, 10) || 0) + '</div><div style="font-size:10px;color:#64748b;">' + _weeklyEsc(_weeklyT("weekly_blocked")) + '</div></div>' +
    '<div style="background:#111827;border-radius:10px;padding:12px;text-align:center;"><div style="font-size:24px;font-weight:bold;color:#f59e0b;">' + (parseInt(report.warnings, 10) || 0) + '</div><div style="font-size:10px;color:#64748b;">' + _weeklyEsc(_weeklyT("weekly_warnings")) + '</div></div></div>' +
    '<div style="margin-bottom:16px;"><div style="font-size:12px;color:#64748b;text-transform:uppercase;margin-bottom:8px;">' + _weeklyEsc(_weeklyT("weekly_top_threats")) + '</div>' + threatList + '</div>' +
    '<div style="font-size:10px;color:#475569;text-align:center;">\uD83D\uDD12 ' + _weeklyEsc(_weeklyT("weekly_on_device")) + '</div>' +
    '</div></div>';

  document.body.appendChild(div);
  document.getElementById("ls-report-close").onclick = function() { div.remove(); };
}
