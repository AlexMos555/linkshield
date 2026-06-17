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

/**
 * Show weekly report as floating overlay
 */
function showWeeklyReport(report) {
  var existing = document.getElementById("ls-weekly-report");
  if (existing) existing.remove();

  var threatList = report.topThreats.map(function(t) {
    return '<div style="display:flex;justify-content:space-between;padding:4px 0;font-size:13px;"><span style="color:#94a3b8;">' + t.domain + '</span><span style="color:#ef4444;">' + t.count + 'x</span></div>';
  }).join("") || '<div style="color:#22c55e;font-size:13px;">No threats this week!</div>';

  var div = document.createElement("div");
  div.id = "ls-weekly-report";
  div.innerHTML = '<div style="position:fixed;inset:0;z-index:999999;background:#0f172aee;display:flex;align-items:center;justify-content:center;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,sans-serif;color:#e2e8f0;">' +
    '<div style="background:#1e293b;border-radius:16px;padding:32px;max-width:400px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,0.5);">' +
    '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">' +
    '<h2 style="font-size:20px;font-weight:700;margin:0;">Weekly Report</h2>' +
    '<span id="ls-report-close" style="cursor:pointer;color:#6b7280;font-size:20px;">\u00D7</span></div>' +
    '<div style="font-size:12px;color:#64748b;margin-bottom:16px;">' + report.period.start + ' \u2014 ' + report.period.end + '</div>' +
    '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:20px;">' +
    '<div style="background:#111827;border-radius:10px;padding:12px;text-align:center;"><div style="font-size:24px;font-weight:bold;">' + report.totalChecks + '</div><div style="font-size:10px;color:#64748b;">Checked</div></div>' +
    '<div style="background:#111827;border-radius:10px;padding:12px;text-align:center;"><div style="font-size:24px;font-weight:bold;color:#ef4444;">' + report.threatsBlocked + '</div><div style="font-size:10px;color:#64748b;">Blocked</div></div>' +
    '<div style="background:#111827;border-radius:10px;padding:12px;text-align:center;"><div style="font-size:24px;font-weight:bold;color:#f59e0b;">' + report.warnings + '</div><div style="font-size:10px;color:#64748b;">Warnings</div></div></div>' +
    '<div style="margin-bottom:16px;"><div style="font-size:12px;color:#64748b;text-transform:uppercase;margin-bottom:8px;">Top Threats</div>' + threatList + '</div>' +
    '<div style="font-size:10px;color:#475569;text-align:center;">\uD83D\uDD12 Generated 100% on your device</div>' +
    '</div></div>';

  document.body.appendChild(div);
  document.getElementById("ls-report-close").onclick = function() { div.remove(); };
}
