/**
 * Security Score — 100% On-Device Calculation
 *
 * Score NUMBER is synced to server (for cross-device display).
 * Score BREAKDOWN stays on device. Server never sees factors.
 *
 * Factors:
 *   Base: 50
 *   +15: Extension active for 7+ days
 *   +10: No dangerous clicks in 30 days
 *   +10: Privacy Audit score avg > 70
 *   +5:  Weekly Report viewed
 *   +5:  Multiple devices protected
 *   +5:  Whitelist configured (actively managing)
 *   -15: Clicked through on dangerous site (override block page)
 *   -10: Multiple dangerous sites visited
 *   -5:  Extension disabled for periods
 *
 * Every line the user reads comes from packages/i18n-strings
 * (extension.score). The lines put the number last ("Checks in total: 120")
 * so no language needs a plural form the browser's i18n cannot pick.
 */

// Named per file: content scripts share one global scope.
function _scoreT(key, subs) {
  try {
    return chrome.i18n.getMessage(key, subs || []) || key;
  } catch (e) {
    return key;
  }
}

function _scoreEsc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, function(c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}

async function calculateSecurityScore() {
  var data = await chrome.storage.local.get([
    "stats", "recent_threats", "audits", "whitelist",
    "install_date", "block_overrides"
  ]);

  var stats = data.stats || {};
  var threats = data.recent_threats || [];
  var audits = data.audits || {};
  var whitelist = data.whitelist || [];
  var installDate = data.install_date || new Date().toISOString();
  var overrides = data.block_overrides || 0;

  var score = 50;
  var factors = [];

  // Extension active duration
  var daysSinceInstall = Math.floor((Date.now() - new Date(installDate).getTime()) / 86400000);
  if (daysSinceInstall >= 7) {
    score += 15;
    factors.push({ factor: "active_duration", points: 15, detail: _scoreT("score_factor_active_days", [String(daysSinceInstall)]) });
  } else {
    factors.push({ factor: "active_duration", points: 0, detail: _scoreT("score_factor_active_days_of_week", [String(daysSinceInstall)]) });
  }

  // No dangerous clicks in 30 days
  var thirtyDaysAgo = new Date(Date.now() - 30 * 86400000);
  var recentDangerous = threats.filter(function(t) {
    return t.level === "dangerous" && new Date(t.time) >= thirtyDaysAgo;
  });

  if (recentDangerous.length === 0) {
    score += 10;
    factors.push({ factor: "no_dangerous", points: 10, detail: _scoreT("score_factor_no_dangerous") });
  } else {
    score -= Math.min(recentDangerous.length * 2, 10);
    factors.push({ factor: "dangerous_visits", points: -Math.min(recentDangerous.length * 2, 10), detail: _scoreT("score_factor_dangerous_visits", [String(recentDangerous.length)]) });
  }

  // Privacy Audit average
  var auditScores = Object.values(audits).map(function(a) {
    var gradeMap = { A: 95, B: 85, C: 70, D: 55, F: 30 };
    return gradeMap[a.grade] || 50;
  });

  if (auditScores.length >= 3) {
    var avgAudit = auditScores.reduce(function(a, b) { return a + b; }, 0) / auditScores.length;
    if (avgAudit > 70) {
      score += 10;
      factors.push({ factor: "audit_avg", points: 10, detail: _scoreT("score_factor_audit_avg", [String(Math.round(avgAudit))]) });
    }
  }

  // Whitelist configured
  if (whitelist.length > 0) {
    score += 5;
    factors.push({ factor: "whitelist", points: 5, detail: _scoreT("score_factor_trusted_sites", [String(whitelist.length)]) });
  }

  // Block page overrides (negative)
  if (overrides > 0) {
    score -= Math.min(overrides * 5, 15);
    factors.push({ factor: "overrides", points: -Math.min(overrides * 5, 15), detail: _scoreT("score_factor_overrides", [String(overrides)]) });
  }

  // Total checks volume (engagement)
  if ((stats.total_checks || 0) > 100) {
    score += 5;
    factors.push({ factor: "engagement", points: 5, detail: _scoreT("score_factor_checks", [String(stats.total_checks)]) });
  }

  score = Math.max(0, Math.min(100, score));

  return {
    score: score,
    factors: factors,
    calculatedAt: new Date().toISOString(),
    onDevice: true,
  };
}

function showSecurityScore(scoreData) {
  var existing = document.getElementById("ls-score-overlay");
  if (existing) existing.remove();

  var scoreColor = scoreData.score >= 80 ? "#22c55e" : scoreData.score >= 50 ? "#f59e0b" : "#ef4444";
  var labelKey = scoreData.score >= 80 ? "score_label_excellent"
    : scoreData.score >= 60 ? "score_label_good"
    : scoreData.score >= 40 ? "score_label_fair"
    : "score_label_low";
  var label = _scoreT(labelKey);

  var factorsHTML = scoreData.factors.map(function(f) {
    var color = f.points > 0 ? "#22c55e" : f.points < 0 ? "#ef4444" : "#64748b";
    var sign = f.points > 0 ? "+" : "";
    return '<div style="display:flex;justify-content:space-between;padding:4px 0;font-size:13px;">' +
      '<span style="color:#94a3b8;">' + _scoreEsc(f.detail) + '</span>' +
      '<span style="color:' + color + ';font-weight:600;">' + sign + (parseInt(f.points, 10) || 0) + '</span></div>';
  }).join("");

  var div = document.createElement("div");
  div.id = "ls-score-overlay";
  div.innerHTML = '<div style="position:fixed;inset:0;z-index:999999;background:#0f172aee;display:flex;align-items:center;justify-content:center;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,sans-serif;color:#e2e8f0;">' +
    '<div style="background:#1e293b;border-radius:16px;padding:32px;max-width:380px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,0.5);">' +
    '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">' +
    '<h2 style="font-size:20px;font-weight:700;margin:0;">' + _scoreEsc(_scoreT("score_title")) + '</h2>' +
    '<span id="ls-score-close" style="cursor:pointer;color:#6b7280;font-size:20px;">×</span></div>' +
    '<div style="text-align:center;margin-bottom:20px;">' +
    '<div style="font-size:64px;font-weight:800;color:' + scoreColor + ';">' + (parseInt(scoreData.score, 10) || 0) + '</div>' +
    '<div style="font-size:16px;color:' + scoreColor + ';font-weight:600;">' + _scoreEsc(label) + '</div></div>' +
    '<div style="margin-bottom:16px;">' +
    '<div style="font-size:12px;color:#64748b;text-transform:uppercase;margin-bottom:8px;">' + _scoreEsc(_scoreT("score_breakdown")) + '</div>' +
    factorsHTML + '</div>' +
    '<div style="font-size:10px;color:#475569;text-align:center;">🔒 ' + _scoreEsc(_scoreT("score_on_device")) + '</div>' +
    '</div></div>';

  document.body.appendChild(div);
  document.getElementById("ls-score-close").onclick = function() { div.remove(); };
}
