/**
 * LinkShield Popup — Complete Logic
 */

// ── Load stats ──
async function loadStats() {
  try {
    var stats = await chrome.runtime.sendMessage({ type: "GET_STATS" });
    if (stats) {
      document.getElementById("total-checks").textContent = fmt(stats.total_checks || 0);
      document.getElementById("threats-blocked").textContent = fmt(stats.threats_blocked || 0);
      document.getElementById("threats-warned").textContent = fmt(stats.threats_warned || 0);
    }
  } catch (e) {}
}

// ── Page status ──
async function loadPageStatus() {
  try {
    var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tabs[0] || !tabs[0].url) return;

    var url = new URL(tabs[0].url);
    var domain = url.hostname;
    var icon = document.getElementById("status-icon");
    var title = document.getElementById("status-title");
    var sub = document.getElementById("status-subtitle");

    title.textContent = domain;
    sub.textContent = "Checking...";

    var resp = await chrome.runtime.sendMessage({ type: "CHECK_DOMAINS", domains: [domain] });

    if (resp && resp.results && resp.results[0]) {
      var r = resp.results[0];
      icon.className = "status-icon " + r.level;
      if (r.level === "safe") {
        icon.textContent = "\u2713";
        title.textContent = "This page is safe";
      } else if (r.level === "caution") {
        icon.textContent = "\u26A0";
        title.textContent = "Proceed with caution";
      } else {
        icon.textContent = "\u2717";
        title.textContent = "Dangerous site!";
      }
      sub.textContent = domain + " \u2014 Score: " + r.score + "/100";
    }
  } catch (e) {
    document.getElementById("status-title").textContent = "Unable to check";
  }
}

// ── Recent threats ──
async function loadThreats() {
  try {
    var data = await chrome.storage.local.get(["recent_threats"]);
    var threats = data.recent_threats || [];
    var container = document.getElementById("recent-threats");
    if (threats.length === 0) return;

    container.innerHTML = "";
    threats.slice(0, 8).forEach(function(t) {
      var item = document.createElement("div");
      item.className = "recent-item";
      item.innerHTML = '<span class="recent-dot ' + t.level + '"></span><span class="recent-domain">' + t.domain + '</span><span class="recent-score">' + t.score + '</span>';
      container.appendChild(item);
    });
  } catch (e) {}
}

// ── Aha moment ──
async function checkAha() {
  try {
    var data = await chrome.storage.local.get(["stats", "aha_shown"]);
    if (!data.aha_shown && data.stats && data.stats.threats_blocked > 0) {
      document.getElementById("aha-count").textContent = data.stats.threats_blocked;
      document.getElementById("aha-banner").style.display = "flex";
      await chrome.storage.local.set({ aha_shown: true });
    }
  } catch (e) {}
}

// ── Upgrade banner (free users) ──
async function checkUpgrade() {
  try {
    var data = await chrome.storage.local.get(["stats", "user_tier"]);
    var tier = data.user_tier || "free";
    if (tier === "free") {
      var used = (data.stats || {}).total_checks || 0;
      document.getElementById("checks-used").textContent = Math.min(used, 10);
      document.getElementById("upgrade-banner").style.display = "flex";
    }
  } catch (e) {}
}

// ── Button handlers ──
function setupButtons() {
  // Privacy Audit
  document.getElementById("btn-audit").addEventListener("click", async function() {
    var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs[0]) {
      chrome.tabs.sendMessage(tabs[0].id, { type: "RUN_PRIVACY_AUDIT" });
      window.close();
    }
  });

  // Report issue
  document.getElementById("btn-report").addEventListener("click", async function() {
    var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs[0] && tabs[0].url) {
      var domain = new URL(tabs[0].url).hostname;
      var type = confirm("Is this site SAFE but marked as dangerous?\n\nOK = Yes (false positive)\nCancel = No, it's dangerous but wasn't caught (false negative)")
        ? "false_positive" : "false_negative";

      // Store report locally
      var data = await chrome.storage.local.get(["reports"]);
      var reports = data.reports || [];
      reports.push({ domain: domain, type: type, time: new Date().toISOString() });
      await chrome.storage.local.set({ reports: reports.slice(-100) });

      alert("Thank you! Report saved for: " + domain);
    }
  });

  // Whitelist
  document.getElementById("btn-whitelist").addEventListener("click", async function() {
    var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs[0] && tabs[0].url) {
      var domain = new URL(tabs[0].url).hostname;
      if (confirm("Always trust " + domain + "?\n\nThis site will never be blocked.")) {
        var data = await chrome.storage.local.get(["whitelist"]);
        var wl = data.whitelist || [];
        if (!wl.includes(domain)) wl.push(domain);
        await chrome.storage.local.set({ whitelist: wl });
        alert(domain + " added to your whitelist.");
      }
    }
  });

  // Breach Check
  document.getElementById("btn-breach").addEventListener("click", async function() {
    var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs[0]) {
      chrome.tabs.sendMessage(tabs[0].id, { type: "SHOW_BREACH_CHECK" });
      window.close();
    }
  });

  // Security Score
  document.getElementById("btn-score").addEventListener("click", async function() {
    var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs[0]) {
      chrome.tabs.sendMessage(tabs[0].id, { type: "SHOW_SECURITY_SCORE" });
      window.close();
    }
  });

  // Weekly Report
  document.getElementById("btn-weekly").addEventListener("click", async function() {
    var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs[0]) {
      chrome.tabs.sendMessage(tabs[0].id, { type: "SHOW_WEEKLY_REPORT" });
      window.close();
    }
  });

  // Settings
  document.getElementById("btn-settings").addEventListener("click", function(e) {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });
}

// ── Helpers ──
function fmt(n) {
  if (n >= 1000000) return (n / 1000000).toFixed(1) + "M";
  if (n >= 1000) return (n / 1000).toFixed(1) + "K";
  return n.toString();
}

// ── Init ──
document.addEventListener("DOMContentLoaded", function() {
  // Show skeleton loading immediately
  document.querySelectorAll(".stat-number").forEach(function(el) {
    el.classList.add("skeleton", "loading");
  });
  document.getElementById("status-icon").classList.add("loading");

  // Load everything
  // Show onboarding tip on first open
  chrome.storage.local.get(["tip_dismissed"], function(data) {
    if (!data.tip_dismissed) {
      document.getElementById("onboarding-tip").style.display = "block";
      document.getElementById("dismiss-tip").onclick = function() {
        document.getElementById("onboarding-tip").style.display = "none";
        chrome.storage.local.set({ tip_dismissed: true });
      };
    }
  });

  // Check API availability
  fetch("http://localhost:8000/health").then(function(r) {
    if (!r.ok) throw new Error();
  }).catch(function() {
    document.getElementById("api-warning").style.display = "block";
  });

  loadStats().then(function() {
    document.querySelectorAll(".stat-number").forEach(function(el) {
      el.classList.remove("skeleton", "loading");
    });
  });
  loadPageStatus().then(function() {
    document.getElementById("status-icon").classList.remove("loading");
  });
  loadThreats();
  checkAha();
  checkUpgrade();
  setupButtons();
});
