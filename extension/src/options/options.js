// Cleanway Options Page Script

// ══════════════════════════════════════════════════════════════════════
// Skill Level (Kids / Regular / Granny / Pro)
// ══════════════════════════════════════════════════════════════════════
// Defaults per-mode (applied only when the user hasn't customized them)
const SKILL_DEFAULTS = {
  kids:    { fontScale: 1.0, voiceAlerts: false, showPinSection: true  },
  regular: { fontScale: 1.0, voiceAlerts: false, showPinSection: false },
  granny:  { fontScale: 1.3, voiceAlerts: true,  showPinSection: false },
  pro:     { fontScale: 1.0, voiceAlerts: false, showPinSection: false },
};

const VALID_SKILLS = new Set(["kids", "regular", "granny", "pro"]);

function normalizeSkill(s) {
  return VALID_SKILLS.has(s) ? s : "regular";
}

function applySkillUI(skill) {
  // Highlight active card
  document.querySelectorAll(".skill-card").forEach((card) => {
    card.classList.toggle("active", card.getAttribute("data-skill") === skill);
  });
  // Show/hide mode-specific sub-options
  const opts = SKILL_DEFAULTS[skill] || SKILL_DEFAULTS.regular;
  const fontBlock = document.getElementById("skill-opt-font");
  const voiceBlock = document.getElementById("skill-opt-voice");
  const pinBlock = document.getElementById("skill-opt-pin");
  // Font scale: visible in Granny + Pro
  fontBlock.hidden = !(skill === "granny" || skill === "pro");
  // Voice alerts: visible in Granny only
  voiceBlock.hidden = skill !== "granny";
  // Parental PIN: visible in Kids only
  pinBlock.hidden = skill !== "kids";
}

async function loadSkillSettings() {
  const data = await chrome.storage.local.get([
    "skill_level",
    "font_scale",
    "voice_alerts",
    "parental_pin_set",
  ]);
  const skill = normalizeSkill(data.skill_level || "regular");
  document.querySelector(`input[name="skill-level"][value="${skill}"]`).checked = true;
  applySkillUI(skill);

  const fontScale = typeof data.font_scale === "number"
    ? data.font_scale
    : SKILL_DEFAULTS[skill].fontScale;
  document.getElementById("font-scale").value = String(fontScale);
  document.getElementById("font-scale-val").textContent = fontScale.toFixed(1) + "×";

  document.getElementById("voice-alerts").checked =
    data.voice_alerts === undefined ? SKILL_DEFAULTS[skill].voiceAlerts : !!data.voice_alerts;

  const pinSet = !!data.parental_pin_set;
  updatePinControls(pinSet);
}

function updatePinControls(pinSet) {
  const status = document.getElementById("pin-status");
  const saveBtn = document.getElementById("save-pin");
  const clearBtn = document.getElementById("clear-pin");
  status.textContent = pinSet
    ? "✓ PIN is set — required to switch out of Kids Mode"
    : "";
  saveBtn.textContent = pinSet ? "Update" : "Set PIN";
  clearBtn.hidden = !pinSet;
}

async function pushSkillToApi(patch) {
  // Non-blocking best-effort: if signed in (JWT in storage), sync to API.
  try {
    const stored = await chrome.storage.local.get(["auth_token", "api_url"]);
    if (!stored.auth_token) return;
    const apiBase =
      stored.api_url || "https://web-production-fe08.up.railway.app";
    await fetch(apiBase + "/api/v1/user/settings", {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + stored.auth_token,
      },
      body: JSON.stringify(patch),
    });
  } catch (e) {
    // Offline or unauthenticated — local storage still authoritative
    console.warn("[Cleanway] skill sync failed:", e && e.message);
  }
}

document.querySelectorAll('input[name="skill-level"]').forEach((radio) => {
  radio.addEventListener("change", async (e) => {
    const skill = e.target.value;
    applySkillUI(skill);
    // When switching TO a mode, apply its default font/voice unless explicitly set
    const existing = await chrome.storage.local.get(["font_scale", "voice_alerts"]);
    const next = {
      skill_level: skill,
      font_scale: existing.font_scale ?? SKILL_DEFAULTS[skill].fontScale,
      voice_alerts: existing.voice_alerts ?? SKILL_DEFAULTS[skill].voiceAlerts,
    };
    document.getElementById("font-scale").value = String(next.font_scale);
    document.getElementById("font-scale-val").textContent =
      next.font_scale.toFixed(1) + "×";
    document.getElementById("voice-alerts").checked = next.voice_alerts;
    await chrome.storage.local.set(next);
    await pushSkillToApi({
      skill_level: skill,
      font_scale: next.font_scale,
      voice_alerts_enabled: next.voice_alerts,
    });
  });
});

document.getElementById("font-scale").addEventListener("input", async (e) => {
  const v = parseFloat(e.target.value);
  document.getElementById("font-scale-val").textContent = v.toFixed(1) + "×";
  await chrome.storage.local.set({ font_scale: v });
  await pushSkillToApi({ font_scale: v });
});

document.getElementById("voice-alerts").addEventListener("change", async (e) => {
  const v = !!e.target.checked;
  await chrome.storage.local.set({ voice_alerts: v });
  await pushSkillToApi({ voice_alerts_enabled: v });
});

document.getElementById("save-pin").addEventListener("click", async () => {
  const input = document.getElementById("parental-pin");
  const pin = (input.value || "").trim();
  if (!/^\d{4}$/.test(pin)) {
    document.getElementById("pin-status").textContent =
      "PIN must be exactly 4 digits";
    return;
  }
  await chrome.storage.local.set({ parental_pin_set: true });
  await pushSkillToApi({ parental_pin: pin });
  input.value = "";
  updatePinControls(true);
});

document.getElementById("clear-pin").addEventListener("click", async () => {
  if (!confirm("Clear the parental PIN?")) return;
  await chrome.storage.local.set({ parental_pin_set: false });
  await pushSkillToApi({ parental_pin: "" });
  updatePinControls(false);
});

loadSkillSettings();

// ══════════════════════════════════════════════════════════════════════
// Existing Options logic below
// ══════════════════════════════════════════════════════════════════════

// Load settings
chrome.storage.local.get(["settings", "stats"], (data) => {
  const s = data.settings || {};
  document.getElementById("auto-scan").checked = s.autoScan !== false;
  document.getElementById("show-badges").checked = s.showBadges !== false;
  document.getElementById("block-dangerous").checked = s.blockDangerous !== false;
  document.getElementById("auto-audit").checked = s.autoAudit === true;
  document.getElementById("anon-stats").checked = s.anonStats === true;

  const stats = data.stats || {};
  document.getElementById("s-total").textContent = stats.total_checks || 0;
  document.getElementById("s-blocked").textContent = stats.threats_blocked || 0;
  document.getElementById("s-warned").textContent = stats.threats_warned || 0;
});

// Save on toggle
document.querySelectorAll("input[type=checkbox]").forEach((cb) => {
  cb.addEventListener("change", () => {
    const settings = {
      autoScan: document.getElementById("auto-scan").checked,
      showBadges: document.getElementById("show-badges").checked,
      blockDangerous: document.getElementById("block-dangerous").checked,
      autoAudit: document.getElementById("auto-audit").checked,
      anonStats: document.getElementById("anon-stats").checked,
    };
    chrome.storage.local.set({ settings });
    const msg = document.getElementById("saved-msg");
    msg.style.display = "block";
    setTimeout(() => msg.style.display = "none", 2000);
  });
});

// Clear data
document.getElementById("clear-data").addEventListener("click", () => {
  if (confirm("Delete all local check history? This cannot be undone.")) {
    chrome.storage.local.remove(["recent_threats", "stats", "audits"], () => {
      location.reload();
    });
  }
});

// Load custom lists
chrome.storage.local.get(["custom_blocklist", "custom_whitelist"], (data) => {
  if (data.custom_blocklist) document.getElementById("custom-blocklist").value = data.custom_blocklist;
  if (data.custom_whitelist) document.getElementById("custom-whitelist").value = data.custom_whitelist;
});

// Save custom lists
document.getElementById("save-lists").addEventListener("click", () => {
  chrome.storage.local.set({
    custom_blocklist: document.getElementById("custom-blocklist").value,
    custom_whitelist: document.getElementById("custom-whitelist").value,
  });
  document.getElementById("save-lists").textContent = "Saved!";
  setTimeout(() => document.getElementById("save-lists").textContent = "Save Lists", 2000);
});

// Load privacy settings
chrome.storage.local.get(["settings"], (data) => {
  const s2 = data.settings || {};
  document.getElementById("clean-tracking").checked = s2.cleanTracking !== false;
  document.getElementById("block-miners").checked = s2.blockMiners !== false;
});

// Load API URL
chrome.storage.local.get(["api_url"], (data) => {
  if (data.api_url) document.getElementById("api-url-input").value = data.api_url;
});

// Save API URL
document.getElementById("save-api-url").addEventListener("click", () => {
  const url = document.getElementById("api-url-input").value.trim();
  if (url) {
    chrome.storage.local.set({ api_url: url });
    document.getElementById("save-api-url").textContent = "Saved!";
    setTimeout(() => document.getElementById("save-api-url").textContent = "Save", 2000);
  }
});

// Copy referral link
document.getElementById("copy-referral").addEventListener("click", async () => {
  const data = await chrome.storage.local.get(["referral_code"]);
  let code = data.referral_code;
  if (!code) {
    code = Math.random().toString(36).substring(2, 10).toUpperCase();
    await chrome.storage.local.set({ referral_code: code });
  }
  const url = "https://cleanway.ai/ref/" + code;
  await navigator.clipboard.writeText(url);
  document.getElementById("copy-referral").textContent = "Copied!";
  setTimeout(() => document.getElementById("copy-referral").textContent = "Copy link", 2000);
});

// Redeem referral code
document.getElementById("redeem-code").addEventListener("click", async () => {
  const code = document.getElementById("referral-input").value.trim().toUpperCase();
  if (!code) return;
  await chrome.storage.local.set({ redeemed_code: code });
  alert("Code " + code + " saved!");
});

// Export
document.getElementById("export-data").addEventListener("click", () => {
  chrome.storage.local.get(null, (data) => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "cleanway-export.json";
    a.click();
    URL.revokeObjectURL(url);
  });
});
