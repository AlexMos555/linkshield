// Cleanway Options Page Script

// ══════════════════════════════════════════════════════════════════════
// i18n
// ══════════════════════════════════════════════════════════════════════
// Every text on this page comes from the browser's language catalog
// (_locales/<lang>/messages.json, generated from packages/i18n-strings).
// options.html carries English defaults plus data-i18n keys; until this
// applier existed nothing read those keys, so the whole page was English.
// scripts/test-extension-core.mjs fails if a key used here or in the HTML
// is missing from any locale.

function t(key, subs) {
  try {
    return chrome.i18n.getMessage(key, subs || []) || key;
  } catch (e) {
    return key;
  }
}

function applyI18n() {
  const attrs = [
    ["data-i18n", (el, msg) => { el.textContent = msg; }],
    ["data-i18n-title", (el, msg) => el.setAttribute("title", msg)],
    ["data-i18n-placeholder", (el, msg) => el.setAttribute("placeholder", msg)],
    ["data-i18n-aria-label", (el, msg) => el.setAttribute("aria-label", msg)],
  ];
  for (const [attr, apply] of attrs) {
    document.querySelectorAll(`[${attr}]`).forEach((el) => {
      const key = el.getAttribute(attr);
      const msg = t(key);
      if (msg && msg !== key) apply(el, msg);
    });
  }
  try {
    document.documentElement.lang = chrome.i18n.getUILanguage();
  } catch (e) { /* keep lang="en" */ }
}

applyI18n();

// A button's label flips to a confirmation for two seconds, then back.
function flashLabel(el, message, restoreKey) {
  if (!el) return;
  el.textContent = message;
  setTimeout(() => { el.textContent = t(restoreKey); }, 2000);
}

// ══════════════════════════════════════════════════════════════════════
// Account — sign in / out through the background (background/auth.js)
// ══════════════════════════════════════════════════════════════════════
// The background owns the tokens: it refreshes before answering AUTH_STATUS,
// opens the cleanway.ai connect tab for AUTH_START_SIGN_IN and forgets the
// session on AUTH_SIGN_OUT. This page never touches the refresh token.

function sendToBackground(message) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(message, (reply) => {
        if (chrome.runtime.lastError) { resolve(null); return; }
        resolve(reply || null);
      });
    } catch (e) { resolve(null); }
  });
}

async function loadAccount() {
  const section = document.getElementById("account-section");
  if (!section) return;
  const s = await sendToBackground({ type: "AUTH_STATUS" });
  if (!s) return;
  const label = document.getElementById("account-label");
  const desc = document.getElementById("account-desc");
  const signIn = document.getElementById("account-sign-in");
  const signOut = document.getElementById("account-sign-out");
  if (s.signedIn) {
    label.textContent = s.email ? t("account_signed_in_as", [s.email]) : t("account_signed_in");
    desc.textContent = t("account_signed_in_desc");
  } else {
    if (s.pending) label.textContent = t("account_pending");
    else if (s.signedOutReason === "expired") label.textContent = t("account_expired");
    else if (s.signedOutReason === "device_revoked") label.textContent = t("account_device_revoked");
    else if (s.signedOutReason === "device_limit") label.textContent = t("account_device_limit");
    else label.textContent = t("account_signed_out");
    desc.textContent = t("account_signed_out_desc");
  }
  signIn.hidden = s.signedIn;
  signOut.hidden = !s.signedIn;
  section.hidden = false;
}

document.getElementById("account-sign-in").addEventListener("click", async (e) => {
  e.currentTarget.disabled = true;
  await sendToBackground({ type: "AUTH_START_SIGN_IN" });
  e.currentTarget.disabled = false;
});

document.getElementById("account-sign-out").addEventListener("click", async (e) => {
  e.currentTarget.disabled = true;
  await sendToBackground({ type: "AUTH_SIGN_OUT" });
  e.currentTarget.disabled = false;
  // The storage listener below reloads the page into its signed-out state.
});

// Signing in on the cleanway.ai tab (or out here) changes which sections
// this page shows — Family Hub, This device. Reload when the signed-in state
// flips; an hourly token refresh (same state) does not.
try {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local" || !changes.auth_token) return;
    if (Boolean(changes.auth_token.oldValue) !== Boolean(changes.auth_token.newValue)) location.reload();
  });
} catch (e) { /* storage events unavailable */ }

loadAccount().catch(() => {});

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
  // Was "✓ PIN is set — required to switch out of Kids Mode". Nothing verifies
  // it: the skill radios above switch mode without a prompt, and the backend
  // has no parental_pin field. Saying nothing beats confirming a lock that
  // isn't there; the row description carries the honest explanation.
  status.textContent = "";
  saveBtn.textContent = t(pinSet ? "options_pin_update" : "options_pin_set");
  clearBtn.hidden = !pinSet;
}

async function pushSkillToApi(patch) {
  // Non-blocking best-effort: if signed in (JWT in storage), sync to API.
  try {
    const stored = await chrome.storage.local.get(["auth_token", "api_url"]);
    if (!stored.auth_token) return;
    const apiBase =
      stored.api_url || "https://api.cleanway.ai";
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
    // When switching TO a mode, keep a font size already chosen. Voice is
    // the new mode's default: the block page reads voice_alerts now, and a
    // switch through Regular stored "off", which then silenced Grandparent
    // (whose switch is the only place to turn it back on).
    const existing = await chrome.storage.local.get(["font_scale"]);
    const next = {
      skill_level: skill,
      font_scale: existing.font_scale ?? SKILL_DEFAULTS[skill].fontScale,
      voice_alerts: SKILL_DEFAULTS[skill].voiceAlerts,
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
    document.getElementById("pin-status").textContent = t("options_pin_invalid");
    return;
  }
  await chrome.storage.local.set({ parental_pin_set: true });
  await pushSkillToApi({ parental_pin: pin });
  input.value = "";
  updatePinControls(true);
});

document.getElementById("clear-pin").addEventListener("click", async () => {
  if (!confirm(t("options_pin_clear_confirm"))) return;
  await chrome.storage.local.set({ parental_pin_set: false });
  await pushSkillToApi({ parental_pin: "" });
  updatePinControls(false);
});

loadSkillSettings();

// ══════════════════════════════════════════════════════════════════════
// Email scanning (opt-in) — background/webmail-scanner.js does the rest
// ══════════════════════════════════════════════════════════════════════
// Off unless switched on here. On = the browser granted the four mail
// sites AND webmailScannerEnabled is true; the background then injects
// content/webmail.js. Off = the flag goes false, the background unregisters
// the script and every copy running in an open mail tab stops itself.

const WEBMAIL_FLAG = "webmailScannerEnabled";
const WEBMAIL_ORIGINS = [
  "https://mail.google.com/*",
  "https://outlook.office.com/*",
  "https://outlook.live.com/*",
  "https://mail.yahoo.com/*",
];

// Callback form: it works in Chrome, in Firefox's chrome.* namespace and in
// Safari alike. Must be called straight from the click — Firefox only shows
// its permission prompt for a user action, and an await before it loses that.
function requestWebmailOrigins() {
  return new Promise((resolve, reject) => {
    if (!chrome.permissions || typeof chrome.permissions.request !== "function") {
      // No permissions API: the browser's own per-site access controls apply.
      resolve(true);
      return;
    }
    try {
      const maybe = chrome.permissions.request({ origins: WEBMAIL_ORIGINS }, (granted) => {
        const err = chrome.runtime.lastError;
        if (err) reject(err);
        else resolve(Boolean(granted));
      });
      if (maybe && typeof maybe.then === "function") maybe.then((g) => resolve(Boolean(g)), reject);
    } catch (e) {
      reject(e);
    }
  });
}

(function initWebmailScanner() {
  const box = document.getElementById("webmail-scanner");
  const status = document.getElementById("webmail-status");
  if (!box || !status) return;

  function showStatus(key) {
    status.textContent = key ? t(key) : "";
    status.hidden = !key;
  }

  const supported = Boolean(chrome.scripting && typeof chrome.scripting.registerContentScripts === "function");
  if (!supported) {
    box.checked = false;
    box.disabled = true;
    showStatus("webmail_setting_unsupported");
    return;
  }

  chrome.storage.local.get(WEBMAIL_FLAG, (d) => {
    box.checked = Boolean(d) && d[WEBMAIL_FLAG] === true;
  });
  try {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== "local" || !changes[WEBMAIL_FLAG]) return;
      box.checked = changes[WEBMAIL_FLAG].newValue === true;
    });
  } catch (e) { /* storage events unavailable: the page shows what it read */ }

  box.addEventListener("change", () => {
    if (!box.checked) {
      showStatus(null);
      chrome.storage.local.set({ [WEBMAIL_FLAG]: false });
      return;
    }
    requestWebmailOrigins()
      .then((granted) => {
        if (!granted) throw new Error("denied");
        showStatus(null);
        chrome.storage.local.set({ [WEBMAIL_FLAG]: true });
      })
      .catch(() => {
        box.checked = false;
        showStatus("webmail_setting_denied");
      });
  });
})();

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
  if (cb.id === "webmail-scanner") return; // its own handler above; "saved" would show even when the browser refused
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
  if (confirm(t("options_clear_confirm"))) {
    chrome.storage.local.remove(["recent_threats", "stats", "audits", "blocked_pages_today"], () => {
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
  flashLabel(document.getElementById("save-lists"), t("options_saved"), "options_save_lists");
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
    flashLabel(document.getElementById("save-api-url"), t("options_saved"), "options_save");
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
  flashLabel(document.getElementById("copy-referral"), t("options_copied"), "family_invite_link_copy_btn");
});

// Redeem referral code
document.getElementById("redeem-code").addEventListener("click", async () => {
  const code = document.getElementById("referral-input").value.trim().toUpperCase();
  if (!code) return;
  await chrome.storage.local.set({ redeemed_code: code });
  alert(t("options_redeem_saved", [code]));
});

// ─── Device-level override (Family Hub) ─────────────────────────
//
// Reads /api/v1/user/device/{hash}/effective on load to populate the
// resolved state + provenance badges. PATCH /overrides on change.
// Section stays hidden when there's no auth_token — this whole feature
// only makes sense for signed-in users with a server-side account.

async function lazyApi() {
  return import(chrome.runtime.getURL("src/utils/api.js"));
}

// Same names as the skill cards above (options_skill_<level>).
const SKILL_LABEL_KEYS = {
  kids: "options_skill_kids",
  regular: "options_skill_regular",
  granny: "options_skill_granny",
  pro: "options_skill_pro",
};

function setSkillCardActive(name, value) {
  document.querySelectorAll(`input[name="${name}"]`).forEach((radio) => {
    const card = radio.closest(".skill-card");
    if (!card) return;
    card.classList.toggle("active", radio.value === value);
    radio.checked = radio.value === value;
  });
}

async function refreshDeviceOverridePanel() {
  const section = document.getElementById("device-override-section");
  if (!section) return;
  let stored;
  try {
    stored = await chrome.storage.local.get(["auth_token"]);
  } catch {
    return;
  }
  if (!stored || !stored.auth_token) {
    // Anonymous user — feature only applies to signed-in accounts.
    section.hidden = true;
    return;
  }
  let api;
  try {
    api = await lazyApi();
  } catch {
    section.hidden = true;
    return;
  }

  const hash = await api.getDeviceHash();
  const effective = await api.fetchEffectiveSkill(stored.auth_token, hash);
  if (!effective) {
    // API down → keep panel hidden so the user doesn't see broken UI
    section.hidden = true;
    return;
  }

  section.hidden = false;

  const summary = document.getElementById("device-effective-summary");
  if (summary) {
    const labelKey = SKILL_LABEL_KEYS[effective.skill_level];
    const label = labelKey ? t(labelKey) : effective.skill_level;
    summary.textContent = `${label} · ${effective.font_scale.toFixed(1)}× · ${
      t(effective.voice_alerts_enabled ? "options_voice_on" : "options_voice_off")
    }`;
  }
  const badge = document.getElementById("device-skill-source");
  if (badge) {
    badge.hidden = false;
    badge.setAttribute("data-source", effective.skill_source);
    badge.textContent = t(
      effective.skill_source === "device_override"
        ? "options_source_device"
        : "options_source_account"
    );
  }

  // Reflect controls if any field already has a device-level override
  const anyOverride =
    effective.skill_source === "device_override" ||
    effective.voice_source === "device_override" ||
    effective.font_source === "device_override";
  document.getElementById("device-override-on").checked = anyOverride;
  document.getElementById("device-override-controls").hidden = !anyOverride;

  setSkillCardActive("device-skill-level", effective.skill_level);
  document.getElementById("device-voice-alerts").checked = !!effective.voice_alerts_enabled;
  const fontEl = document.getElementById("device-font-scale");
  fontEl.value = String(effective.font_scale);
  document.getElementById("device-font-scale-val").textContent = effective.font_scale.toFixed(1) + "×";
}

async function pushDeviceOverride(payload) {
  let stored;
  try {
    stored = await chrome.storage.local.get(["auth_token"]);
  } catch {
    return;
  }
  if (!stored || !stored.auth_token) return;
  const api = await lazyApi();
  const hash = await api.getDeviceHash();
  const updated = await api.patchDeviceOverrides(stored.auth_token, hash, payload);
  if (updated) {
    // Re-render so badges + summary reflect the new resolved state
    await refreshDeviceOverridePanel();
  }
}

// Toggle override on/off
const overrideToggle = document.getElementById("device-override-on");
if (overrideToggle) {
  overrideToggle.addEventListener("change", async (e) => {
    const on = !!e.target.checked;
    document.getElementById("device-override-controls").hidden = !on;
    if (!on) {
      // Switching OFF wipes all device overrides → revert to user defaults
      await pushDeviceOverride({ clear_overrides: true });
    }
  });
}

// Per-device skill level
document.querySelectorAll('input[name="device-skill-level"]').forEach((radio) => {
  radio.addEventListener("change", async (e) => {
    setSkillCardActive("device-skill-level", e.target.value);
    await pushDeviceOverride({ skill_level_override: e.target.value });
  });
});

// Per-device voice
const dvVoice = document.getElementById("device-voice-alerts");
if (dvVoice) {
  dvVoice.addEventListener("change", async (e) => {
    await pushDeviceOverride({ voice_alerts_enabled: !!e.target.checked });
  });
}

// Per-device font
const dvFont = document.getElementById("device-font-scale");
if (dvFont) {
  dvFont.addEventListener("input", (e) => {
    document.getElementById("device-font-scale-val").textContent =
      parseFloat(e.target.value).toFixed(1) + "×";
  });
  dvFont.addEventListener("change", async (e) => {
    const v = parseFloat(e.target.value);
    if (!Number.isNaN(v) && v >= 0.8 && v <= 2.5) {
      await pushDeviceOverride({ font_scale: v });
    }
  });
}

// Clear all device overrides
const dvClear = document.getElementById("device-clear-overrides");
if (dvClear) {
  dvClear.addEventListener("click", async () => {
    await pushDeviceOverride({ clear_overrides: true });
    document.getElementById("device-override-on").checked = false;
    document.getElementById("device-override-controls").hidden = true;
  });
}

// Initial load
refreshDeviceOverridePanel().catch(() => {});

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

// ─── Family Hub ───────────────────────────────────────────────────
//
// State machine:
//   loading  → fetch /family/mine
//   none     → "Create" + "Join" CTAs
//   active   → list members + recent alerts (+ owner-only invite)
//
// Auth: requires chrome.storage.local.auth_token (Supabase access
// token from a successful sign-in). Without it the section stays
// hidden — "Sign in" in the Account section above goes through
// cleanway.ai/extension/connect (background/auth.js).
//
// Modules: family-api.js, family-crypto.js and family-fanout.js are ES
// modules, imported on demand below. family-crypto.js imports the vendored
// TweetNaCl itself; options.html loads no crypto scripts of its own.

async function lazyFamilyApi() {
  return import(chrome.runtime.getURL("src/utils/family-api.js"));
}

async function lazyFamilyCrypto() {
  return import(chrome.runtime.getURL("src/utils/family-crypto.js"));
}

function showFamilyState(name) {
  const states = ["loading", "none", "active"];
  for (const s of states) {
    const el = document.getElementById(`family-state-${s}`);
    if (el) el.hidden = s !== name;
  }
}

let _familyState = { token: null, currentFamilyId: null, members: [] };

async function loadFamilyHub() {
  const section = document.getElementById("family-hub-section");
  if (!section) return;

  let stored;
  try {
    stored = await chrome.storage.local.get(["auth_token"]);
  } catch {
    return;
  }
  if (!stored || !stored.auth_token) {
    // Anonymous — Family Hub only makes sense for signed-in users.
    section.hidden = true;
    return;
  }

  section.hidden = false;
  showFamilyState("loading");
  _familyState.token = stored.auth_token;

  const api = await lazyFamilyApi();
  const mine = await api.listMyFamilies(stored.auth_token);
  if (!mine || !Array.isArray(mine.families) || mine.families.length === 0) {
    showFamilyState("none");
    return;
  }

  // Single-family UX for v1 — pick the first. Multi-family is a future
  // iteration (rare case: user belongs to two families).
  const fam = mine.families[0];
  _familyState.currentFamilyId = fam.family_id;

  // Make sure my keypair is registered server-side so siblings can
  // encrypt to me. Idempotent (server-side ON CONFLICT, client-side
  // chrome.storage cache).
  try {
    const crypto = await lazyFamilyCrypto();
    const kp = await crypto.getOrCreateKeypair();
    await api.registerMyKey(stored.auth_token, fam.family_id, kp.publicKeyB64);
  } catch (e) {
    console.warn("[Cleanway] family key register failed:", e && e.message);
  }

  const members = await api.listMembers(stored.auth_token, fam.family_id);
  _familyState.members = (members && members.members) || [];

  document.getElementById("family-active-name").textContent = fam.name;
  document.getElementById("family-active-count").textContent =
    t("options_family_members_count", [String(fam.member_count)]);
  const roleBadge = document.getElementById("family-active-role");
  roleBadge.textContent = familyRoleText(fam.role);
  roleBadge.setAttribute("data-source", fam.role === "owner" ? "device_override" : "user_default");

  document.getElementById("family-owner-controls").hidden = fam.role !== "owner";

  renderFamilyMembers(_familyState.members, stored.auth_token);
  renderFamilyAlerts(stored.auth_token, fam.family_id);

  // Cache pubkeys for the background's auto-fan-out and poller, so a sibling
  // added a minute ago is picked up now. The background also refreshes this
  // cache on its own once it is an hour old (family-fanout.js).
  try {
    const fanout = await import(chrome.runtime.getURL("src/utils/family-fanout.js"));
    // My own user_id is the token's `sub` claim; null leaves every member a sibling.
    const myUid = fanout.userIdFromToken(stored.auth_token);
    await fanout.setFamilyCache(fam.family_id, myUid, _familyState.members);
  } catch (e) {
    console.warn("[Cleanway] family cache update failed:", e && e.message);
  }

  showFamilyState("active");
}

// "owner" / "member" from the API, in the reader's language.
function familyRoleText(role) {
  if (role === "owner") return t("options_family_role_owner");
  if (role === "member") return t("options_family_role_member");
  return String(role || "");
}

// The level a relative's alert carries, as the badges name it.
function familyAlertLevelText(level) {
  if (level === "dangerous") return t("badge_label_dangerous");
  if (level === "caution") return t("badge_label_caution");
  return t("options_family_alert_blocked");
}

function renderFamilyMembers(members) {
  const container = document.getElementById("family-members-list");
  if (!container) return;
  container.innerHTML = "";
  for (const m of members) {
    const row = document.createElement("div");
    row.className = "family-member-row";
    const dot = document.createElement("span");
    dot.style.cssText = `width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; background: ${m.public_key_b64 ? "#22c55e" : "#64748b"};`;
    const label = document.createElement("span");
    label.style.flex = "1";
    label.style.color = "#e2e8f0";
    // We don't have email/name here — backend returns user_id only.
    // Show shortened ID + role for now; future iteration can join with
    // public.users to surface display_name.
    label.textContent = `${m.user_id.slice(0, 8)}… (${familyRoleText(m.role)})`;
    if (!m.public_key_b64) {
      const note = document.createElement("span");
      note.style.cssText = "font-size: 11px; color: #f59e0b;";
      note.textContent = t("options_family_no_key");
      row.appendChild(dot);
      row.appendChild(label);
      row.appendChild(note);
    } else {
      row.appendChild(dot);
      row.appendChild(label);
    }
    container.appendChild(row);
  }
}

async function renderFamilyAlerts(token, familyId) {
  const container = document.getElementById("family-alerts-list");
  if (!container) return;

  const api = await lazyFamilyApi();
  const list = await api.listAlerts(token, familyId);
  if (!list || !Array.isArray(list.alerts) || list.alerts.length === 0) {
    // Keep the i18n empty-state default
    return;
  }

  const crypto = await lazyFamilyCrypto();
  const kp = await crypto.getOrCreateKeypair();

  const decrypted = [];
  for (const env of list.alerts) {
    const opened = crypto.decryptForMe(
      {
        ciphertext_b64: env.ciphertext_b64,
        nonce_b64: env.nonce_b64,
        sender_pubkey_b64: env.sender_pubkey_b64,
      },
      kp.secretKeyB64
    );
    if (opened) {
      decrypted.push({ ...opened, _server_id: env.id, _at: env.created_at });
    }
  }

  if (!decrypted.length) {
    return; // All envelopes failed to decrypt — show empty state
  }

  container.innerHTML = "";
  for (const a of decrypted) {
    const row = document.createElement("div");
    row.className = "family-alert-row";
    const domain = document.createElement("div");
    domain.className = "domain";
    domain.textContent = a.domain || t("options_family_unknown_domain");
    const meta = document.createElement("div");
    meta.className = "meta";
    const when = a._at ? new Date(a._at).toLocaleString() : "";
    meta.textContent = `${familyAlertLevelText(a.level)} · ${when}`;
    row.appendChild(domain);
    row.appendChild(meta);
    container.appendChild(row);
  }
}

// ─── Event handlers ───────────────────────────────────────────────

document.getElementById("family-create-btn")?.addEventListener("click", async () => {
  const stored = await chrome.storage.local.get(["auth_token"]);
  if (!stored.auth_token) return;
  const api = await lazyFamilyApi();
  const created = await api.createFamily(stored.auth_token, t("options_family_default_name"));
  if (created) {
    // Re-render — the keypair register + member fetch happens in loadFamilyHub.
    await loadFamilyHub();
  } else {
    alert(t("options_family_create_failed"));
  }
});

document.getElementById("family-join-toggle-btn")?.addEventListener("click", () => {
  const form = document.getElementById("family-join-form");
  if (form) form.hidden = !form.hidden;
});

// Pasting a Cleanway invite URL into the code field auto-populates both
// fields. The shared parser lives in utils/family-invite-url.js so it can be
// covered by Node smoke tests; here we just consume the global it exports.
const _inviteHelpers = (typeof self !== "undefined" && self.familyInviteUrl) || null;

document.getElementById("family-join-code")?.addEventListener("input", (e) => {
  if (!_inviteHelpers) return;
  const parsed = _inviteHelpers.parseInviteUrl(e.target.value);
  if (parsed) {
    e.target.value = parsed.code;
    const pinInput = document.getElementById("family-join-pin");
    if (pinInput) pinInput.value = parsed.pin;
  }
});

document.getElementById("family-accept-btn")?.addEventListener("click", async () => {
  let code = (document.getElementById("family-join-code")?.value || "").trim();
  let pin = (document.getElementById("family-join-pin")?.value || "").trim();
  // Belt-and-suspenders: if the user clicks Join before the input handler fires,
  // unpack the URL here too.
  const parsed = _inviteHelpers ? _inviteHelpers.parseInviteUrl(code) : null;
  if (parsed) {
    code = parsed.code;
    pin = parsed.pin;
  }
  const errBox = document.getElementById("family-join-error");
  if (!code || !/^\d{4}$/.test(pin)) {
    errBox.textContent = t("options_family_join_invalid_input");
    errBox.hidden = false;
    return;
  }
  errBox.hidden = true;
  const stored = await chrome.storage.local.get(["auth_token"]);
  if (!stored.auth_token) return;
  const api = await lazyFamilyApi();
  const joined = await api.acceptInvite(stored.auth_token, code, pin);
  if (joined) {
    await loadFamilyHub();
  } else {
    errBox.textContent = t("options_family_join_failed");
    errBox.hidden = false;
  }
});

document.getElementById("family-invite-btn")?.addEventListener("click", async () => {
  if (!_familyState.currentFamilyId || !_familyState.token) return;
  const api = await lazyFamilyApi();
  const invite = await api.createInvite(_familyState.token, _familyState.currentFamilyId);
  if (!invite) {
    alert(t("options_family_invite_failed"));
    return;
  }
  // Show modal with code+PIN — appears ONCE, server keeps only hashes.
  const modal = document.getElementById("family-invite-modal");
  document.getElementById("family-invite-code-display").textContent = invite.code;
  document.getElementById("family-invite-pin-display").textContent = invite.pin;

  // Build a shareable URL via the shared helper (same encoding rules as the
  // landing /family/join route + the smoke tests).
  const inviteUrl = _inviteHelpers
    ? _inviteHelpers.buildInviteUrl(invite.code, invite.pin)
    : "https://cleanway.ai/family/join#code=" +
      encodeURIComponent(invite.code) +
      "&pin=" +
      encodeURIComponent(invite.pin);

  // Render the QR if the vendored generator is loaded. Wrapped in a try/
  // catch so a broken QR never blocks the modal — the manual code+PIN are
  // still visible above.
  const qrWrap = document.getElementById("family-invite-qr-wrap");
  const qrEl = document.getElementById("family-invite-qr");
  if (qrEl) qrEl.innerHTML = "";
  try {
    if (typeof qrcode !== "undefined" && qrEl) {
      // Type 0 = auto-pick smallest version that fits; M = 15% redundancy
      // (good middle ground for screens-photographed-by-phone).
      const q = qrcode(0, "M");
      q.addData(inviteUrl);
      q.make();
      // 4-pixel module, 4-module quiet zone — scans cleanly from a phone.
      qrEl.innerHTML = q.createImgTag(4, 4, t("options_family_invite_qr_alt"));
      if (qrWrap) qrWrap.hidden = false;
    }
  } catch (e) {
    if (qrWrap) qrWrap.hidden = true;
    console.warn("QR render failed", e);
  }

  // Shareable link block.
  const linkWrap = document.getElementById("family-invite-link-wrap");
  const linkDisplay = document.getElementById("family-invite-link-display");
  if (linkDisplay) linkDisplay.textContent = inviteUrl;
  if (linkWrap) linkWrap.hidden = false;

  modal.hidden = false;

  document.getElementById("family-invite-copy-btn").onclick = async () => {
    try {
      await navigator.clipboard.writeText(t("options_family_invite_share", [invite.code, invite.pin]));
      flashLabel(document.getElementById("family-invite-copy-btn"), t("options_copied"), "family_invite_copy_btn");
    } catch {
      // Clipboard blocked
    }
  };

  const linkCopyBtn = document.getElementById("family-invite-link-copy-btn");
  if (linkCopyBtn) {
    linkCopyBtn.onclick = async () => {
      try {
        await navigator.clipboard.writeText(inviteUrl);
        flashLabel(linkCopyBtn, t("options_copied"), "family_invite_link_copy_btn");
      } catch {
        // Clipboard blocked
      }
    };
  }

  document.getElementById("family-invite-close-btn").onclick = () => {
    modal.hidden = true;
    // Hide the link/QR sections so the next open of an empty modal looks clean.
    if (qrWrap) qrWrap.hidden = true;
    if (linkWrap) linkWrap.hidden = true;
  };
});

// Initial load
loadFamilyHub().catch(() => {});
