/**
 * Cleanway API Client
 *
 * Handles communication with the Cleanway backend.
 * Privacy: only domain names are sent — never full URLs or page content.
 */

// API base resolution: chrome.storage.local.api_url (dev override) → production Railway URL
// To use local dev: Options page → set API URL to http://localhost:8000 → Save
let API_BASE = "https://api.cleanway.ai";
try {
  chrome.storage.local.get("api_url").then(function(data) {
    if (data && typeof data.api_url === "string" && data.api_url.startsWith("http")) {
      API_BASE = data.api_url.replace(/\/$/, "");
    }
  }).catch(function() {});
  chrome.storage.onChanged.addListener(function(changes, area) {
    if (area === "local" && changes && changes.api_url && typeof changes.api_url.newValue === "string") {
      API_BASE = changes.api_url.newValue.replace(/\/$/, "");
    }
  });
} catch (e) { /* storage not available (tests, edge cases) */ }

/**
 * Check domains against Cleanway API
 * @param {string[]} domains - List of domain names to check
 * @param {string} [token] - Optional JWT auth token
 * @returns {Promise<{results: Array, checked_at: string, api_calls_remaining: number}>}
 */
export async function checkDomains(domains, token = null) {
  const headers = { "Content-Type": "application/json" };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  try {
    const resp = await fetch(`${API_BASE}/api/v1/check`, {
      method: "POST",
      headers,
      body: JSON.stringify({ domains }),
    });

    if (resp.status === 429) {
      const data = await resp.json();
      return { error: "rate_limit", detail: data.detail };
    }

    if (!resp.ok) {
      return { error: "api_error", status: resp.status };
    }

    return await resp.json();
  } catch (e) {
    return { error: "network_error", message: e.message };
  }
}

/**
 * Resolve a stable device hash (UUID v4) for this browser install.
 *
 * Persisted in chrome.storage.local so it survives popup/options
 * reloads and extension restarts. A user reinstalling the extension
 * gets a new hash — that's intentional: it represents "this install"
 * not "this physical machine", which matches how the backend
 * `devices` table is keyed (user_id + device_hash UNIQUE).
 *
 * @returns {Promise<string>}
 */
export async function getDeviceHash() {
  try {
    const stored = await chrome.storage.local.get("device_hash");
    if (stored && typeof stored.device_hash === "string" && stored.device_hash.length > 0) {
      return stored.device_hash;
    }
    const fresh = generateUuid();
    await chrome.storage.local.set({ device_hash: fresh });
    return fresh;
  } catch {
    // Storage unavailable (preview / very edge cases) — return a
    // session-scoped UUID. Won't persist but the helper still returns
    // a string so callers don't have to null-check.
    return generateUuid();
  }
}

function generateUuid() {
  // crypto.randomUUID is available in MV3 service workers + popups
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  // Fallback for older runtimes
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * Fetch the resolved effective skill + accessibility for THIS device.
 *
 * Returns { device_hash, skill_level, voice_alerts_enabled, font_scale,
 *           skill_source, voice_source, font_source }
 * where each *_source is "device_override" or "user_default" — used by
 * the options UI to show "Set on this device" badges per field.
 *
 * @param {string|null} token JWT
 * @param {string} deviceHash from getDeviceHash()
 * @returns {Promise<object|null>}
 */
export async function fetchEffectiveSkill(token, deviceHash) {
  if (!token || !deviceHash) return null;
  try {
    const url = `${API_BASE}/api/v1/user/device/${encodeURIComponent(deviceHash)}/effective`;
    const resp = await fetch(url, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!resp.ok) return null;
    return await resp.json();
  } catch {
    return null;
  }
}

/**
 * PATCH device-scoped overrides — Family Hub use case (admin enables
 * Granny Mode on grandmother's specific phone without changing her
 * account-level default).
 *
 * Payload accepts any subset of:
 *   { skill_level_override, voice_alerts_enabled, font_scale,
 *     clear_overrides }
 *
 * @param {string|null} token
 * @param {string} deviceHash
 * @param {object} payload
 * @returns {Promise<object|null>}
 */
export async function patchDeviceOverrides(token, deviceHash, payload) {
  if (!token || !deviceHash) return null;
  try {
    const url = `${API_BASE}/api/v1/user/device/${encodeURIComponent(deviceHash)}/overrides`;
    const resp = await fetch(url, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(payload || {}),
    });
    if (!resp.ok) return null;
    return await resp.json();
  } catch {
    return null;
  }
}

/**
 * Fetch the freemium-threshold + paid-tier gating state for the user.
 *
 * Returns null when no auth token (anonymous user — server-side counter
 * isn't tracked) or when the API is unreachable. Callers should treat
 * null as "show no nudge" and gracefully degrade.
 *
 * Shape: { threats_blocked_lifetime, threshold, gated, tier,
 *          nudge_shown_at, nudge_count }
 *
 * @param {string|null} token JWT
 * @returns {Promise<object|null>}
 */
export async function fetchThreatStatus(token) {
  if (!token) return null;
  try {
    const resp = await fetch(`${API_BASE}/api/v1/user/threats/status`, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!resp.ok) return null;
    return await resp.json();
  } catch {
    return null;
  }
}

/**
 * Increment the lifetime threat counter when extension blocks a scam.
 *
 * Best-effort: no error surfacing — the block already happened
 * client-side and the user shouldn't see a red toast because the
 * server counter sync flaked.
 *
 * @param {string|null} token JWT
 * @param {number} count number of threats freshly blocked since last sync
 * @returns {Promise<object|null>} updated status or null
 */
export async function incrementThreatCounter(token, count = 1) {
  if (!token || count < 1) return null;
  try {
    const resp = await fetch(`${API_BASE}/api/v1/user/threats/increment`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ count }),
    });
    if (!resp.ok) return null;
    return await resp.json();
  } catch {
    return null;
  }
}

/**
 * Extract unique domains from a list of URLs
 * @param {string[]} urls
 * @returns {string[]}
 */
export function extractDomains(urls) {
  const domains = new Set();
  for (const url of urls) {
    try {
      const parsed = new URL(url.startsWith("http") ? url : `https://${url}`);
      if (parsed.hostname && parsed.hostname !== "localhost") {
        domains.add(parsed.hostname.toLowerCase());
      }
    } catch {
      // Skip invalid URLs
    }
  }
  return [...domains];
}
