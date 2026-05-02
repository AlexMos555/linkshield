/**
 * Family Hub REST client.
 *
 * Pairs with packages/extension-core/src/utils/family-crypto.js: this
 * module talks to /api/v1/family/* and never sees plaintext alert
 * content (encryption happens via family-crypto before any submit,
 * decryption after any list).
 *
 * All calls require an auth_token (Supabase access token) passed
 * explicitly so callers don't accidentally rely on a stale singleton.
 * Returns null on any non-2xx so the UI layer can show a polite
 * "couldn't load" state rather than crashing on a 503 from a
 * Supabase outage.
 */

// Reuse the API base resolution logic from utils/api.js so dev
// override (chrome.storage.local.api_url) works consistently.
let API_BASE = "https://api.cleanway.ai";
try {
  chrome.storage.local.get("api_url").then((data) => {
    if (data && typeof data.api_url === "string" && data.api_url.startsWith("http")) {
      API_BASE = data.api_url.replace(/\/$/, "");
    }
  }).catch(() => {});
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes && changes.api_url && typeof changes.api_url.newValue === "string") {
      API_BASE = changes.api_url.newValue.replace(/\/$/, "");
    }
  });
} catch { /* storage not available in tests */ }

async function _fetch(path, { method = "GET", token, body } = {}) {
  if (!token) return null;
  const headers = { Authorization: `Bearer ${token}` };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  try {
    const resp = await fetch(`${API_BASE}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (!resp.ok) return null;
    // Some endpoints (PATCH /overrides etc) may return empty bodies.
    const text = await resp.text();
    return text ? JSON.parse(text) : {};
  } catch {
    return null;
  }
}

// ─── Family lifecycle ──────────────────────────────────────────────

export async function createFamily(token, name = "My Family") {
  return _fetch("/api/v1/family", { method: "POST", token, body: { name } });
}

export async function registerMyKey(token, familyId, publicKeyB64, keyVersion = 1) {
  return _fetch(`/api/v1/family/${encodeURIComponent(familyId)}/keys`, {
    method: "POST",
    token,
    body: { public_key_b64: publicKeyB64, key_version: keyVersion },
  });
}

export async function listMembers(token, familyId) {
  return _fetch(`/api/v1/family/${encodeURIComponent(familyId)}/members`, { token });
}

// ─── Invites ──────────────────────────────────────────────────────

export async function createInvite(token, familyId) {
  return _fetch(`/api/v1/family/${encodeURIComponent(familyId)}/invite`, {
    method: "POST",
    token,
  });
}

export async function acceptInvite(token, code, pin) {
  return _fetch("/api/v1/family/accept", {
    method: "POST",
    token,
    body: { code, pin },
  });
}

// ─── Alerts (server-blind ciphertext I/O) ─────────────────────────

/**
 * @param {string} token
 * @param {string} familyId
 * @param {Array<{ recipient_user_id, ciphertext_b64, nonce_b64,
 *                  sender_pubkey_b64, alert_type? }>} envelopes
 *        — already encrypted client-side via family-crypto.js
 */
export async function submitAlerts(token, familyId, envelopes) {
  return _fetch(`/api/v1/family/${encodeURIComponent(familyId)}/alerts`, {
    method: "POST",
    token,
    body: { envelopes },
  });
}

export async function listAlerts(token, familyId) {
  return _fetch(`/api/v1/family/${encodeURIComponent(familyId)}/alerts`, { token });
}
