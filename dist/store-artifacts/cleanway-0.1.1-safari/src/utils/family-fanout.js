/**
 * Family Hub auto-fan-out.
 *
 * When background.js detects a dangerous block, this module:
 *   1. Reads the cached family + sibling pubkeys from chrome.storage.local
 *      (refreshed by options.js whenever the user opens the Family Hub
 *      panel; freshness check below caps a stale entry at 1 hour).
 *   2. Skips if we sent an alert about the same domain in the last 10
 *      minutes — prevents spam when someone reloads a phishing page
 *      multiple times in quick succession.
 *   3. Encrypts the alert payload to each sibling's pubkey via
 *      family-crypto.js's encryptForFamily helper and POSTs to
 *      /family/{id}/alerts.
 *
 * Loaded into the MV3 service-worker context via importScripts of
 * tweetnacl + tweetnacl-util (at the top of background/index.js), so
 * globalThis.nacl is already populated before this module runs.
 *
 * Fail-open: every error path silently no-ops. The block UX always
 * runs; family alerts are a best-effort courtesy.
 */

const CACHE_KEY = "family_cache";
const DEDUP_KEY = "family_alerts_dedup";
const CACHE_TTL_MS = 60 * 60 * 1000;       // 1 hour
const DEDUP_WINDOW_MS = 10 * 60 * 1000;    // 10 minutes per domain
const DEDUP_MAX_ENTRIES = 200;             // cap memory: forget oldest

// ─── Family cache ──────────────────────────────────────────────────

/**
 * Pull the cached family + sibling pubkey list. Returns null if no
 * cache exists, the cache is older than CACHE_TTL_MS, or the structure
 * is malformed (forgive forward-incompatible writes).
 *
 * Shape: { family_id, members: [{user_id, public_key_b64}], cached_at }
 */
export async function getCachedFamilyState() {
  try {
    const data = await chrome.storage.local.get([CACHE_KEY]);
    const cached = data && data[CACHE_KEY];
    if (!cached || typeof cached !== "object") return null;
    if (!cached.family_id || !Array.isArray(cached.members)) return null;
    if (typeof cached.cached_at !== "number") return null;
    if (Date.now() - cached.cached_at > CACHE_TTL_MS) return null;
    return cached;
  } catch {
    return null;
  }
}

/**
 * Persist the family + sibling list. Called from options.js after a
 * successful Family Hub render so background.js can use the same data
 * without re-fetching the API on every block.
 *
 * @param {string} familyId
 * @param {string} myUserId — excluded from members[] so we don't
 *                            encrypt to ourselves
 * @param {Array<{user_id, public_key_b64, role}>} members — full list
 *        from /family/{id}/members; this fn filters out the caller +
 *        anyone without a published pubkey.
 */
export async function setFamilyCache(familyId, myUserId, members) {
  const siblings = (members || [])
    .filter((m) => m && m.user_id && m.user_id !== myUserId && m.public_key_b64);
  const value = {
    family_id: familyId,
    members: siblings.map((m) => ({ user_id: m.user_id, public_key_b64: m.public_key_b64 })),
    cached_at: Date.now(),
  };
  try {
    await chrome.storage.local.set({ [CACHE_KEY]: value });
  } catch {
    // chrome.storage quota error or context invalidated — silent
  }
}

export async function clearFamilyCache() {
  try {
    await chrome.storage.local.remove([CACHE_KEY, DEDUP_KEY]);
  } catch {
    // Silent
  }
}

// ─── Dedup window ──────────────────────────────────────────────────

async function _readDedup() {
  try {
    const data = await chrome.storage.local.get([DEDUP_KEY]);
    const map = data && data[DEDUP_KEY];
    return (map && typeof map === "object") ? map : {};
  } catch {
    return {};
  }
}

async function _writeDedup(map) {
  // Trim before write to keep storage bounded.
  const entries = Object.entries(map);
  if (entries.length > DEDUP_MAX_ENTRIES) {
    entries.sort((a, b) => b[1] - a[1]); // most recent first
    const trimmed = Object.fromEntries(entries.slice(0, DEDUP_MAX_ENTRIES));
    try { await chrome.storage.local.set({ [DEDUP_KEY]: trimmed }); } catch {}
    return;
  }
  try { await chrome.storage.local.set({ [DEDUP_KEY]: map }); } catch {}
}

/**
 * Returns true if we sent an alert about this domain within the last
 * DEDUP_WINDOW_MS. Lossy on storage failure (returns false → may
 * double-send, which is the safer side).
 */
export async function recentlySentForDomain(domain) {
  if (!domain) return false;
  const map = await _readDedup();
  const last = map[domain];
  return typeof last === "number" && Date.now() - last < DEDUP_WINDOW_MS;
}

export async function markSentForDomain(domain) {
  if (!domain) return;
  const map = await _readDedup();
  map[domain] = Date.now();
  await _writeDedup(map);
}

// ─── Main entry: fan-out ──────────────────────────────────────────

/**
 * Encrypt + submit alerts for a list of dangerous block results.
 *
 * @param {string} token — Supabase access token. No-op on null.
 * @param {Array<{ domain: string, score?: number, level?: string,
 *                  source?: string }>} blockedResults
 * @returns {Promise<number>} number of alerts actually submitted
 *          (after dedup / cache-miss filtering)
 */
export async function fanOutAlerts(token, blockedResults) {
  if (!token || !Array.isArray(blockedResults) || blockedResults.length === 0) {
    return 0;
  }

  const cache = await getCachedFamilyState();
  if (!cache || cache.members.length === 0) {
    return 0; // No family or no siblings with keys — nothing to do
  }

  // Need crypto helpers — loaded as ESM via dynamic import.
  // family-crypto.js itself relies on globalThis.nacl which the
  // service worker populated via importScripts() at startup.
  let crypto;
  try {
    crypto = await import(chrome.runtime.getURL("utils/family-crypto.js"));
  } catch {
    return 0;
  }

  let secretKeyB64;
  try {
    const kp = await crypto.getOrCreateKeypair();
    secretKeyB64 = kp.secretKeyB64;
  } catch {
    return 0; // No keypair yet (user hasn't opened Family Hub) — defer
  }

  // Filter dangerous + dedup
  const fresh = [];
  for (const r of blockedResults) {
    if (!r || r.level !== "dangerous" || !r.domain) continue;
    // eslint-disable-next-line no-await-in-loop
    const recent = await recentlySentForDomain(r.domain);
    if (recent) continue;
    fresh.push(r);
  }
  if (fresh.length === 0) return 0;

  // Build envelopes per dangerous result × per sibling
  let api;
  try {
    api = await import(chrome.runtime.getURL("utils/family-api.js"));
  } catch {
    return 0;
  }

  let totalSent = 0;
  for (const r of fresh) {
    const alert = {
      domain: r.domain,
      blocked_at: new Date().toISOString(),
      level: r.level,
      score: typeof r.score === "number" ? r.score : null,
      source: r.source || "extension",
      alert_type: "block",
    };
    try {
      const envelopes = crypto.encryptForFamily(alert, cache.members, secretKeyB64);
      if (!envelopes || envelopes.length === 0) continue;
      // eslint-disable-next-line no-await-in-loop
      const resp = await api.submitAlerts(token, cache.family_id, envelopes);
      if (resp && typeof resp.accepted === "number") {
        totalSent += resp.accepted;
        // eslint-disable-next-line no-await-in-loop
        await markSentForDomain(r.domain);
      }
    } catch {
      // Skip this domain; continue with others. Logging at this layer
      // would surface via the SW console which is fine, but we deliberately
      // stay silent so a single bad envelope doesn't spam logs.
    }
  }
  return totalSent;
}
