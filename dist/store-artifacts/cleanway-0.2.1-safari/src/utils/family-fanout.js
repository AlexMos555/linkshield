/**
 * Family Hub auto-fan-out.
 *
 * When the background has shown a block page for a scam the API confirmed
 * (see background/page-blocks.js — a link on a page never counts), this
 * module:
 *   1. Gets the family + sibling pubkeys: the copy cached in
 *      chrome.storage.local, refreshed from the server once it is an hour
 *      old (familyStateFor). The Options page refreshes it too, but most
 *      people never open Options again after setup — without the background
 *      refresh, alerts stopped an hour after the last visit there.
 *   2. Skips if we sent an alert about the same domain in the last 10
 *      minutes — prevents spam when someone reloads a phishing page
 *      multiple times in quick succession.
 *   3. Encrypts the alert payload to each sibling's pubkey via
 *      family-crypto.js's encryptForFamily helper and POSTs to
 *      /family/{id}/alerts.
 *
 * Imported statically by the background (a module service worker, where
 * import() is forbidden) and dynamically by the Options page.
 *
 * Fail-open: every error path silently no-ops. The block UX always
 * runs; family alerts are a best-effort courtesy.
 */

import { listMembers, listMyFamilies, submitAlerts } from "./family-api.js";
import { encryptForFamily, getOrCreateKeypair } from "./family-crypto.js";

const CACHE_KEY = "family_cache";
const DEDUP_KEY = "family_alerts_dedup";
const CACHE_TTL_MS = 60 * 60 * 1000;       // refresh from the server hourly
const DEDUP_WINDOW_MS = 10 * 60 * 1000;    // 10 minutes per domain
const DEDUP_MAX_ENTRIES = 200;             // cap memory: forget oldest

// ─── Family cache ──────────────────────────────────────────────────

/**
 * The cached family + sibling pubkey list, whatever its age, or null if
 * there is none or the structure is malformed (forgive forward-incompatible
 * writes).
 *
 * Shape: { family_id, members: [{user_id, public_key_b64}], cached_at,
 *          refresh_failed_at? }
 */
export async function readFamilyCache() {
  try {
    const data = await chrome.storage.local.get([CACHE_KEY]);
    const cached = data && data[CACHE_KEY];
    if (!cached || typeof cached !== "object") return null;
    if (!cached.family_id || !Array.isArray(cached.members)) return null;
    if (typeof cached.cached_at !== "number") return null;
    return cached;
  } catch {
    return null;
  }
}

// Due for a refresh: an hour since the last good fetch AND since the last
// failed attempt, so an offline laptop asks once an hour, not every minute.
function isStale(cached, now = Date.now()) {
  const lastTry = Math.max(cached.cached_at, cached.refresh_failed_at || 0);
  return now - lastTry > CACHE_TTL_MS;
}

/**
 * The user id inside a Supabase access token (the JWT `sub` claim), or null
 * for a malformed token — then every member counts as a sibling.
 *
 * @param {string} token
 * @returns {string|null}
 */
export function userIdFromToken(token) {
  try {
    const payload = JSON.parse(atob(String(token).split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    return typeof payload.sub === "string" ? payload.sub : null;
  } catch {
    return null;
  }
}

/**
 * Fetch the family and its members from the server and cache them.
 *
 * @param {string} token
 * @returns {Promise<{status: "ok", state: object} | {status: "none"} | {status: "failed"}>}
 *   "none": the server says this account is in no family (cache cleared);
 *   "failed": offline, server error or expired token — nothing was learned.
 */
export async function refreshFamilyCache(token) {
  if (!token) return { status: "failed" };
  const mine = await listMyFamilies(token);
  if (!mine || !Array.isArray(mine.families)) return { status: "failed" };
  if (mine.families.length === 0) {
    await clearFamilyCache();
    return { status: "none" };
  }
  // Single-family UX for v1, same as the Options page: the first one.
  const familyId = mine.families[0].family_id;
  const members = await listMembers(token, familyId);
  if (!members || !Array.isArray(members.members)) return { status: "failed" };
  await setFamilyCache(familyId, userIdFromToken(token), members.members);
  const state = await readFamilyCache();
  return state ? { status: "ok", state } : { status: "failed" };
}

/**
 * The family to alert and poll, refreshed from the server when the cached
 * copy is an hour old. If the refresh fails the stale copy is still used:
 * the server checks membership on every alert and inbox read anyway.
 *
 * @param {string|null} token
 * @returns {Promise<object|null>} null when there is no family
 */
export async function familyStateFor(token) {
  const cached = await readFamilyCache();
  if (cached && !isStale(cached)) return cached;
  if (!token) return cached;
  const refreshed = await refreshFamilyCache(token);
  if (refreshed.status === "ok") return refreshed.state;
  if (refreshed.status === "none") return null;
  if (cached) {
    try {
      await chrome.storage.local.set({ [CACHE_KEY]: { ...cached, refresh_failed_at: Date.now() } });
    } catch {
      // Silent — the next call just retries sooner.
    }
  }
  return cached;
}

/**
 * Persist the family + sibling list. Called by refreshFamilyCache and by
 * options.js after a successful Family Hub render.
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
 * Encrypt + submit alerts for blocks the API confirmed. Anything else — an
 * offline guess (source "local"), a caution, a platform verdict — is dropped
 * here as well as by the caller: a relative is told "a scam site was
 * blocked" only when that is what happened.
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

  // Confirmed blocks only, minus the ones already sent — before anything
  // that may touch the network.
  const fresh = [];
  for (const r of blockedResults) {
    if (!r || r.level !== "dangerous" || r.source !== "api" || !r.domain) continue;
    // eslint-disable-next-line no-await-in-loop
    const recent = await recentlySentForDomain(r.domain);
    if (recent) continue;
    fresh.push(r);
  }
  if (fresh.length === 0) return 0;

  const cache = await familyStateFor(token);
  if (!cache || cache.members.length === 0) {
    return 0; // No family or no siblings with keys — nothing to do
  }

  let secretKeyB64;
  try {
    const kp = await getOrCreateKeypair();
    secretKeyB64 = kp.secretKeyB64;
  } catch {
    return 0; // Key storage unavailable — defer
  }

  // Build envelopes per dangerous result × per sibling
  let totalSent = 0;
  for (const r of fresh) {
    const alert = {
      domain: r.domain,
      blocked_at: new Date().toISOString(),
      level: r.level,
      score: typeof r.score === "number" ? r.score : null,
      source: r.source,
      alert_type: "block",
    };
    try {
      const envelopes = encryptForFamily(alert, cache.members, secretKeyB64);
      if (!envelopes || envelopes.length === 0) continue;
      // eslint-disable-next-line no-await-in-loop
      const resp = await submitAlerts(token, cache.family_id, envelopes);
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
