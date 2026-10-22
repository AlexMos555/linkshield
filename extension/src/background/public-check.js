/**
 * The public site check, as the background asks it:
 * GET /api/v1/public/check/{host}, for the page the person is on and for
 * every link host on it.
 *
 * What went wrong before 0.2.2: one request per host, one after another,
 * with no install header, so the whole browser shared its IP's 60 checks an
 * hour (behind a carrier NAT, a neighbourhood's). A 429 or a timeout was
 * cached as the offline verdict for an hour, the page check waited behind
 * the links, and nothing noticed that server-side protection had stopped.
 *
 * Now:
 *   - Every check carries X-Cleanway-Install: a random UUID made here, kept
 *     in chrome.storage.local and replaced every 24 hours, so the server
 *     limits this browser on its own (api/services/rate_limiter.py
 *     install_key). It is not derived from the browser, the device id or the
 *     account; the server keeps only a hash of it, for an hour at most.
 *   - A 429 pauses LINK lookups until its Retry-After (header, else the
 *     body's retry_after_seconds, else a minute). The page check is still
 *     sent: it is the one that blocks a scam page.
 *   - A fallback (the offline verdict) is kept only until the API can be
 *     asked again: after a 429, until the pause ends (at most 5 minutes);
 *     after a timeout, an error status or a network failure, 2 minutes.
 *   - Lookups run a few at a time (mapLimit), not one after another.
 *
 * The answer itself is cached by background/verdict-cache.js.
 */

export const INSTALL_KEY = "cleanway_install";
export const INSTALL_HEADER = "X-Cleanway-Install";
export const INSTALL_RENEW_MS = 24 * 3600_000;
export const LOOKUP_TIMEOUT_MS = 3000;
export const LOOKUP_CONCURRENCY = 4;
export const DEFAULT_RETRY_AFTER_MS = 60_000;
export const MAX_RETRY_AFTER_MS = 3600_000;
export const FALLBACK_TTL_MS = 2 * 60_000;
export const MAX_PAUSED_FALLBACK_TTL_MS = 5 * 60_000;
export const PAUSE_KEY = "public_check_paused_until";

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function isInstallId(value) {
  return typeof value === "string" && UUID_V4.test(value);
}

/** RFC 4122 version-4 UUID from the platform's secure random source. */
export function randomUuid(cryptoImpl = globalThis.crypto) {
  if (cryptoImpl && typeof cryptoImpl.randomUUID === "function") return cryptoImpl.randomUUID();
  const b = new Uint8Array(16);
  cryptoImpl.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const hex = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * This install's rate-limit number. `get()` resolves the UUID, or null when
 * none can be made (the check then goes without the header, limited per IP).
 * @param {{get: Function, set: Function}} storage  chrome.storage.local
 */
export function createInstallId(storage, { now = () => Date.now(), crypto: cryptoImpl = globalThis.crypto } = {}) {
  let current = null;
  let pending = null;

  const fresh = (v, t) => Boolean(v) && isInstallId(v.id) && typeof v.made_at === "number"
    && v.made_at <= t && t - v.made_at < INSTALL_RENEW_MS;

  async function load() {
    const t = now();
    if (fresh(current, t)) return current.id;
    try {
      const stored = await storage.get(INSTALL_KEY);
      const v = stored && stored[INSTALL_KEY];
      if (fresh(v, t)) {
        current = v;
        return v.id;
      }
    } catch (e) { /* storage unavailable: a number for this worker only */ }
    try {
      current = { id: randomUuid(cryptoImpl), made_at: t };
    } catch (e) {
      return null;
    }
    try {
      await storage.set({ [INSTALL_KEY]: current });
    } catch (e) { /* kept in memory */ }
    return current.id;
  }

  return {
    get() {
      if (!pending) pending = load().finally(() => { pending = null; });
      return pending;
    },
  };
}

/** How long a 429 asks us to wait, in ms (0 … MAX_RETRY_AFTER_MS). */
export function retryAfterMs(header, body, nowMs) {
  let ms = null;
  const v = typeof header === "string" ? header.trim() : "";
  if (/^\d+$/.test(v)) {
    ms = Number(v) * 1000;
  } else if (v) {
    const at = Date.parse(v);
    if (!Number.isNaN(at)) ms = at - nowMs;
  }
  if (ms === null) {
    const s = body && body.detail && typeof body.detail === "object" ? body.detail.retry_after_seconds : null;
    if (typeof s === "number" && Number.isFinite(s) && s >= 0) ms = s * 1000;
  }
  if (ms === null) ms = DEFAULT_RETRY_AFTER_MS;
  return Math.min(Math.max(ms, 0), MAX_RETRY_AFTER_MS);
}

/** Run fn over items, at most `limit` at a time; results in input order. */
export async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  }
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker);
  await Promise.all(workers);
  return out;
}

/**
 * @param {object} deps
 * @param {(url: string, init: object) => Promise<Response>} deps.fetchImpl
 * @param {() => string} deps.apiBase  the allowlisted API base (utils/api-base.js)
 * @param {{get: () => Promise<string|null>}} deps.installId
 * @param {object|null} [deps.pauseStore]  chrome.storage.session, so a worker
 *   restart does not walk straight back into the limit
 */
export function createPublicCheck({ fetchImpl, apiBase, installId, pauseStore = null, now = () => Date.now(), timeoutMs = LOOKUP_TIMEOUT_MS }) {
  let pausedUntil = 0;
  if (pauseStore) {
    pauseStore.get(PAUSE_KEY).then((d) => {
      const v = d && d[PAUSE_KEY];
      if (typeof v === "number" && v > pausedUntil) pausedUntil = Math.min(v, now() + MAX_RETRY_AFTER_MS);
    }).catch(() => {});
  }

  /** Milliseconds left before link lookups may ask the API again. */
  function pausedFor() {
    return Math.max(0, pausedUntil - now());
  }

  function pause(ms) {
    pausedUntil = Math.max(pausedUntil, now() + ms);
    if (pauseStore) pauseStore.set({ [PAUSE_KEY]: pausedUntil }).catch(() => {});
  }

  /**
   * One host. Resolves {data} with the API's answer, or {data: null, ttlMs}:
   * the caller uses the offline verdict and keeps it for ttlMs (0: not at all).
   */
  async function lookup(domain, { page = false } = {}) {
    const waiting = pausedFor();
    if (!page && waiting > 0) return { data: null, ttlMs: Math.min(waiting, MAX_PAUSED_FALLBACK_TTL_MS) };
    const headers = {};
    const id = await installId.get().catch(() => null);
    if (id) headers[INSTALL_HEADER] = id;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const resp = await fetchImpl(`${apiBase()}/api/v1/public/check/${encodeURIComponent(domain)}`, {
        headers,
        signal: ctrl.signal,
        credentials: "omit",
      });
      if (resp.status === 429) {
        let body = null;
        try { body = await resp.json(); } catch (e) { /* no JSON body */ }
        const header = resp.headers && typeof resp.headers.get === "function" ? resp.headers.get("Retry-After") : null;
        const wait = retryAfterMs(header, body, now());
        pause(wait);
        return { data: null, ttlMs: Math.min(wait, MAX_PAUSED_FALLBACK_TTL_MS) };
      }
      if (!resp.ok) return { data: null, ttlMs: FALLBACK_TTL_MS };
      const data = await resp.json(); // inside the timer: a stalled body times out too
      return data && typeof data === "object" ? { data } : { data: null, ttlMs: FALLBACK_TTL_MS };
    } catch (e) {
      return { data: null, ttlMs: FALLBACK_TTL_MS };
    } finally {
      clearTimeout(timer);
    }
  }

  return { lookup, pausedFor };
}
