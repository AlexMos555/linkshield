/**
 * The background's verdict cache.
 *
 * In memory: a bounded LRU (JavaScript's Map keeps insertion order; a hit is
 * re-inserted at the tail, the head is evicted at the cap). MV3 service
 * workers can live for hours during active browsing, and an unbounded Map
 * grew by every domain the person ever saw.
 *
 * Every entry has its own lifetime:
 *   - an API verdict: an hour, and mirrored to chrome.storage.session, so a
 *     restarted worker (Chrome stops an idle one after 30 seconds) does not
 *     ask the API again for every link it already checked. storage.session
 *     is memory only, gone when the browser quits, and out of content
 *     scripts' reach (utils/token-store.js); where the browser has none
 *     (Firefox < 115, Safari < 16.4) the memory copy is all there is.
 *   - an answer made without the API (an official or user-content host, or
 *     the offline verdict when the API did not answer): memory only, for as
 *     long as the caller says (background/public-check.js decides that for a
 *     fallback; 0 keeps nothing).
 */

export const VERDICT_TTL_MS = 3600_000;
export const MAX_ENTRIES = 1000;
export const SESSION_PREFIX = "cw_verdict:";
const PRUNE_EVERY_WRITES = 200;

/** storage.session when this browser has it, else null. */
export function sessionArea(api) {
  try {
    const s = api && api.storage && api.storage.session;
    return s && typeof s.get === "function" && typeof s.set === "function" && typeof s.remove === "function" ? s : null;
  } catch (e) {
    return null;
  }
}

export function createVerdictCache({ session = null, now = () => Date.now(), maxEntries = MAX_ENTRIES } = {}) {
  const memory = new Map(); // domain → {r, until, api}
  let writes = 0;

  function put(domain, r, ttlMs, api) {
    memory.delete(domain);
    if (!(ttlMs > 0)) return;
    if (memory.size >= maxEntries) {
      const oldest = memory.keys().next().value;
      if (oldest !== undefined) memory.delete(oldest);
    }
    memory.set(domain, { r, until: now() + ttlMs, api });
  }

  /**
   * The cached result, or null. `apiOnly`: only an API verdict counts (the
   * page check never settles for a fallback — it asks the API again).
   */
  function get(domain, { apiOnly = false } = {}) {
    const e = memory.get(domain);
    if (!e) return null;
    if (now() >= e.until) {
      memory.delete(domain);
      return null;
    }
    if (apiOnly && !e.api) return null;
    memory.delete(domain); // LRU touch
    memory.set(domain, e);
    return e.r;
  }

  /** An answer from the API: an hour, in memory and in storage.session. */
  function setVerdict(domain, r) {
    put(domain, r, VERDICT_TTL_MS, true);
    if (!session) return;
    session.set({ [SESSION_PREFIX + domain]: { r, until: now() + VERDICT_TTL_MS } }).catch(() => {});
    writes++;
    if (writes % PRUNE_EVERY_WRITES === 0) prune().catch(() => {});
  }

  /** An answer made without the API: memory only, for ttlMs. */
  function setLocal(domain, r, ttlMs) {
    put(domain, r, ttlMs, false);
  }

  /** Bring back the API verdicts a previous worker kept, for these domains. */
  async function hydrate(domains) {
    if (!session) return;
    const missing = domains.filter((d) => !memory.has(d));
    if (!missing.length) return;
    let stored;
    try {
      stored = await session.get(missing.map((d) => SESSION_PREFIX + d));
    } catch (e) {
      return;
    }
    const t = now();
    for (const d of missing) {
      const e = stored && stored[SESSION_PREFIX + d];
      if (memory.has(d) || !e || typeof e.until !== "number" || e.until <= t || !e.r || typeof e.r !== "object") continue;
      put(d, e.r, Math.min(e.until - t, VERDICT_TTL_MS), true);
    }
  }

  /** Drop expired verdicts from storage.session, and the oldest past the cap. */
  async function prune() {
    if (!session) return 0;
    const all = await session.get(null);
    const t = now();
    const mine = Object.entries(all || {}).filter(([k]) => k.startsWith(SESSION_PREFIX));
    const live = mine.filter(([, v]) => v && typeof v.until === "number" && v.until > t);
    const expired = mine.filter((entry) => !live.includes(entry)).map(([k]) => k);
    live.sort((a, b) => a[1].until - b[1].until);
    const over = live.slice(0, Math.max(0, live.length - maxEntries)).map(([k]) => k);
    const drop = expired.concat(over);
    if (drop.length) await session.remove(drop);
    return drop.length;
  }

  return { get, setVerdict, setLocal, hydrate, prune };
}
