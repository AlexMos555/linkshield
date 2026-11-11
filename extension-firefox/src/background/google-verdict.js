/**
 * A verdict that rests on Google's lists, and how long it may be kept.
 *
 * The API's code for a hit on Google's lists is `safe_browsing` (Safe
 * Browsing v4 once, Google Web Risk in production since 2026-11-03). Web
 * Risk's rules for warnings (docs.cloud.google.com/web-risk/docs/
 * user-warnings, read 2026-11-04) allow a warning only while "the cached
 * response is still valid at the time a warning is shown. Under no other
 * circumstances may a warning be shown." The public check says how many more
 * seconds that is (`advisory_ttl`, api/services/google_advisory.py; null when
 * no reason is Google's), and:
 *   - the verdict cache keeps such a verdict no longer (apiVerdictTtlMs);
 *   - the verdict goes out with the end of that window (advisoryUntil), and
 *     the surfaces that keep a warning on screen take it down then: the link
 *     badges (content/index.js) and the block page, whose address carries it
 *     (utils/blocked-url.js, blocked/blocked.js);
 *   - a relative is never told about such a block (restsOnGoogle,
 *     hasGoogleWindow): a family alert carries no "Advisory provided by
 *     Google" and is shown whenever the relative's poll picks it up, long
 *     after Google's answer.
 * content/reason-labels.js draws Google's credit from the same code.
 */

export const GOOGLE_REASON_CODE = "safe_browsing";

/**
 * How long a fresh answer resting on Google stays on screen when the server
 * gave it no window (advisory_ttl 0: Google's answer was valid when the API
 * replied, for how long nobody could read; or a server from before
 * advisory_ttl). Kept by no cache; taken down and asked again after this.
 * content/index.js and the website (landing/components/LiveCheckResult.tsx)
 * use the same 30 s.
 */
export const ZERO_WINDOW_SHOW_MS = 30_000;

/**
 * @param {Array<{ signal?: string }>} reasons a cached verdict's reasons
 * @returns {boolean} whether one of them is Google's
 */
export function restsOnGoogle(reasons) {
  return Array.isArray(reasons) && reasons.some((r) => Boolean(r) && r.signal === GOOGLE_REASON_CODE);
}

/**
 * How long an API verdict may be kept, in ms: `maxMs` as always, but never
 * past `advisory_ttl` when the server gives one. A verdict with Google's
 * reason and no usable window (a server from before advisory_ttl) is kept
 * nowhere: 0.
 * @param {{ reason_codes?: string[], advisory_ttl?: number|null }} data the API's answer
 * @param {number} maxMs the cache's own limit
 */
export function apiVerdictTtlMs(data, maxMs) {
  const left = data && data.advisory_ttl;
  if (typeof left === "number" && Number.isFinite(left) && left >= 0) {
    return Math.min(maxMs, Math.floor(left) * 1000);
  }
  const codes = data && Array.isArray(data.reason_codes) ? data.reason_codes : [];
  return codes.includes(GOOGLE_REASON_CODE) || (left !== undefined && left !== null) ? 0 : maxMs;
}

/**
 * Whether the API's answer rests on Google: it gives a window (the server
 * reads all reasons; the shown five may have left Google's out), or one of
 * its reason codes is Google's.
 */
export function answerRestsOnGoogle(data) {
  if (!data || typeof data !== "object") return false;
  if (typeof data.advisory_ttl === "number") return true;
  return Array.isArray(data.reason_codes) && data.reason_codes.includes(GOOGLE_REASON_CODE);
}

/**
 * When a verdict made from this answer must leave the screen (epoch ms):
 * the end of its cache window `ttlMs` (apiVerdictTtlMs), or with no window,
 * ZERO_WINDOW_SHOW_MS from `nowMs`. Null for an answer not resting on Google.
 */
export function advisoryUntil(data, ttlMs, nowMs) {
  if (!answerRestsOnGoogle(data)) return null;
  return nowMs + (ttlMs > 0 ? ttlMs : ZERO_WINDOW_SHOW_MS);
}

/** Whether a verdict the background handed out carries Google's window. */
export function hasGoogleWindow(verdict) {
  return Boolean(verdict) && typeof verdict.advisory_until === "number" && Number.isFinite(verdict.advisory_until);
}
