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
 *   - a relative is never told about such a block (restsOnGoogle): a family
 *     alert carries no "Advisory provided by Google" and is shown whenever the
 *     relative's poll picks it up, long after Google's answer.
 * content/reason-labels.js draws Google's credit from the same code.
 */

export const GOOGLE_REASON_CODE = "safe_browsing";

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
