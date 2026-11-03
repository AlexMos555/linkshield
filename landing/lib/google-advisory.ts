/**
 * Google's credit under a /check verdict built on Google's lists.
 *
 * The API asks Google Web Risk about a checked site (production since
 * 2026-11-03; the hit keeps the `safe_browsing` code Safe Browsing v4 had).
 * Web Risk's rules for warnings (docs.cloud.google.com/web-risk/docs/
 * user-warnings, read 2026-11-03): a warning about a page Google flagged
 * carries "Advisory provided by Google" linked to the Web Risk Advisory and
 * lets people learn more about its threat type (antiphishing.org for
 * phishing, Google Search Central for malware, Google's policy for unwanted
 * software — the API asks about all three); a warning built only on other
 * sources must not carry Google's name. The app (mobile/src/utils/
 * google-advisory.ts) and the extension (content/reason-labels.js) link the
 * same pages — scripts/test-landing-honesty.mjs holds the three to one list.
 *
 * A warning may also be shown only while Google's answer is valid ("Under no
 * other circumstances"). The /check page is cached and regenerated in the
 * background, so a cached copy can be served at any age: a verdict resting
 * on Google never goes into it — the browser fetches it live
 * (components/LiveCheckResult.tsx), and keeps it no longer than the API's
 * `advisory_ttl`.
 */

/** The API's reason code for a hit on Google's lists. */
export const GOOGLE_REASON_CODE = "safe_browsing";

export const GOOGLE_ADVISORY_LINKS = Object.freeze({
  advisory: "https://docs.cloud.google.com/web-risk/docs/advisory",
  phishing: "https://www.antiphishing.org/",
  malware: "https://developers.google.com/search/docs/advanced/security/malware",
  unwanted: "https://www.google.com/about/company/unwanted-software-policy.html",
});

/** Whether one of the verdict's reason codes (the API's `reason_codes`) is Google's. */
export function hasGoogleAdvisory(codes: readonly (string | undefined)[] | undefined | null): boolean {
  return Array.isArray(codes) && codes.includes(GOOGLE_REASON_CODE);
}
