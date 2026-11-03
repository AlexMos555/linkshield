/**
 * Google's credit under a verdict built on Google's lists.
 *
 * The server asks Google Web Risk about a checked site (production since
 * 2026-11-03; the hit keeps the `safe_browsing` code Safe Browsing v4 had).
 * Web Risk's rules for warnings (docs.cloud.google.com/web-risk/docs/
 * user-warnings, read 2026-11-03): a warning about a page Google flagged
 * carries "Advisory provided by Google" linked to the Web Risk Advisory and
 * lets people learn more (antiphishing.org for phishing, Google Search
 * Central for malware); a warning built only on other sources must not carry
 * Google's name. The extension (content/reason-labels.js) and the website
 * (landing/lib/google-advisory.ts) link the same pages —
 * scripts/test-landing-honesty.mjs holds the three to one list.
 */

/** The API's reason code for a hit on Google's lists. */
export const GOOGLE_REASON_CODE = "safe_browsing";

export const GOOGLE_ADVISORY_LINKS = Object.freeze({
  advisory: "https://docs.cloud.google.com/web-risk/docs/advisory",
  phishing: "https://www.antiphishing.org/",
  malware: "https://developers.google.com/search/docs/advanced/security/malware",
});

/** Whether one of a verdict's reasons is Google's. */
export function hasGoogleAdvisory(reasons: ReadonlyArray<{ code?: string }> | null | undefined): boolean {
  return Array.isArray(reasons) && reasons.some((r) => Boolean(r) && r.code === GOOGLE_REASON_CODE);
}
