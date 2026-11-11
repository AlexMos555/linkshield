/**
 * The "Try these" examples on the manual check screen (app/check.tsx): one
 * tap, one verdict of each kind. Each must keep giving that verdict, or the
 * first thing a new person tries teaches them the app is broken —
 * "paypa1-verify.tk" was an invented name, and by 2026-11-11 it answered
 * "This site doesn't exist" on both a Galaxy and an iPhone.
 *
 *  - safe: google.com — on the allowlist.
 *  - dangerous: list-canary.cleanway.ai — Cleanway's own name. The publisher
 *    writes it into every blocklist (LIST_CANARY in
 *    api/services/blocklist_artifact.py), so it is on the phone's list and
 *    the server's, and a monitor checks every 15 minutes that it is still
 *    blocked. It points nowhere: nothing can be hosted on it, and nobody
 *    else's site is called a scam for a demo. A real phishing name would be
 *    taken down — and off the lists — within days.
 *  - caution: pay-pal.com — a look-alike of paypal.com by its spelling alone
 *    (a hyphen inside the brand), which is the lesson and does not depend on
 *    what is hosted there.
 *
 * "evil.netlify.app" is gone too: it answered "safe", which under that name
 * taught the opposite of what it was there for.
 *
 * scripts/test-device-fixes.mjs pins the dangerous one to LIST_CANARY.
 */
export const DANGEROUS_EXAMPLE = "list-canary.cleanway.ai";

export const CHECK_EXAMPLES: readonly string[] = ["google.com", DANGEROUS_EXAMPLE, "pay-pal.com"];
