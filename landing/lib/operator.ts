/**
 * The company that runs Cleanway, exactly as the founder gave it (2026-10-22).
 *
 * The privacy policy (section 2, where it is also named as the controller)
 * and the terms (section 1) spell it out in every locale's strings; the home
 * footer fills it into landing.footer.operator. scripts/test-landing-honesty.mjs
 * fails if any locale drifts from these values.
 */
export const OPERATOR = {
  name: "ACECORE GLOBAL TECHNOLOGIES – FZCO",
  address: "Dubai Silicon Oasis (DSO), Dubai Digital Park, Building A2, Office 43029-001, Dubai, UAE",
  registration: "43029",
} as const;

/**
 * Whose developer account the App Store shows as the iPhone app's seller.
 * For now it is the founder's personal account (decision 2026-10-10: launch on
 * it, move the whole account to the company later —
 * docs/runbooks/company-accounts.md §3), so terms section 1 says so in every
 * locale. After the move: set "company" and drop that paragraph;
 * scripts/test-landing-honesty.mjs holds the two in step.
 */
export const APP_STORE_SELLER: "founder" | "company" = "founder";
