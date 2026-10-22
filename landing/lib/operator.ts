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
