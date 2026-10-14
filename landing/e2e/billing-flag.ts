/**
 * The operator-billed subscription flag, as the server under test was built
 * with it. NEXT_PUBLIC_BILLING_ENABLED is inlined at build time, so the test
 * process must be given the same value as the build (the CI matrix does);
 * specs that assert one state skip in the other. Same parsing as
 * lib/support.ts isFlagOn.
 */
export const BILLING_ON: boolean = ["1", "true", "yes", "on"].includes(
  (process.env.NEXT_PUBLIC_BILLING_ENABLED ?? "").trim().toLowerCase(),
);

/**
 * NEXT_PUBLIC_SUPPORT_EMAIL_LIVE, read like lib/support.ts: the mailbox is
 * live unless the flag explicitly says 0/false/no/off (on in CI).
 */
export const SUPPORT_LIVE: boolean = !["0", "false", "no", "off"].includes(
  (process.env.NEXT_PUBLIC_SUPPORT_EMAIL_LIVE ?? "").trim().toLowerCase(),
);
