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
 * NEXT_PUBLIC_STRIPE_LIVE (lib/billing-config.ts): Stripe checkout can take a
 * payment, so the world /pricing sells the device plan. Off — the default —
 * it is the free page. Inlined at build time like the flag above: specs that
 * assert one state skip in the other.
 */
export const STRIPE_LIVE: boolean = ["1", "true", "yes", "on"].includes(
  (process.env.NEXT_PUBLIC_STRIPE_LIVE ?? "").trim().toLowerCase(),
);

/**
 * NEXT_PUBLIC_SUPPORT_EMAIL_LIVE, read like lib/support.ts: the mailbox is
 * live unless the flag explicitly says 0/false/no/off (on in CI).
 */
export const SUPPORT_LIVE: boolean = !["0", "false", "no", "off"].includes(
  (process.env.NEXT_PUBLIC_SUPPORT_EMAIL_LIVE ?? "").trim().toLowerCase(),
);
