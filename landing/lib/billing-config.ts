/**
 * The operator-billed subscription as configured for THIS deployment.
 *
 * lib/billing.ts holds the parsers and the rules (pure, import-free, table-
 * tested); this file binds them to the environment once, for the pages.
 * Everything stays off until NEXT_PUBLIC_BILLING_ENABLED is set in the Vercel
 * project and the site is rebuilt — NEXT_PUBLIC_* is inlined at build time.
 * Stripe's world plans have their own switch, NEXT_PUBLIC_STRIPE_LIVE.
 */
import {
  billingTermsFromEnv,
  pricingVariant,
  sellerFromEnv,
  stopNumberFromEnv,
  supportPhoneFromEnv,
  type BillingTerms,
  type PricingVariant,
  type Seller,
} from "@/lib/billing";
import { paidPlansOffered, type Visitor } from "@/lib/paid-plans";
import { isFlagOn } from "@/lib/support";

// Spelled out literally: Next inlines NEXT_PUBLIC_* only when the name is a
// literal `process.env.X`.
export const BILLING_ENABLED: boolean = isFlagOn(process.env.NEXT_PUBLIC_BILLING_ENABLED);

/**
 * Stripe checkout can take a payment end to end: real STRIPE_PRICE_* ids,
 * STRIPE_SECRET_KEY and the webhook (STRIPE_WEBHOOK_SECRET + the endpoint) on
 * the API — docs/runbooks/LAUNCH_ROADMAP.md. Off by default: until it is
 * set, the world /pricing is the free page (no plan cards, no buy button, no
 * Offer in the JSON-LD) instead of a "Get Unlimited" that ends in an error.
 * The API refuses such a checkout too (503 checkout_not_configured).
 */
export const STRIPE_LIVE: boolean = isFlagOn(process.env.NEXT_PUBLIC_STRIPE_LIVE);

export const BILLING_TERMS: BillingTerms = billingTermsFromEnv(process.env);
export const SELLER: Seller = sellerFromEnv(process.env);
export const STOP_NUMBER: string | null = stopNumberFromEnv(process.env);
export const SUPPORT_PHONE: string | null = supportPhoneFromEnv(process.env);

/** Which /pricing this visitor gets, with this deployment's flags. */
export function pricingVariantFor(visitor: Visitor): PricingVariant {
  return pricingVariant(paidPlansOffered(visitor), BILLING_ENABLED, STRIPE_LIVE);
}
