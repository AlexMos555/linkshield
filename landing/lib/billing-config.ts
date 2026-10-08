/**
 * The operator-billed subscription as configured for THIS deployment.
 *
 * lib/billing.ts holds the parsers and the rules (pure, import-free, table-
 * tested); this file binds them to the environment once, for the pages.
 * Everything stays off until NEXT_PUBLIC_BILLING_ENABLED is set in the Vercel
 * project and the site is rebuilt — NEXT_PUBLIC_* is inlined at build time.
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

export const BILLING_TERMS: BillingTerms = billingTermsFromEnv(process.env);
export const SELLER: Seller = sellerFromEnv(process.env);
export const STOP_NUMBER: string | null = stopNumberFromEnv(process.env);
export const SUPPORT_PHONE: string | null = supportPhoneFromEnv(process.env);

/** Which /pricing this visitor gets, with this deployment's flag. */
export function pricingVariantFor(visitor: Visitor): PricingVariant {
  return pricingVariant(paidPlansOffered(visitor), BILLING_ENABLED);
}
