/**
 * The operator-billed subscription (Russia) — what the site may say about it.
 *
 * Everything here is OFF until NEXT_PUBLIC_BILLING_ENABLED is set in the
 * Vercel project (and the site rebuilt: NEXT_PUBLIC_* is inlined at build
 * time). With the flag off, every page renders exactly as before: /pricing
 * keeps the free-only page for Russian visitors, /cancel does not exist, the
 * terms and the policy keep their current payment sections.
 *
 * The numbers are the founder's settings, not facts of the code: the same env
 * names as the API's `BillingSettings` (docs/BILLING.md) with a NEXT_PUBLIC_
 * prefix, so the page and the server can be configured from one sheet.
 * Hand-written prices are banned from the strings by
 * scripts/check-landing-claims.py; the components pass these values as ICU
 * arguments instead.
 */

// No imports: scripts/test-landing-honesty.mjs loads this file straight into
// Node, where the "@/" alias does not exist. The flag and the env-bound values
// live in lib/billing-config.ts.

export type PlanCode = "solo" | "family3" | "family5";

export interface Plan {
  readonly code: PlanCode;
  /** Phones one payment covers. */
  readonly devices: 1 | 3 | 5;
  /** Monthly price, whole rubles. */
  readonly priceRub: number;
}

export type LapsePolicy = "basic" | "off";

export interface BillingTerms {
  readonly plans: readonly Plan[];
  readonly trialDays: number;
  readonly graceDays: number;
  /** What happens after the grace window: `basic` keeps list blocking, `off` stops it. */
  readonly lapsePolicy: LapsePolicy;
}

/** The founder's prices (2026-09-29): 99 / 270 / 399 ₽ a month. */
export const DEFAULT_PRICES_RUB: Readonly<Record<PlanCode, number>> = { solo: 99, family3: 270, family5: 399 };
export const DEFAULT_TRIAL_DAYS = 14;
export const DEFAULT_GRACE_DAYS = 7;
export const DEFAULT_LAPSE_POLICY: LapsePolicy = "basic";

const PLAN_DEVICES: Readonly<Record<PlanCode, 1 | 3 | 5>> = { solo: 1, family3: 3, family5: 5 };
const PLAN_ORDER: readonly PlanCode[] = ["solo", "family3", "family5"];

type Env = Readonly<Record<string, string | undefined>>;

/** A whole positive number from an env value; anything else is the fallback. */
export function parsePositiveInt(raw: string | undefined | null, fallback: number): number {
  const text = (raw ?? "").trim();
  if (!/^\d{1,6}$/.test(text)) return fallback;
  const value = Number(text);
  return value > 0 ? value : fallback;
}

/** `off` switches protection off after grace; every other value is the default `basic`. */
export function parseLapsePolicy(raw: string | undefined | null): LapsePolicy {
  return (raw ?? "").trim().toLowerCase() === "off" ? "off" : DEFAULT_LAPSE_POLICY;
}

export function billingTermsFromEnv(env: Env): BillingTerms {
  const prices: Record<PlanCode, number> = {
    solo: parsePositiveInt(env.NEXT_PUBLIC_BILLING_PRICE_SOLO_RUB, DEFAULT_PRICES_RUB.solo),
    family3: parsePositiveInt(env.NEXT_PUBLIC_BILLING_PRICE_FAMILY3_RUB, DEFAULT_PRICES_RUB.family3),
    family5: parsePositiveInt(env.NEXT_PUBLIC_BILLING_PRICE_FAMILY5_RUB, DEFAULT_PRICES_RUB.family5),
  };
  return {
    plans: PLAN_ORDER.map((code) => ({ code, devices: PLAN_DEVICES[code], priceRub: prices[code] })),
    trialDays: parsePositiveInt(env.NEXT_PUBLIC_BILLING_TRIAL_DAYS, DEFAULT_TRIAL_DAYS),
    graceDays: parsePositiveInt(env.NEXT_PUBLIC_BILLING_GRACE_DAYS, DEFAULT_GRACE_DAYS),
    lapsePolicy: parseLapsePolicy(env.NEXT_PUBLIC_BILLING_LAPSE_POLICY),
  };
}

/** Rubles per phone a month, rounded to whole rubles ("≈ 80 ₽ за телефон"). */
export function pricePerDevice(plan: Plan): number {
  return Math.round(plan.priceRub / plan.devices);
}

/**
 * The ICU arguments every billing string may use: the three prices and the
 * windows. Prices go in as strings so a locale's number formatting cannot
 * change them (Intl renders 399 as ٣٩٩ for Arabic); the day counts stay
 * numbers because the strings pluralise on them.
 */
export function billingMessageArgs(terms: BillingTerms): Record<string, string | number> {
  const byCode = Object.fromEntries(terms.plans.map((plan) => [plan.code, plan.priceRub])) as Record<PlanCode, number>;
  return {
    solo: String(byCode.solo),
    family3: String(byCode.family3),
    family5: String(byCode.family5),
    days: terms.trialDays,
    grace: terms.graceDays,
  };
}

export type PricingVariant = "stripe" | "operator" | "free";

/**
 * Which /pricing a visitor gets. Stripe plans where they are sold
 * (`stripeOffered` = lib/paid-plans.ts); for everyone else — Russian visitors —
 * the operator-billed subscription once the flag is on, and until then the
 * free-only page they see today.
 */
export function pricingVariant(stripeOffered: boolean, billingEnabled: boolean): PricingVariant {
  if (stripeOffered) return "stripe";
  return billingEnabled ? "operator" : "free";
}

/** The seller named on the pricing page and in the offer — an ИП, once registered. */
export interface Seller {
  readonly name: string | null;
  readonly inn: string | null;
  readonly ogrnip: string | null;
}

const INN_INDIVIDUAL = /^\d{12}$/;
const OGRNIP = /^\d{15}$/;

function optionalText(raw: string | undefined, pattern?: RegExp): string | null {
  const text = (raw ?? "").trim();
  if (!text) return null;
  if (pattern && !pattern.test(text)) return null;
  return text;
}

/**
 * Requisites from the environment. A malformed ИНН or ОГРНИП is dropped
 * rather than printed: a wrong number on an offer is worse than a pending one.
 */
export function sellerFromEnv(env: Env): Seller {
  return {
    name: optionalText(env.NEXT_PUBLIC_BILLING_SELLER_NAME),
    inn: optionalText(env.NEXT_PUBLIC_BILLING_SELLER_INN, INN_INDIVIDUAL),
    ogrnip: optionalText(env.NEXT_PUBLIC_BILLING_SELLER_OGRNIP, OGRNIP),
  };
}

/** True when every requisite the offer needs is present. */
export function sellerIsComplete(seller: Seller): boolean {
  return seller.name !== null && seller.inn !== null && seller.ogrnip !== null;
}

const SHORT_NUMBER = /^\d{4,6}$/;
const PHONE_E164 = /^\+\d{10,15}$/;

/** The short number for the SMS «СТОП» cancel channel, once the operator assigns one. */
export function stopNumberFromEnv(env: Env): string | null {
  return optionalText(env.NEXT_PUBLIC_BILLING_STOP_NUMBER, SHORT_NUMBER);
}

/** A support phone in E.164 (+7…), shown only when set. */
export function supportPhoneFromEnv(env: Env): string | null {
  return optionalText(env.NEXT_PUBLIC_SUPPORT_PHONE, PHONE_E164);
}

/** `+79991234567` → `+7 999 123-45-67` for Russian numbers; other numbers as given. */
export function formatPhone(e164: string): string {
  const match = /^\+7(\d{3})(\d{3})(\d{2})(\d{2})$/.exec(e164);
  return match ? `+7 ${match[1]} ${match[2]}-${match[3]}-${match[4]}` : e164;
}

export interface SectionLike {
  readonly id?: string;
}

/**
 * The terms and the policy each keep today's payment section (id `payments`:
 * "no paid plans in Russia, Stripe elsewhere"). With the flag on that section
 * is replaced in place by the operator-billing one, so the numbering and the
 * other sections — including the ones that promise blocking stays free — do
 * not move. The source strings are left as they are.
 */
export function replaceSection<T extends SectionLike>(sections: readonly T[], id: string, replacement: T): T[] {
  return sections.map((section) => (section.id === id ? replacement : section));
}
