/**
 * The operator-billed subscription (Russia) — what the site may say about it.
 *
 * Everything here is OFF until NEXT_PUBLIC_BILLING_ENABLED is set in the
 * Vercel project (and the site rebuilt: NEXT_PUBLIC_* is inlined at build
 * time). With the flag off, every page renders exactly as before: /pricing
 * keeps the free-only page for Russian visitors, /cancel does not exist, the
 * terms and the policy keep their current payment sections.
 *
 * The numbers are the founder's settings, not facts of the code. The windows
 * use the same env names as the API's `BillingSettings` (docs/BILLING.md) with
 * a NEXT_PUBLIC_ prefix. The device prices (NEXT_PUBLIC_BILLING_PRICE_RUB,
 * _INCLUDED_DEVICES, _EXTRA_DEVICE_RUB) are ahead of the API: its operator
 * catalogue (api/billing) still sells the one-, three- and five-phone plans
 * and must move to the device plan before the flag is switched on.
 * Hand-written prices are banned from the strings by
 * scripts/check-landing-claims.py; the components pass these values as ICU
 * arguments instead.
 */

// No imports: scripts/test-landing-honesty.mjs loads this file straight into
// Node, where the "@/" alias does not exist. The flag and the env-bound values
// live in lib/billing-config.ts.

/**
 * One subscription that counts devices (founder decision 2026-10-07,
 * docs/ACCOUNTS_BILLING_PLAN.md §5): a monthly price for the included
 * devices, and a price for every device beyond them. A device is a phone,
 * tablet or browser with the extension signed in to one account.
 */
export interface BillingTerms {
  /** Monthly price for the included devices, whole rubles. */
  readonly priceRub: number;
  /** Devices the subscription covers. */
  readonly includedDevices: number;
  /** Monthly price of each device beyond the included ones, whole rubles. */
  readonly extraDeviceRub: number;
  /** Days after install with everything unlimited and nothing charged. */
  readonly trialDays: number;
  /** Detailed checks a day without the subscription. */
  readonly freeChecksPerDay: number;
  readonly graceDays: number;
  /** What happens after the grace window: `basic` keeps list blocking, `off` stops it. */
  readonly lapsePolicy: LapsePolicy;
}

export type LapsePolicy = "basic" | "off";

/**
 * The founder's numbers (2026-10-07): 99 ₽ a month for 3 devices, +29 ₽ a
 * month for each one more, everything unlimited for the first 7 days. They
 * replace the 99 / 270 / 399 ₽ one-, three- and five-phone plans of
 * 2026-09-29.
 */
export const DEFAULT_PRICE_RUB = 99;
export const DEFAULT_INCLUDED_DEVICES = 3;
export const DEFAULT_EXTRA_DEVICE_RUB = 29;
export const DEFAULT_TRIAL_DAYS = 7;
export const DEFAULT_FREE_CHECKS_PER_DAY = 3;
export const DEFAULT_GRACE_DAYS = 7;
export const DEFAULT_LAPSE_POLICY: LapsePolicy = "basic";

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
  return {
    priceRub: parsePositiveInt(env.NEXT_PUBLIC_BILLING_PRICE_RUB, DEFAULT_PRICE_RUB),
    includedDevices: parsePositiveInt(env.NEXT_PUBLIC_BILLING_INCLUDED_DEVICES, DEFAULT_INCLUDED_DEVICES),
    extraDeviceRub: parsePositiveInt(env.NEXT_PUBLIC_BILLING_EXTRA_DEVICE_RUB, DEFAULT_EXTRA_DEVICE_RUB),
    trialDays: parsePositiveInt(env.NEXT_PUBLIC_BILLING_TRIAL_DAYS, DEFAULT_TRIAL_DAYS),
    freeChecksPerDay: parsePositiveInt(env.NEXT_PUBLIC_BILLING_FREE_CHECKS_PER_DAY, DEFAULT_FREE_CHECKS_PER_DAY),
    graceDays: parsePositiveInt(env.NEXT_PUBLIC_BILLING_GRACE_DAYS, DEFAULT_GRACE_DAYS),
    lapsePolicy: parseLapsePolicy(env.NEXT_PUBLIC_BILLING_LAPSE_POLICY),
  };
}

/** Rubles a month for `devices` devices: the plan, plus each device beyond the included ones. */
export function monthlyPriceFor(terms: BillingTerms, devices: number): number {
  return terms.priceRub + Math.max(0, devices - terms.includedDevices) * terms.extraDeviceRub;
}

/**
 * The ICU arguments every billing string may use: the price, the extra
 * device's price, the included devices and the windows. Prices go in as
 * strings so a locale's number formatting cannot change them (Intl renders
 * 99 as ٩٩ for Arabic); the counts stay numbers because the strings
 * pluralise on them.
 */
export function billingMessageArgs(terms: BillingTerms): Record<string, string | number> {
  return {
    price: String(terms.priceRub),
    extra: String(terms.extraDeviceRub),
    devices: terms.includedDevices,
    days: terms.trialDays,
    checks: terms.freeChecksPerDay,
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
