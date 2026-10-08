/**
 * The world's device plan as the /pricing page shows it (Stripe variant).
 *
 * The numbers come from GET /api/v1/pricing/for-country (api/services/pricing.py):
 * one plan — unlimited detailed checks on 3 devices of one account — at a
 * regional (PPP) price, plus a price per extra device. The strings never carry
 * a price: every amount is an ICU argument built here, so a price change is an
 * API change and nothing else (scripts/check-landing-claims.py holds the
 * `landing.pricing` strings to that).
 *
 * The API and the site deploy separately. Until the API serves the device plan
 * — or when it is down — `normalizePricing` returns null and the page renders
 * DEFAULT_PRICING: the base tier, which is also what checkout charges for a
 * request without a country.
 *
 * No imports: scripts/test-landing-honesty.mjs loads this file straight into
 * Node, where the "@/" alias does not exist.
 */

export type Interval = "monthly" | "yearly";
export type Tier = 1 | 2 | 3 | 4;

export interface Price {
  /** USD for the interval: the monthly price, or the yearly total. */
  readonly amount: number;
  /** Per-month rate for comparison (yearly ÷ 12). */
  readonly monthlyEquivalent: number;
}

export interface WorldPricing {
  /** The country the prices were computed for (echoed back to checkout), or null for the base tier. */
  readonly country: string | null;
  readonly tier: Tier;
  readonly includedDevices: number;
  readonly price: Readonly<Record<Interval, Price>>;
  /** One device beyond the included ones, on the same interval as the plan. */
  readonly extraDevice: Readonly<Record<Interval, Price>>;
  /** Free trial on an account's first web subscription. */
  readonly trialDays: number;
  readonly freeChecksPerDay: number;
  readonly freeUnlimitedDays: number;
}

/** Base tier (2) — mirrors api/services/pricing.py TIER_PRICES[2] and the free-tier constants. */
export const DEFAULT_PRICING: WorldPricing = {
  country: null,
  tier: 2,
  includedDevices: 3,
  price: {
    monthly: { amount: 0.99, monthlyEquivalent: 0.99 },
    yearly: { amount: 9.99, monthlyEquivalent: 0.83 },
  },
  extraDevice: {
    monthly: { amount: 0.49, monthlyEquivalent: 0.49 },
    yearly: { amount: 4.99, monthlyEquivalent: 0.42 },
  },
  trialDays: 14,
  freeChecksPerDay: 3,
  freeUnlimitedDays: 7,
};

type Json = Record<string, unknown>;

function isObject(value: unknown): value is Json {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function positive(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : null;
}

function wholeNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : null;
}

function readPrice(node: unknown): Price | null {
  if (!isObject(node)) return null;
  const amount = positive(node.amount);
  const monthlyEquivalent = positive(node.monthly_equivalent);
  return amount !== null && monthlyEquivalent !== null ? { amount, monthlyEquivalent } : null;
}

function readIntervals(node: unknown): Record<Interval, Price> | null {
  if (!isObject(node)) return null;
  const monthly = readPrice(node.monthly);
  const yearly = readPrice(node.yearly);
  return monthly && yearly ? { monthly, yearly } : null;
}

/**
 * The /pricing/for-country response as the page needs it, or null when it is
 * not the device plan (an API from before it, a partial body, garbage).
 * Checked at runtime: the generated types say what the API SHOULD send, not
 * what the API deployed right now sends.
 */
export function normalizePricing(data: unknown): WorldPricing | null {
  if (!isObject(data) || !isObject(data.plan) || !isObject(data.free)) return null;
  const plan = data.plan;
  const free = data.free;
  const price = readIntervals(plan.price);
  const extraDevice = readIntervals(plan.extra_device);
  const includedDevices = wholeNumber(plan.included_devices);
  const trialDays = wholeNumber(plan.trial_days);
  const freeChecksPerDay = wholeNumber(free.detailed_checks_per_day);
  const freeUnlimitedDays = wholeNumber(free.unlimited_days_after_install);
  const tier = data.tier;
  if (
    !price || !extraDevice || !includedDevices || trialDays === null
    || freeChecksPerDay === null || freeUnlimitedDays === null
    || (tier !== 1 && tier !== 2 && tier !== 3 && tier !== 4)
  ) {
    return null;
  }
  const country = typeof data.country === "string" && /^[A-Z]{2}$/.test(data.country) ? data.country : null;
  return { country, tier, includedDevices, price, extraDevice, trialDays, freeChecksPerDay, freeUnlimitedDays };
}

/**
 * Whole months a year of the yearly price saves over twelve monthly payments
 * — the "≈ 2 months free" on the yearly toggle. 0 when yearly is not cheaper,
 * and then the page says nothing about saving.
 */
export function monthsFree(pricing: WorldPricing): number {
  const { monthly, yearly } = pricing.price;
  const saved = 12 * monthly.amount - yearly.amount;
  return saved > 0 ? Math.round(saved / monthly.amount) : 0;
}

/**
 * "$0.99". Always US formatting: the charge is in US dollars, and a locale's
 * digits or separators must not make the page show a different-looking number
 * than the Stripe receipt.
 */
export function usd(amount: number): string {
  return `$${amount.toFixed(2)}`;
}

/** A visitor's interval preference from `?interval=` (after sign-up); yearly by default on the web. */
export function intervalFrom(raw: string | null | undefined): Interval {
  return raw === "monthly" ? "monthly" : "yearly";
}

/** The checkout key the API takes (api/services/pricing.py parse_plan_key). */
export function checkoutPlanKey(interval: Interval): string {
  return `devices_${interval}`;
}
