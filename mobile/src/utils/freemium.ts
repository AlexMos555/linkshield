/**
 * The free plan's rules (docs/ACCOUNTS_BILLING_PLAN.md §5), pure — no React
 * Native — so mobile/scripts/test-freemium.mjs runs them under plain node.
 *
 *   • Blocking by the scam list is never limited: the DNS shield, and a
 *     "dangerous — on our list" verdict, show paid or not. Nothing here is
 *     consulted by the shield, and the screens show the list's verdict
 *     before they ask anything of this file.
 *   • A free phone gets DAILY_LIMIT detailed checks a day (a typed or shared
 *     link, or a shared message), counted on the phone and reset at local
 *     midnight. The first TRIAL_DAYS after install are unlimited.
 *   • A paid account (GET /api/v1/me/entitlement) is unlimited. Not signed in
 *     is free. A paid answer is trusted offline for ENTITLEMENT_GRACE_MS.
 *
 * Everything is behind EXPO_PUBLIC_FREEMIUM_ENABLED (off by default): with it
 * off the app behaves exactly as before — every check is detailed.
 */

// ── Config ────────────────────────────────────────────────────────────

/**
 * Where this build is installed from. Store builds must never link out to a web checkout.
 * "appstore" is the iPhone app — the only way an iOS build ships (TestFlight included).
 */
export type Distribution = "site" | "play" | "rustore" | "appstore";

export interface FreemiumConfig {
  enabled: boolean;
  /** Detailed checks a free phone gets per local day. */
  dailyLimit: number;
  /** Unlimited days after the first launch with the limit on. */
  trialDays: number;
  distribution: Distribution;
}

export const DEFAULT_DAILY_LIMIT = 3;
export const DEFAULT_TRIAL_DAYS = 7;
export const DEFAULT_DISTRIBUTION: Distribution = "site";

const DAY_MS = 24 * 60 * 60 * 1000;

/** Re-ask the server about the plan at most this often (a forced refresh skips it). */
export const ENTITLEMENT_FRESH_MS = 6 * 60 * 60 * 1000;
/** A paid answer still counts this long when the server cannot be reached. */
export const ENTITLEMENT_GRACE_MS = 7 * DAY_MS;

/** A day's consumed checks remember at most this many sites (a re-open of the same site is not a new check). */
const MAX_KEYS = 50;

function intOr(value: string | undefined, fallback: number, min: number, max: number): number {
  if (value === undefined || value.trim() === "") return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) return fallback;
  return n;
}

/** The env var names the config is read from (Expo inlines EXPO_PUBLIC_* at build time). */
export interface FreemiumEnv {
  EXPO_PUBLIC_FREEMIUM_ENABLED?: string;
  EXPO_PUBLIC_FREE_CHECKS_PER_DAY?: string;
  EXPO_PUBLIC_FREE_TRIAL_DAYS?: string;
  EXPO_PUBLIC_DISTRIBUTION?: string;
}

/**
 * The build's distribution. An iOS build is always "appstore", whatever the
 * env says: Apple distributes every iPhone build (App Store, TestFlight), and
 * an iOS build that fell back to "site" would link to the web checkout —
 * App Review 3.1.1 rejects that. On Android "appstore" means nothing and an
 * unknown value is the site APK, as before.
 */
export function distributionFor(raw: string | undefined, os: string): Distribution {
  if (os === "ios") return "appstore";
  const dist = (raw ?? "").trim().toLowerCase();
  return dist === "play" || dist === "rustore" || dist === "site" ? dist : DEFAULT_DISTRIBUTION;
}

/** Off unless the flag says "1" or "true"; a bad number falls back to the default, never to "unlimited". */
export function readFreemiumConfig(env: FreemiumEnv, os: string = "android"): FreemiumConfig {
  const flag = (env.EXPO_PUBLIC_FREEMIUM_ENABLED ?? "").trim().toLowerCase();
  return {
    enabled: flag === "1" || flag === "true",
    dailyLimit: intOr(env.EXPO_PUBLIC_FREE_CHECKS_PER_DAY, DEFAULT_DAILY_LIMIT, 0, 1000),
    trialDays: intOr(env.EXPO_PUBLIC_FREE_TRIAL_DAYS, DEFAULT_TRIAL_DAYS, 0, 365),
    distribution: distributionFor(env.EXPO_PUBLIC_DISTRIBUTION, os),
  };
}

// ── The daily counter ─────────────────────────────────────────────────

/** The phone's local calendar day, "YYYY-MM-DD" — the counter resets when it changes. */
export function localDayKey(nowMs: number): string {
  const d = new Date(nowMs);
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${d.getFullYear()}-${mm}-${dd}`;
}

export interface QuotaState {
  /** localDayKey() of the day these counts belong to. */
  day: string;
  /** Detailed checks used that day. */
  used: number;
  /** Sites already counted that day: re-opening one ("Full details", a re-check) is not a new check. */
  keys: string[];
  /** The paywall opened by itself that day already — afterwards only the in-place card offers it. */
  paywallShown: boolean;
}

export function emptyQuota(day: string): QuotaState {
  return { day, used: 0, keys: [], paywallShown: false };
}

/** The counter for [day]: a stored one from another day (or an unreadable one) starts over. */
export function quotaForDay(stored: unknown, day: string): QuotaState {
  if (!stored || typeof stored !== "object") return emptyQuota(day);
  const s = stored as Partial<QuotaState>;
  if (s.day !== day) return emptyQuota(day);
  const used = typeof s.used === "number" && Number.isFinite(s.used) && s.used > 0 ? Math.floor(s.used) : 0;
  const keys = Array.isArray(s.keys) ? s.keys.filter((k): k is string => typeof k === "string").slice(-MAX_KEYS) : [];
  return { day, used, keys, paywallShown: s.paywallShown === true };
}

/** First launch with the limit on, read back from storage; a missing or broken value is "now". */
export function installedAtOr(stored: unknown, nowMs: number): number {
  const n = typeof stored === "string" ? Number(stored) : stored;
  return typeof n === "number" && Number.isFinite(n) && n > 0 ? n : nowMs;
}

/**
 * Inside the unlimited first days? A clock set before the install date is
 * not "in the trial" — moving the clock back must not buy more free days.
 */
export function inTrial(installedAtMs: number, nowMs: number, trialDays: number): boolean {
  if (trialDays <= 0) return false;
  const age = nowMs - installedAtMs;
  return age >= 0 && age < trialDays * DAY_MS;
}

/** Whole days of the trial left, rounded up (1 on its last day), 0 outside it. */
export function trialDaysLeft(installedAtMs: number, nowMs: number, trialDays: number): number {
  if (!inTrial(installedAtMs, nowMs, trialDays)) return 0;
  return Math.ceil((installedAtMs + trialDays * DAY_MS - nowMs) / DAY_MS);
}

// ── Paid status ───────────────────────────────────────────────────────

/** The parts of GET /api/v1/me/entitlement this file reads. */
export interface EntitlementLike {
  plan: string;
  status: string;
}

/** The server sends a paid plan only while it grants access (active / trialing / past_due). */
export function isPaidEntitlement(ent: EntitlementLike | null | undefined): boolean {
  if (!ent) return false;
  return ent.plan !== "free" && ent.status !== "free";
}

/** The last answer about the plan, kept on the phone. */
export interface EntitlementCache {
  /** Whose answer it is — another account signing in on this phone does not inherit it. */
  account: string;
  paid: boolean;
  fetchedAt: number;
}

/** Still worth using without asking again? */
export function entitlementFresh(cache: EntitlementCache | null, account: string, nowMs: number): boolean {
  if (!cache || cache.account !== account) return false;
  const age = nowMs - cache.fetchedAt;
  return age >= 0 && age < ENTITLEMENT_FRESH_MS;
}

/**
 * Paid, from the cache, when the server cannot answer right now: a paid
 * answer counts for ENTITLEMENT_GRACE_MS, so a subscriber on a train is not
 * locked out; a free one is free.
 */
export function paidFromCache(cache: EntitlementCache | null, account: string, nowMs: number): boolean {
  if (!cache || cache.account !== account || !cache.paid) return false;
  const age = nowMs - cache.fetchedAt;
  return age >= 0 && age < ENTITLEMENT_GRACE_MS;
}

/** Narrowing for a cache read back from storage. */
export function parseEntitlementCache(raw: unknown): EntitlementCache | null {
  if (!raw || typeof raw !== "object") return null;
  const c = raw as Partial<EntitlementCache>;
  if (typeof c.account !== "string" || typeof c.paid !== "boolean" || typeof c.fetchedAt !== "number") return null;
  return { account: c.account, paid: c.paid, fetchedAt: c.fetchedAt };
}

// ── The decision ──────────────────────────────────────────────────────

export type Access =
  | { kind: "unlimited"; why: "off" | "paid" | "trial" }
  | { kind: "free"; limit: number; remaining: number };

export function accessFor(input: {
  config: FreemiumConfig;
  paid: boolean;
  installedAt: number;
  quota: QuotaState;
  nowMs: number;
}): Access {
  const { config, paid, installedAt, quota, nowMs } = input;
  if (!config.enabled) return { kind: "unlimited", why: "off" };
  if (paid) return { kind: "unlimited", why: "paid" };
  if (inTrial(installedAt, nowMs, config.trialDays)) return { kind: "unlimited", why: "trial" };
  return { kind: "free", limit: config.dailyLimit, remaining: Math.max(0, config.dailyLimit - quota.used) };
}

export interface CheckGate {
  /** Show the detailed analysis (server site check, text model reasons, scheme explanation)? */
  detailed: boolean;
  /** The counter after this check, to store. */
  quota: QuotaState;
  /** The limit stopped this check and the paywall has not opened by itself today. */
  autoPaywall: boolean;
}

/**
 * One detailed check is asked for. [key] names the site so that opening the
 * same site again the same day ("Full details", a re-check) is free; null
 * (a message — its text is never stored, not even hashed) always counts.
 */
export function gateCheck(access: Access, quota: QuotaState, key: string | null): CheckGate {
  if (access.kind === "unlimited") return { detailed: true, quota, autoPaywall: false };
  if (key !== null && quota.keys.includes(key)) return { detailed: true, quota, autoPaywall: false };
  if (access.remaining > 0) {
    const keys = key === null ? quota.keys : [...quota.keys, key].slice(-MAX_KEYS);
    return { detailed: true, quota: { ...quota, used: quota.used + 1, keys }, autoPaywall: false };
  }
  return { detailed: false, quota, autoPaywall: !quota.paywallShown };
}

/**
 * The paywall opened by itself today. The screen decides whether it opens at
 * all (never over a "dangerous" verdict), so it is marked only when it did.
 */
export function withPaywallShown(quota: QuotaState): QuotaState {
  return quota.paywallShown ? quota : { ...quota, paywallShown: true };
}

// ── The paywall ───────────────────────────────────────────────────────

export type Market = "ru" | "world";

/**
 * Russia pays by phone balance (99 ₽ for 3 devices); everyone else in
 * dollars. The phone's region decides; with no region, the language.
 */
export function marketFor(language: string, region: string | null | undefined): Market {
  const r = (region ?? "").trim().toUpperCase();
  if (r) return r === "RU" ? "ru" : "world";
  return (language || "").split("-")[0].toLowerCase() === "ru" ? "ru" : "world";
}

/** Prices shown on the paywall. Amounts are display strings; the store / checkout charges. */
export const PRICES = {
  ru: { month: "99 ₽", devices: 3 },
  world: { month: "$0.99", year: "$9.99", devices: 3 },
} as const;

/** The site sells the yearly plan only — a fixed card fee eats a third of $0.99 (§5). */
export const WEB_CHECKOUT_URL = "https://cleanway.ai/pricing?plan=personal&interval=yearly";

/** Link out to the web checkout? Only in the APK from our own site — never in a store build. */
export function webCheckoutAllowed(distribution: Distribution): boolean {
  return distribution === "site";
}

/**
 * List "automatic SMS check" among the plan's benefits? Only in the RuStore
 * build: the APKs from our site and from Google Play cannot read SMS (no SMS
 * permission — scripts/check-android-permissions.mjs), so they never promise it.
 */
export function smsBenefitShown(distribution: Distribution): boolean {
  return distribution === "rustore";
}

export type PaywallBenefit = "unlimited" | "sms" | "text_model" | "calls" | "devices";

/**
 * What the paywall lists as the plan's benefits — only what this build can
 * do (App Review 2.3.1 / Play's deceptive-behaviour rule). The iPhone app
 * has no on-device message analyzer, no SMS reading and no call guard (all
 * Android), so it lists the unlimited checks and the devices only.
 */
export function paywallBenefits(distribution: Distribution): PaywallBenefit[] {
  if (distribution === "appstore") return ["unlimited", "devices"];
  return smsBenefitShown(distribution)
    ? ["unlimited", "sms", "text_model", "calls", "devices"]
    : ["unlimited", "text_model", "calls", "devices"];
}

/**
 * Does this build sell the plan through its store's own billing, via
 * RevenueCat (src/services/store-billing.ts)? Google Play and the App Store.
 * RuStore billing is not built yet; the site APK sells on the web.
 */
export function revenueCatStore(distribution: Distribution): boolean {
  return distribution === "play" || distribution === "appstore";
}

/**
 * Offer "a newer version — download" from our own server? Only in the APK
 * from our site. A store build is updated by its store (Google Play forbids
 * an app updating itself any other way).
 */
export function selfUpdateAllowed(distribution: Distribution): boolean {
  return distribution === "site";
}

/**
 * What the paywall's one button does:
 *   sign_in      — paying needs an account: sign in first, then come back;
 *   web_checkout — the site's checkout (site APK, world prices);
 *   store        — Google Play / RuStore billing (startStorePurchase);
 *   soon         — no way to pay here yet (Russia: phone-balance billing is not merged).
 */
export type PurchaseAction = "sign_in" | "web_checkout" | "store" | "soon";

export function purchaseAction(input: { signedIn: boolean; market: Market; distribution: Distribution }): PurchaseAction {
  const { signedIn, market, distribution } = input;
  if (market === "ru") return "soon";
  if (!signedIn) return "sign_in";
  return webCheckoutAllowed(distribution) ? "web_checkout" : "store";
}

/**
 * The price shown large, and the line under it. The site APK sells the year
 * (that is what its button buys); a store build sells the month.
 */
export function priceDisplay(market: Market, distribution: Distribution): {
  price: string;
  period: "month" | "year";
  alt: { price: string; period: "month" | "year" } | null;
} {
  if (market === "ru") return { price: PRICES.ru.month, period: "month", alt: null };
  return webCheckoutAllowed(distribution)
    ? { price: PRICES.world.year, period: "year", alt: { price: PRICES.world.month, period: "month" } }
    : { price: PRICES.world.month, period: "month", alt: { price: PRICES.world.year, period: "year" } };
}
