/**
 * The free plan's rules (docs/ACCOUNTS_BILLING_PLAN.md §5), pure — no React
 * Native — so mobile/scripts/test-freemium.mjs runs them under plain node.
 *
 *   • Blocking by the scam list is never limited: the DNS shield, and a
 *     "dangerous — on our list" verdict, show paid or not. Nothing here is
 *     consulted by the shield, and the screens show the list's verdict
 *     before they ask anything of this file.
 *   • A free phone gets the server's number of manual checks a calendar
 *     month (FreeTerms, from GET /api/v1/pricing/for-country `free`; 5 since
 *     the founder's decision of 2026-11-04) — a site's full check (typed,
 *     pasted, shared, or opened from History / the link guard; the same site
 *     again that month is free) or, on Android, a message's analysis —
 *     counted on the phone and reset on the 1st, local time. The server's
 *     first `trialDays` after install have everything unlocked. With no
 *     answer from the server yet, nothing is limited.
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
  distribution: Distribution;
}

export const DEFAULT_DISTRIBUTION: Distribution = "site";

const DAY_MS = 24 * 60 * 60 * 1000;

/** Re-ask the server about the plan at most this often (a forced refresh skips it). */
export const ENTITLEMENT_FRESH_MS = 6 * 60 * 60 * 1000;
/** A paid answer still counts this long when the server cannot be reached. */
export const ENTITLEMENT_GRACE_MS = 7 * DAY_MS;
/** Re-ask the server for the free plan's numbers this often (the stored ones are used meanwhile). */
export const TERMS_FRESH_MS = 6 * 60 * 60 * 1000;

/** A month's consumed checks remember at most this many sites (a re-open of the same site is not a new check). */
const MAX_KEYS = 200;

/** The env var names the config is read from (Expo inlines EXPO_PUBLIC_* at build time). */
export interface FreemiumEnv {
  EXPO_PUBLIC_FREEMIUM_ENABLED?: string;
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

/**
 * Off unless the flag says "1" or "true". The numbers (how many checks, how
 * many days unlocked) are not build settings: they come from the server (parseFreeTerms).
 * [paidPlans] false (store-billing.ts paidPlansOffered: an iPhone build with no
 * App Store billing) turns the limit off too: a limit whose only way out is a
 * paywall the build cannot show would be a dead end.
 */
export function readFreemiumConfig(env: FreemiumEnv, os: string = "android", paidPlans: boolean = true): FreemiumConfig {
  const flag = (env.EXPO_PUBLIC_FREEMIUM_ENABLED ?? "").trim().toLowerCase();
  return {
    enabled: paidPlans && (flag === "1" || flag === "true"),
    distribution: distributionFor(env.EXPO_PUBLIC_DISTRIBUTION, os),
  };
}

// ── The server's terms ────────────────────────────────────────────────

/** The free plan's numbers, as the server publishes them. */
export interface FreeTerms {
  /** Manual checks a calendar month. */
  limit: number;
  /** Days after install with everything unlocked. */
  trialDays: number;
}

function wholeIn(v: unknown, min: number, max: number): number | null {
  return typeof v === "number" && Number.isInteger(v) && v >= min && v <= max ? v : null;
}

/**
 * The `free` block of GET /api/v1/pricing/for-country (api/routers/pricing.py
 * FreeTier), or null for anything else — an older API (per-day numbers), a
 * period this build does not know, a partial or garbled body. Null leaves the
 * stored terms alone.
 */
export function parseFreeTerms(pricing: unknown): FreeTerms | null {
  if (!pricing || typeof pricing !== "object") return null;
  const free = (pricing as { free?: unknown }).free;
  if (!free || typeof free !== "object") return null;
  const f = free as Record<string, unknown>;
  if (f.manual_checks_period !== "month") return null;
  const limit = wholeIn(f.manual_checks, 0, 1000);
  const trialDays = wholeIn(f.unlimited_days_after_install, 0, 365);
  return limit === null || trialDays === null ? null : { limit, trialDays };
}

/** The last terms the server sent, kept on the phone. */
export interface TermsCache {
  terms: FreeTerms;
  fetchedAt: number;
}

export function parseTermsCache(raw: unknown): TermsCache | null {
  if (!raw || typeof raw !== "object") return null;
  const c = raw as { terms?: unknown; fetchedAt?: unknown };
  if (typeof c.fetchedAt !== "number" || !Number.isFinite(c.fetchedAt) || !c.terms || typeof c.terms !== "object") return null;
  const t = c.terms as Record<string, unknown>;
  const limit = wholeIn(t.limit, 0, 1000);
  const trialDays = wholeIn(t.trialDays, 0, 365);
  return limit === null || trialDays === null ? null : { terms: { limit, trialDays }, fetchedAt: c.fetchedAt };
}

/** Recent enough not to ask again? A stamp from the future (clock moved back) is stale. */
export function termsFresh(cache: TermsCache | null, nowMs: number): boolean {
  if (!cache) return false;
  const age = nowMs - cache.fetchedAt;
  return age >= 0 && age < TERMS_FRESH_MS;
}

// ── The monthly counter ───────────────────────────────────────────────

/** The phone's local calendar day, "YYYY-MM-DD" — the paywall opens by itself at most once a day. */
export function localDayKey(nowMs: number): string {
  const d = new Date(nowMs);
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${d.getFullYear()}-${mm}-${dd}`;
}

/** The phone's local calendar month, "YYYY-MM" — the counter resets when it changes. */
export function localMonthKey(nowMs: number): string {
  const d = new Date(nowMs);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`;
}

export interface QuotaState {
  /** localMonthKey() of the month these counts belong to. */
  period: string;
  /** Manual checks used that month. */
  used: number;
  /** Sites already counted that month: re-opening one ("Full details", a re-check) is not a new check. */
  keys: string[];
  /** localDayKey() of the day the paywall last opened by itself, or null. */
  paywallDay: string | null;
}

export function emptyQuota(period: string): QuotaState {
  return { period, used: 0, keys: [], paywallDay: null };
}

/** The counter for [period]: a stored one from another month (or an unreadable one, or the old daily one) starts over. */
export function quotaForPeriod(stored: unknown, period: string): QuotaState {
  if (!stored || typeof stored !== "object") return emptyQuota(period);
  const s = stored as Partial<QuotaState>;
  if (s.period !== period) return emptyQuota(period);
  const used = typeof s.used === "number" && Number.isFinite(s.used) && s.used > 0 ? Math.floor(s.used) : 0;
  const keys = Array.isArray(s.keys) ? s.keys.filter((k): k is string => typeof k === "string").slice(-MAX_KEYS) : [];
  return { period, used, keys, paywallDay: typeof s.paywallDay === "string" ? s.paywallDay : null };
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
  | { kind: "unlimited"; why: "off" | "paid" | "trial" | "no_terms" }
  | { kind: "free"; limit: number; remaining: number };

export function accessFor(input: {
  config: FreemiumConfig;
  /** The server's numbers; null when it has never answered. */
  terms: FreeTerms | null;
  paid: boolean;
  installedAt: number;
  quota: QuotaState;
  nowMs: number;
}): Access {
  const { config, terms, paid, installedAt, quota, nowMs } = input;
  if (!config.enabled) return { kind: "unlimited", why: "off" };
  if (paid) return { kind: "unlimited", why: "paid" };
  // No number from the server yet: limiting by a guess could hide an analysis.
  if (!terms) return { kind: "unlimited", why: "no_terms" };
  if (inTrial(installedAt, nowMs, terms.trialDays)) return { kind: "unlimited", why: "trial" };
  return { kind: "free", limit: terms.limit, remaining: Math.max(0, terms.limit - quota.used) };
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
 * One manual check is asked for. [key] names the site so that opening the
 * same site again the same month ("Full details", a re-check) is free; null
 * (a message — its text is never stored, not even hashed) always counts.
 * [today] is localDayKey(): the paywall opens by itself at most once a day.
 */
export function gateCheck(access: Access, quota: QuotaState, key: string | null, today: string): CheckGate {
  if (access.kind === "unlimited") return { detailed: true, quota, autoPaywall: false };
  if (key !== null && quota.keys.includes(key)) return { detailed: true, quota, autoPaywall: false };
  if (access.remaining > 0) {
    const keys = key === null ? quota.keys : [...quota.keys, key].slice(-MAX_KEYS);
    return { detailed: true, quota: { ...quota, used: quota.used + 1, keys }, autoPaywall: false };
  }
  return { detailed: false, quota, autoPaywall: quota.paywallDay !== today };
}

/**
 * The paywall opened by itself [today]. The screen decides whether it opens at
 * all (never over a "dangerous" verdict), so it is marked only when it did.
 */
export function withPaywallShown(quota: QuotaState, today: string): QuotaState {
  return quota.paywallDay === today ? quota : { ...quota, paywallDay: today };
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

/**
 * Show "Upgrade", the Plan row and "Add a device"? Not where the paywall can
 * only say "coming soon":
 *   • the "ru" market in the site APK and RuStore (purchaseAction "soon") —
 *     Stripe cannot take Russian cards, phone-balance billing is not merged;
 *     the old upgrade screen led there to a page in dollars no one could pay,
 *     report #15. A Google Play / App Store build is not hidden by region: the
 *     store decides what it can sell (Russia stays in the stores' country
 *     lists, but a payment there mostly does not go through);
 *   • a build that cannot take a payment at all (paywallSaleOff) — RuStore,
 *     or a store build whose billing SDK is not there. Its paywall only says
 *     "coming soon"; an Upgrade row there was a sign-in detour to that note.
 * The upgrade code stays; only its entry points are hidden.
 *
 * Decided by marketFor, the paywall's own signal (region, else language), so
 * the two never disagree. It used to read the app's language alone; once the
 * app started in the first language it has (utils/device-locale.ts), a phone
 * set to Ukrainian, Kazakh or Belarusian with Russian second lost every entry
 * point in a country where it can pay, while the paywall still priced it in
 * dollars. [storeBillingOn] is services/store-billing.ts storeBillingOn().
 */
export function paidPlansVisible(input: {
  language: string;
  region: string | null | undefined;
  distribution: Distribution;
  storeBillingOn: boolean;
}): boolean {
  const { language, region, distribution, storeBillingOn } = input;
  const action = purchaseAction({ signedIn: true, market: marketFor(language, region), distribution });
  return action !== "soon" && !paywallSaleOff({ action, distribution, storeBillingOn });
}

/**
 * Russia's price (phone balance, not merged — the paywall says "coming soon")
 * and the devices the plan covers. No world price lives in the app: a store
 * build shows the store's own price (StorePlans.tsx, from RevenueCat), the
 * site APK the server's (webPlanPrice), so a price change is a console or
 * server change, never a new build.
 */
export const PRICES = {
  ru: { month: "99 ₽", devices: 3 },
  world: { devices: 3 },
} as const;

/**
 * The site APK's button: the site's monthly plan (founder 2026-11-04: one
 * price a month everywhere). At that price the card fee's fixed part is no
 * longer a third of it, so the site sells the month too (plan §5).
 */
export const WEB_CHECKOUT_URL = "https://cleanway.ai/pricing?plan=personal&interval=monthly";

/** The parts of GET /api/v1/pricing/for-country this file reads (PricingFor). */
export interface WebPricingLike {
  plan?: { price?: { monthly?: { amount?: unknown } | null; yearly?: { amount?: unknown } | null } | null } | null;
}

function usdOrNull(amount: unknown): string | null {
  if (typeof amount !== "number" || !Number.isFinite(amount) || amount <= 0) return null;
  return "$" + amount.toFixed(2);
}

/**
 * The web checkout's price, from the server (the same numbers the site and
 * Stripe charge). Null when the answer has no usable monthly price — the
 * paywall then shows none rather than a guess.
 */
export function webPlanPrice(pricing: WebPricingLike | null | undefined): { month: string; year: string | null } | null {
  const month = usdOrNull(pricing?.plan?.price?.monthly?.amount);
  if (!month) return null;
  return { month, year: usdOrNull(pricing?.plan?.price?.yearly?.amount) };
}

/** Link out to the web checkout? Only in the APK from our own site — never in a store build. */
export function webCheckoutAllowed(distribution: Distribution): boolean {
  return distribution === "site";
}

/**
 * List "automatic SMS check" among the plan's benefits? In no build today:
 * automatic checking lives only on the unmerged feat/sms-auto-rustore branch,
 * and every build ships without an SMS permission
 * (scripts/check-android-permissions.mjs). Return `distribution === "rustore"`
 * again in the change that merges that branch into the RuStore build.
 */
export function smsBenefitShown(_distribution: Distribution): boolean {
  return false;
}

export type PaywallBenefit = "unlimited" | "sms" | "text_model" | "devices";

/**
 * What the paywall lists as the plan's benefits — only what this build can
 * do and what paying adds (App Review 2.3.1 / Play's deceptive-behaviour
 * rule). The call guard is not listed: it warns every phone, paid or not.
 * The iPhone app has no on-device message analyzer and no SMS reading (both
 * Android), so it lists the unlimited checks and the devices only.
 */
export function paywallBenefits(distribution: Distribution): PaywallBenefit[] {
  if (distribution === "appstore") return ["unlimited", "devices"];
  return smsBenefitShown(distribution)
    ? ["unlimited", "sms", "text_model", "devices"]
    : ["unlimited", "text_model", "devices"];
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
 *   store        — the build's own store billing (startStorePurchase) — only
 *                  when paywallSaleOff says the build can take it;
 *   soon         — no way to pay here yet (Russia in the site APK and RuStore:
 *                  phone-balance billing is not merged; store builds leave the
 *                  country to the store).
 */
export type PurchaseAction = "sign_in" | "web_checkout" | "store" | "soon";

export function purchaseAction(input: { signedIn: boolean; market: Market; distribution: Distribution }): PurchaseAction {
  const { signedIn, market, distribution } = input;
  // In a Google Play or App Store build the store, not the phone's region,
  // decides whether the plan is sold (founder, 2026-11-04). Russia stays in
  // the stores' country lists (2026-11-11): a payment from a Russian
  // storefront mostly fails in the store's own sheet, no sales are expected.
  // A phone set to region RU abroad can pay; a storefront without the product
  // gets the paywall's "not available in your country" (prices_empty).
  if (market === "ru" && !revenueCatStore(distribution)) return "soon";
  if (!signedIn) return "sign_in";
  return webCheckoutAllowed(distribution) ? "web_checkout" : "store";
}

/**
 * The button would end at "paying in the app is coming soon" whatever the
 * person does: a build with no web checkout that cannot bill through a store
 * — RuStore (its billing is not built), or Google Play / the App Store made
 * without the RevenueCat key or SDK ([storeBillingOn] false). The paywall then
 * says so up front with the button off, instead of sending a signed-out
 * person to sign in first for a purchase that cannot happen. The "ru"
 * market's own "coming soon" (action "soon") is not this.
 */
export function paywallSaleOff(input: {
  action: PurchaseAction;
  distribution: Distribution;
  storeBillingOn: boolean;
}): boolean {
  const { action, distribution, storeBillingOn } = input;
  if (action !== "store" && action !== "sign_in") return false;
  if (webCheckoutAllowed(distribution)) return false;
  return !revenueCatStore(distribution) || !storeBillingOn;
}

export interface PriceShown {
  price: string;
  period: "month" | "year";
  alt: { price: string; period: "month" | "year" } | null;
}

/**
 * The price shown large, and the line under it — or null: a store build
 * (Google Play, the App Store) shows only the store's own quote (StorePlans),
 * RuStore sells nothing yet, and the site APK shows the server's price
 * ([web], GET /api/v1/pricing/for-country) once it has answered.
 */
export function priceDisplay(market: Market, distribution: Distribution, web?: WebPricingLike | null): PriceShown | null {
  if (market === "ru") return { price: PRICES.ru.month, period: "month", alt: null };
  if (!webCheckoutAllowed(distribution)) return null;
  const p = webPlanPrice(web);
  if (!p) return null;
  return { price: p.month, period: "month", alt: p.year ? { price: p.year, period: "year" } : null };
}
