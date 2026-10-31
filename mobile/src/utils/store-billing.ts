/**
 * Paying in the app through Google Play or the App Store (RevenueCat SDK),
 * pure — no React Native — so mobile/scripts/test-store-billing.mjs runs it
 * under plain node. The SDK calls themselves are in src/services/store-billing.ts.
 *
 *   • On Android only the Play build pays in the app (EXPO_PUBLIC_DISTRIBUTION=play)
 *     and only with a public Play key (goog_…). The iPhone app pays through
 *     the App Store with a public App Store key (appl_…). Anything else — the
 *     APK from our site, RuStore, a missing or wrong key — is "off" with a
 *     reason, never a crash.
 *   • The plan is the `cleanway.devices` subscription, monthly and yearly
 *     (App Store: cleanway.devices.monthly / cleanway.devices.yearly),
 *     from the RevenueCat offering `default`. Prices are the store's own
 *     strings (localised currency); nothing here invents a price.
 *   • Store errors become a few kinds the paywall can say in words.
 *   • RevenueCat knows the person by the Supabase account id, read from the
 *     session's access token (`sub`). Signed out, the iPhone app buys and
 *     restores under RevenueCat's anonymous id (payingAs; App Review 5.1.1)
 *     and the phone honours its own App Store plan (storePlanActive); Google
 *     Play asks to sign in first.
 *
 * Server side and store setup: docs/runbooks/revenuecat.md.
 */

// ── Config ────────────────────────────────────────────────────────────

export interface StoreBillingEnv {
  EXPO_PUBLIC_DISTRIBUTION?: string;
  EXPO_PUBLIC_REVENUECAT_ANDROID_KEY?: string;
  EXPO_PUBLIC_REVENUECAT_IOS_KEY?: string;
}

/** Which store takes the money — named the way the server names a plan's `source`. */
export type BillingStore = "google_play" | "app_store";

export type StoreBillingConfig =
  | { kind: "on"; apiKey: string; store: BillingStore }
  /**
   * not_play — an Android build that is not the Google Play one (site APK, RuStore);
   * no_key   — the Play build was made without EXPO_PUBLIC_REVENUECAT_ANDROID_KEY,
   *            or the iOS build without EXPO_PUBLIC_REVENUECAT_IOS_KEY;
   * bad_key  — the value is not this store's public key (a secret sk_ key, or
   *            the other store's key, must never ship in the app).
   */
  | { kind: "off"; why: "not_play" | "no_key" | "bad_key" };

const PUBLIC_PLAY_KEY = /^goog_[A-Za-z0-9]+$/;
const PUBLIC_APP_STORE_KEY = /^appl_[A-Za-z0-9]+$/;

/**
 * Pays in the app? On Android only the Google Play build
 * (EXPO_PUBLIC_DISTRIBUTION=play) with a public goog_ key. On iOS every build
 * is the App Store one (freemium.ts distributionFor — an EAS profile's
 * EXPO_PUBLIC_DISTRIBUTION=play must not switch the iPhone app off), and it
 * pays with a public appl_ key.
 */
export function readStoreBillingConfig(env: StoreBillingEnv, os: string): StoreBillingConfig {
  if (os === "ios") {
    const key = (env.EXPO_PUBLIC_REVENUECAT_IOS_KEY ?? "").trim();
    if (!key) return { kind: "off", why: "no_key" };
    if (!PUBLIC_APP_STORE_KEY.test(key)) return { kind: "off", why: "bad_key" };
    return { kind: "on", apiKey: key, store: "app_store" };
  }
  const dist = (env.EXPO_PUBLIC_DISTRIBUTION ?? "").trim().toLowerCase();
  if (dist !== "play" || os !== "android") return { kind: "off", why: "not_play" };
  const key = (env.EXPO_PUBLIC_REVENUECAT_ANDROID_KEY ?? "").trim();
  if (!key) return { kind: "off", why: "no_key" };
  if (!PUBLIC_PLAY_KEY.test(key)) return { kind: "off", why: "bad_key" };
  return { kind: "on", apiKey: key, store: "google_play" };
}

/**
 * Show paid plans at all: the Plan / Upgrade rows, the paywall and its
 * prices, and the free daily limit that leads to it? Yes everywhere except
 * an iPhone build that cannot sell through the App Store (made without its
 * public appl_ key, or with a wrong one). That build goes to App Review as
 * having no in-app purchases, so it must not show a plan, a price or a
 * "coming soon" paywall (guidelines 2.1 / 2.2) — and with nothing to buy it
 * sets no limit either (freemium.ts readFreemiumConfig). Android keeps its
 * paywalls: a Play build without its key, and RuStore, say "coming soon"
 * there (freemium.ts paywallSaleOff) — but show no Upgrade / Plan row
 * leading to it (freemium.ts paidPlansVisible); the site APK sells on the web.
 */
export function paidPlansOffered(billing: StoreBillingConfig, os: string): boolean {
  return os !== "ios" || billing.kind === "on";
}

/**
 * Start the SDK when the app starts? Only for a signed-in person on this
 * phone who has started a store purchase before: the SDK must then run to
 * finish a pending ("slow card") purchase and acknowledge it, or Google
 * refunds it after 3 days. In the iPhone app ([withoutAccount], freemium.ts
 * storePurchaseWithoutAccount) signed out too: a phone that bought or
 * restored without an account has nobody else to tell it about an Ask to
 * Buy approval, a renewal or an end. Everyone else meets RevenueCat only
 * when they open the paywall or tap "Restore purchases" — no request on
 * every start.
 */
export function configureAtStart(input: {
  billing: StoreBillingConfig;
  signedIn: boolean;
  purchaseStarted: boolean;
  withoutAccount?: boolean;
}): boolean {
  return (
    input.billing.kind === "on" && input.purchaseStarted && (input.signedIn || input.withoutAccount === true)
  );
}

// ── Who is paying ─────────────────────────────────────────────────────

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** base64url → a byte string (one char per byte). Null on a character outside the alphabet. */
function base64UrlToBinary(input: string): string | null {
  const s = input.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const ch of s) {
    const v = B64.indexOf(ch);
    if (v < 0) return null;
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out += String.fromCharCode((buffer >> bits) & 0xff);
    }
  }
  return out;
}

/**
 * The Supabase account id (`sub`) inside the session's access token — what
 * RevenueCat knows the person by (Purchases.logIn), so a store purchase lands
 * on this account. Not verified here: the server verifies the token on every
 * call, and a wrong id could only misfile the person's own purchase. Null
 * for anything that is not a JWT with a UUID `sub`.
 */
export function accountIdFromAccessToken(token: string | null | undefined): string | null {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 3 || !parts[1]) return null;
  const json = base64UrlToBinary(parts[1]);
  if (json === null) return null;
  try {
    const claims = JSON.parse(json) as { sub?: unknown };
    return typeof claims.sub === "string" && UUID.test(claims.sub) ? claims.sub : null;
  } catch {
    return null;
  }
}

/**
 * Who a purchase or a restore goes under:
 *   account       — signed in: the account id, so the webhook files it there;
 *   anonymous     — signed out in the iPhone app ([withoutAccount]):
 *                   RevenueCat's anonymous id. Signing in later
 *                   (Purchases.logIn) makes it an alias of the account;
 *   sign_in_first — signed out on Google Play: a plan belongs to an account.
 */
export type PayingAs = { kind: "account"; id: string } | { kind: "anonymous" } | { kind: "sign_in_first" };

export function payingAs(accountId: string | null, withoutAccount: boolean): PayingAs {
  if (accountId) return { kind: "account", id: accountId };
  return withoutAccount ? { kind: "anonymous" } : { kind: "sign_in_first" };
}

// ── What is on sale ───────────────────────────────────────────────────

/** RevenueCat offering the paywall sells from (runbook §3). */
export const OFFERING_ID = "default";
/** The plan's subscription; Play reports it as `cleanway.devices:<base plan>`. */
export const PLAN_PRODUCT_ID = "cleanway.devices";

export type PlanPeriod = "month" | "year";

/** The parts of the SDK's PurchasesStoreProduct this file reads. */
export interface StoreProductLike {
  identifier: string;
  priceString: string;
  price: number;
  currencyCode: string;
}

/** The parts of the SDK's PurchasesPackage this file reads. */
export interface StorePackageLike {
  identifier: string;
  packageType: string;
  product: StoreProductLike;
}

export interface OfferingLike<P extends StorePackageLike> {
  identifier: string;
  availablePackages: P[];
  monthly?: P | null;
  annual?: P | null;
}

export interface OfferingsLike<P extends StorePackageLike> {
  current: OfferingLike<P> | null;
  all: Record<string, OfferingLike<P>>;
}

export interface PlanOption<P extends StorePackageLike> {
  period: PlanPeriod;
  pkg: P;
  /** The store's own price, in the person's currency ("$0.99", "89,00 ₽", "₹ 79"). */
  priceString: string;
  /** Yearly only: whole percent saved against twelve months, when it is worth saying (≥ 5). */
  savePercent: number | null;
}

const PACKAGE_TYPE: Record<PlanPeriod, string> = { month: "MONTHLY", year: "ANNUAL" };
const BASE_PLAN_NAMES: Record<PlanPeriod, readonly string[]> = {
  month: ["monthly"],
  year: ["yearly", "annual"],
};

/**
 * The plan, not the "+1 device" add-on (cleanway.extra_device) — a package
 * misattached in the RevenueCat dashboard must never be sold as the plan.
 * Play: "cleanway.devices:monthly"; App Store (later): "cleanway.devices.monthly".
 */
function isPlanProduct(id: string): boolean {
  return id === PLAN_PRODUCT_ID || id.startsWith(`${PLAN_PRODUCT_ID}:`) || id.startsWith(`${PLAN_PRODUCT_ID}.`);
}

function basePlanOf(id: string): string {
  const rest = id.slice(PLAN_PRODUCT_ID.length + 1);
  return rest.toLowerCase();
}

function sellable<P extends StorePackageLike>(p: P | null | undefined): p is P {
  return Boolean(
    p &&
      p.product &&
      typeof p.product.identifier === "string" &&
      isPlanProduct(p.product.identifier) &&
      typeof p.product.priceString === "string" &&
      p.product.priceString.trim() !== "",
  );
}

function pick<P extends StorePackageLike>(offering: OfferingLike<P>, period: PlanPeriod): P | null {
  const packages = Array.isArray(offering.availablePackages) ? offering.availablePackages : [];
  const candidates: Array<P | null | undefined> = [
    period === "month" ? offering.monthly : offering.annual,
    ...packages.filter((p) => p?.packageType === PACKAGE_TYPE[period]),
    ...packages.filter((p) => p?.product && BASE_PLAN_NAMES[period].includes(basePlanOf(p.product.identifier))),
  ];
  return candidates.find(sellable) ?? null;
}

function yearlySaving(month: StoreProductLike, year: StoreProductLike): number | null {
  if (month.currencyCode !== year.currencyCode) return null;
  if (!(month.price > 0) || !(year.price > 0)) return null;
  const pct = Math.floor((1 - year.price / (12 * month.price)) * 100);
  return pct >= 5 && pct < 100 ? pct : null;
}

/**
 * The plans to show: monthly first (what a store build sells, plan §5),
 * then yearly with its saving. The `default` offering; the "current" one
 * only when `default` is missing. Empty when the store has nothing to sell
 * (offering not set up, products inactive, or none available in the
 * person's country).
 */
export function planOptions<P extends StorePackageLike>(
  offerings: OfferingsLike<P> | null | undefined,
): PlanOption<P>[] {
  if (!offerings) return [];
  const offering = offerings.all?.[OFFERING_ID] ?? offerings.current ?? null;
  if (!offering) return [];
  const month = pick(offering, "month");
  const year = pick(offering, "year");
  const out: PlanOption<P>[] = [];
  if (month) out.push({ period: "month", pkg: month, priceString: month.product.priceString, savePercent: null });
  if (year) {
    out.push({
      period: "year",
      pkg: year,
      priceString: year.product.priceString,
      savePercent: month ? yearlySaving(month.product, year.product) : null,
    });
  }
  return out;
}

/** RevenueCat entitlement the plan's products unlock (runbook §3). */
export const PLAN_ENTITLEMENT_ID = "unlimited";

/**
 * Does Google Play (as RevenueCat sees it) say this person has the plan?
 * Only a hint while our server catches up — the plan the app honours is
 * always the server's (GET /api/v1/me/entitlement).
 */
export function storeHasPlan(
  info: { entitlements?: { active?: Record<string, { isActive?: boolean } | undefined> } } | null | undefined,
): boolean {
  return info?.entitlements?.active?.[PLAN_ENTITLEMENT_ID]?.isActive === true;
}

// ── This phone's own plan (the iPhone app) ────────────────────────────

/**
 * What RevenueCat last said about the plan of whoever the SDK is on this
 * phone. Kept only by the iPhone app, which sells without an account
 * (freemium.ts storePurchaseWithoutAccount): a signed-out buyer has no
 * server answer, so the phone counts its own App Store plan — and keeps
 * counting it signed in when the account's device seats are all taken.
 */
export interface StorePlanCache {
  paid: boolean;
  /** When the store says the plan ends (ms since epoch); null = no end date known. */
  expiresAt: number | null;
  /** When RevenueCat said so. */
  checkedAt: number;
}

/** Ask RevenueCat again at most this often — as freemium.ts ENTITLEMENT_FRESH_MS. */
export const STORE_PLAN_FRESH_MS = 6 * 60 * 60 * 1000;
/** A paid answer counts this long when RevenueCat cannot be asked — as freemium.ts ENTITLEMENT_GRACE_MS. */
export const STORE_PLAN_GRACE_MS = 7 * 24 * 60 * 60 * 1000;

/** The parts of the SDK's CustomerInfo read below. */
export interface CustomerInfoLike {
  /**
   * When RevenueCat's server produced this answer (ISO). An answer from the
   * SDK's cache keeps the date it was fetched (customer info is cached for
   * 5 minutes, and offline for as long as it is offline).
   */
  requestDate?: string | null;
  entitlements?: {
    active?: Record<
      string,
      { isActive?: boolean; expirationDate?: string | null; store?: string | null } | undefined
    >;
  };
}

/**
 * RevenueCat's `store` of an entitlement this phone counts as its own. A
 * signed-in iPhone's RevenueCat customer is the account's, with whatever
 * the account pays through: a Google Play plan there is the server's to
 * count (with the device seats), never "paid in the App Store on this phone".
 */
const APP_STORE_STORES: ReadonlySet<string> = new Set(["APP_STORE", "MAC_APP_STORE"]);

/**
 * This phone's plan from a CustomerInfo the SDK just gave (purchase,
 * restore, logIn, a read): the `unlimited` entitlement, from the App Store
 * only. An end date already past is not paid, whatever isActive says:
 * offline the SDK answers from its cache, and in a billing grace period
 * RevenueCat moves the end date to the end of the grace (nextStorePlan
 * decides whether such an answer may replace a paid one).
 */
export function storePlanFromInfo(info: CustomerInfoLike | null | undefined, nowMs: number): StorePlanCache {
  const unpaid = { paid: false, expiresAt: null, checkedAt: nowMs };
  const ent = info?.entitlements?.active?.[PLAN_ENTITLEMENT_ID];
  if (ent?.isActive !== true || !APP_STORE_STORES.has(String(ent.store ?? ""))) return unpaid;
  const ends = typeof ent.expirationDate === "string" ? Date.parse(ent.expirationDate) : NaN;
  if (!Number.isFinite(ends)) return { paid: true, expiresAt: null, checkedAt: nowMs };
  return ends > nowMs ? { paid: true, expiresAt: ends, checkedAt: nowMs } : unpaid;
}

/** Narrowing for a cache read back from storage. */
export function parseStorePlanCache(raw: unknown): StorePlanCache | null {
  if (!raw || typeof raw !== "object") return null;
  const c = raw as Partial<StorePlanCache>;
  if (typeof c.paid !== "boolean" || typeof c.checkedAt !== "number" || !Number.isFinite(c.checkedAt)) return null;
  if (c.expiresAt !== null && (typeof c.expiresAt !== "number" || !Number.isFinite(c.expiresAt))) return null;
  return { paid: c.paid, expiresAt: c.expiresAt, checkedAt: c.checkedAt };
}

/**
 * Does this phone's own plan count right now? Until the store's end date.
 * Past it (a renewal RevenueCat could not be asked about yet), or with no
 * end date, STORE_PLAN_GRACE_MS after the last paid answer — as a paid
 * account answer offline. Online, storePlanStale has it re-read first.
 */
export function storePlanActive(cache: StorePlanCache | null, nowMs: number): boolean {
  if (!cache || !cache.paid) return false;
  if (cache.expiresAt !== null && nowMs < cache.expiresAt) return true;
  const age = nowMs - cache.checkedAt;
  return age >= 0 && age < STORE_PLAN_GRACE_MS;
}

/** Ask RevenueCat again? After STORE_PLAN_FRESH_MS, or once a paid plan's end date has passed since the last answer. */
export function storePlanStale(cache: StorePlanCache | null, nowMs: number): boolean {
  if (!cache) return true;
  const age = nowMs - cache.checkedAt;
  if (age < 0 || age >= STORE_PLAN_FRESH_MS) return true;
  return cache.paid && cache.expiresAt !== null && cache.checkedAt < cache.expiresAt && nowMs >= cache.expiresAt;
}

/** Has a paid plan's end date passed? Then the SDK's cached answer is dropped before it is asked again. */
export function storePlanPastEnd(cache: StorePlanCache | null, nowMs: number): boolean {
  return Boolean(cache && cache.paid && cache.expiresAt !== null && nowMs >= cache.expiresAt);
}

/** The answer was requested before [stored]'s end date, which has passed since: it cannot know of a renewal. */
function answerPredatesEnd(stored: StorePlanCache, info: CustomerInfoLike | null | undefined, nowMs: number): boolean {
  if (stored.expiresAt === null || nowMs < stored.expiresAt) return false;
  const requested = typeof info?.requestDate === "string" ? Date.parse(info.requestDate) : NaN;
  // Both dates are RevenueCat's / Apple's clock, not the phone's.
  return Number.isFinite(requested) && requested < stored.expiresAt;
}

/**
 * This phone's plan after RevenueCat answered [info]. A paid answer always
 * replaces it, and so does any answer when nothing counts now. An unpaid
 * answer leaves a plan that still counts (storePlanActive) when:
 *   • it predates the plan's end: the end date has passed and the answer
 *     was requested before it — the SDK's cache (offline, or under 5
 *     minutes old) cannot know of a renewal; the 7-day grace then runs
 *     from the last paid answer, as the docs promise;
 *   • [held]: the plan bought here signed out has not reached the account
 *     yet (sign-in did not merge, syncPurchases could not move it) — the
 *     account's own unpaid answer says nothing about it; it counts until
 *     its own end, and "Restore purchases" moves it.
 * Before the end date a fresh unpaid answer is the truth (a refund, the
 * plan transferred away).
 */
export function nextStorePlan(
  stored: StorePlanCache | null,
  info: CustomerInfoLike | null | undefined,
  nowMs: number,
  held: boolean = false,
): StorePlanCache {
  const incoming = storePlanFromInfo(info, nowMs);
  if (incoming.paid || !stored || !storePlanActive(stored, nowMs)) return incoming;
  if (held || answerPredatesEnd(stored, info, nowMs)) return stored;
  return incoming;
}

/**
 * Is a CustomerInfo the SDK gave about whoever is here, so it may become
 * this phone's plan? [sdkAs]: who the SDK was when it answered — an account
 * id, null for RevenueCat's anonymous id, undefined when not known.
 * [here]: the session — the account id, null signed out, undefined signed
 * in but unreadable (offline). Signed out only the anonymous id counts:
 * configure({appUserID: null}) reuses an account id the SDK kept from an
 * earlier run, and that account's plan is not this phone's.
 */
export function storeInfoIsAbout(sdkAs: string | null | undefined, here: string | null | undefined): boolean {
  return sdkAs !== undefined && here !== undefined && sdkAs === here;
}

/**
 * Signed in, and the plan this phone bought signed out did not come along?
 * Purchases.logIn merges the anonymous buyer into the account — unless the
 * account already has an anonymous alias of its own (RevenueCat
 * "Identifying customers": "No merge or purchase transfer occurs"). Then
 * syncPurchases moves it (settleLogIn); when that fails too, the app says
 * "Restore purchases".
 */
export function restoreSuggested(before: StorePlanCache | null, after: StorePlanCache, nowMs: number): boolean {
  return storePlanActive(before, nowMs) && !after.paid;
}

export interface LogInSettled {
  /** This phone's plan from now on (nextStorePlan; held while restoreHint). */
  plan: StorePlanCache;
  /** The plan bought here is still not in the account: say "Restore purchases". */
  restoreHint: boolean;
  /** RevenueCat says the account has the plan: our server must re-read it (no webhook says "merged"). */
  serverSync: boolean;
  /** The last CustomerInfo — logIn's, or syncPurchases'. */
  info: CustomerInfoLike;
}

/**
 * After Purchases.logIn in the iPhone app. [before]: this phone's plan just
 * before; [info]: logIn's answer about the account. Not merged, though the
 * SDK was RevenueCat's anonymous id and this phone has a plan of its own:
 * [syncPurchases] (Purchases.syncPurchasesForResult — "programmatically
 * trigger a restore", no OS sign-in prompt) moves this Apple ID's purchase
 * to the account under the transfer behaviour. Never from another account
 * ([fromAnonymous] false): that would take the plan from it.
 */
export async function settleLogIn(input: {
  fromAnonymous: boolean;
  before: StorePlanCache | null;
  info: CustomerInfoLike;
  nowMs: number;
  syncPurchases: () => Promise<CustomerInfoLike>;
}): Promise<LogInSettled> {
  const { fromAnonymous, before, nowMs } = input;
  let info = input.info;
  let after = storePlanFromInfo(info, nowMs);
  if (fromAnonymous && restoreSuggested(before, after, nowMs)) {
    try {
      info = await input.syncPurchases();
      after = storePlanFromInfo(info, nowMs);
    } catch {
      // Offline, or the store refused: the phone keeps its plan and says Restore.
    }
  }
  const restoreHint = fromAnonymous && restoreSuggested(before, after, nowMs);
  return { plan: nextStorePlan(before, info, nowMs, restoreHint), restoreHint, serverSync: after.paid, info };
}

/**
 * Does our server still have to re-read [accountId] (POST
 * /me/entitlement/refresh)? [pendingFor]: the account a plan reached on
 * sign-in while the refresh had not answered yet. Retried at start, on
 * foreground and on the Account screen until one answers — after the
 * merge no webhook comes until the next renewal (up to a year).
 */
export function serverSyncDue(pendingFor: string | null | undefined, accountId: string | null | undefined): boolean {
  return typeof accountId === "string" && accountId !== "" && pendingFor === accountId;
}

/**
 * Warn before a signed-out purchase or "Restore purchases" in the iPhone
 * app ([withoutAccount])? On a phone where someone has signed in before: a
 * subscription this Apple ID already pays in their account would move to
 * the anonymous id (RevenueCat "Transfer to new App User ID": the previous
 * owner loses it) and stop on Android and in the extension. Signing in is
 * offered first; going on without it stays possible (App Review 5.1.1).
 */
export function warnBeforeWithoutAccount(input: { withoutAccount: boolean; signedIn: boolean; hadAccount: boolean }): boolean {
  return input.withoutAccount && !input.signedIn && input.hadAccount;
}

// ── When it goes wrong ────────────────────────────────────────────────

/**
 *   cancelled     — the person closed Google Play's sheet: say nothing;
 *   pending       — a slow payment (cash, some cards): the plan starts when Google confirms;
 *   already_owned — this Google account already has the subscription (maybe under
 *                   another Cleanway account): restore it instead;
 *   network       — no connection to Google Play or RevenueCat;
 *   not_allowed   — purchases are off on this phone / Google account (family controls);
 *   unavailable   — the plan cannot be bought here (store not set up, country, old Play app);
 *   store_problem — Google Play itself failed;
 *   busy          — another purchase is still going on;
 *   unknown       — anything else.
 */
export type StoreErrorKind =
  | "cancelled"
  | "pending"
  | "already_owned"
  | "network"
  | "not_allowed"
  | "unavailable"
  | "store_problem"
  | "busy"
  | "unknown";

// PURCHASES_ERROR_CODE (@revenuecat/purchases-typescript-internal, generated/error-codes.js).
const ERROR_KINDS: Record<string, StoreErrorKind> = {
  "1": "cancelled", // PURCHASE_CANCELLED_ERROR
  "2": "store_problem", // STORE_PROBLEM_ERROR
  "3": "not_allowed", // PURCHASE_NOT_ALLOWED_ERROR
  "4": "store_problem", // PURCHASE_INVALID_ERROR
  "5": "unavailable", // PRODUCT_NOT_AVAILABLE_FOR_PURCHASE_ERROR
  "6": "already_owned", // PRODUCT_ALREADY_PURCHASED_ERROR
  "7": "already_owned", // RECEIPT_ALREADY_IN_USE_ERROR
  "8": "store_problem", // INVALID_RECEIPT_ERROR
  "9": "store_problem", // MISSING_RECEIPT_FILE_ERROR
  "10": "network", // NETWORK_ERROR
  "11": "unavailable", // INVALID_CREDENTIALS_ERROR (wrong API key / service account)
  "13": "already_owned", // RECEIPT_IN_USE_BY_OTHER_SUBSCRIBER_ERROR
  "15": "busy", // OPERATION_ALREADY_IN_PROGRESS_ERROR
  "18": "unavailable", // INELIGIBLE_ERROR
  "19": "not_allowed", // INSUFFICIENT_PERMISSIONS_ERROR
  "20": "pending", // PAYMENT_PENDING_ERROR
  "23": "unavailable", // CONFIGURATION_ERROR
  "24": "unavailable", // UNSUPPORTED_ERROR
  "32": "network", // PRODUCT_REQUEST_TIMED_OUT_ERROR
  "33": "network", // API_ENDPOINT_BLOCKED (an ad blocker / DNS filter)
  "35": "network", // OFFLINE_CONNECTION_ERROR
};

/** What a rejected SDK call means for the person. */
export function storeErrorKind(err: unknown): StoreErrorKind {
  if (!err || typeof err !== "object") return "unknown";
  const e = err as { code?: unknown; userCancelled?: unknown };
  if (e.userCancelled === true) return "cancelled";
  const code = typeof e.code === "string" ? e.code.trim() : typeof e.code === "number" ? String(e.code) : "";
  return ERROR_KINDS[code] ?? "unknown";
}

// Literal keys, so scripts/check-mobile-i18n.py can see every one.
const ERROR_NOTE_KEYS: Record<Exclude<StoreErrorKind, "cancelled">, string> = {
  pending: "mobile.paywall.note_pending",
  already_owned: "mobile.paywall.err_already_owned",
  network: "mobile.paywall.err_network",
  not_allowed: "mobile.paywall.err_not_allowed",
  unavailable: "mobile.paywall.err_unavailable",
  store_problem: "mobile.paywall.err_store",
  busy: "mobile.paywall.err_busy",
  unknown: "mobile.paywall.err_unknown",
};

// The same, in App Store words (Apple ID, Screen Time, Ask to Buy). Kinds that
// name no store share the Google Play sentence.
const APP_STORE_ERROR_NOTE_KEYS: Record<Exclude<StoreErrorKind, "cancelled">, string> = {
  pending: "mobile.paywall.note_pending_appstore",
  already_owned: "mobile.paywall.err_already_owned_appstore",
  network: "mobile.paywall.err_network_appstore",
  not_allowed: "mobile.paywall.err_not_allowed_appstore",
  unavailable: "mobile.paywall.err_unavailable",
  store_problem: "mobile.paywall.err_store_appstore",
  busy: "mobile.paywall.err_busy",
  unknown: "mobile.paywall.err_unknown",
};

/** The sentence under the button after a failed store call; null when there is nothing to say (cancelled). */
export function storeErrorNoteKey(kind: StoreErrorKind, store: BillingStore = "google_play"): string | null {
  if (kind === "cancelled") return null;
  return store === "app_store" ? APP_STORE_ERROR_NOTE_KEYS[kind] : ERROR_NOTE_KEYS[kind];
}

/** The paywall's and the account screen's store-named sentences. */
export interface StoreCopyKeys {
  pricesLoading: string;
  pricesFailed: string;
  pricesEmpty: string;
  /** The small print under the button: who bills, auto-renewal, where to cancel. */
  fine: string;
  /** Under "Restore purchases" on the account screen. */
  restoreDesc: string;
  /** "Restore purchases" found nothing — on this Apple ID (it restores signed out too), on this account. */
  restoreNone: string;
}

export function storeCopyKeys(store: BillingStore): StoreCopyKeys {
  return store === "app_store"
    ? {
        pricesLoading: "mobile.paywall.prices_loading_appstore",
        pricesFailed: "mobile.paywall.prices_failed_appstore",
        pricesEmpty: "mobile.paywall.prices_empty_appstore",
        fine: "mobile.paywall.fine_store_appstore",
        restoreDesc: "mobile.account.restore_desc_appstore",
        restoreNone: "mobile.paywall.note_restore_none_appstore",
      }
    : {
        pricesLoading: "mobile.paywall.prices_loading",
        pricesFailed: "mobile.paywall.prices_failed",
        pricesEmpty: "mobile.paywall.prices_empty",
        fine: "mobile.paywall.fine_store",
        restoreDesc: "mobile.account.restore_desc",
        restoreNone: "mobile.paywall.note_restore_none",
      };
}

/** The store this build pays through, by distribution; null when it pays elsewhere (or not at all). */
export function billingStoreFor(distribution: string): BillingStore | null {
  return distribution === "appstore" ? "app_store" : distribution === "play" ? "google_play" : null;
}

// ── Managing and cancelling ───────────────────────────────────────────

/** The parts of GET /api/v1/me/entitlement read below. */
export interface StoreEntitlementLike {
  plan: string;
  status: string;
  source?: string | null;
  manage_url?: string | null;
}

function paid(ent: StoreEntitlementLike): boolean {
  return ent.plan !== "free" && ent.status !== "free";
}

function httpsHost(url: string): string | null {
  const m = /^https:\/\/([^/?#:@\s]+)(?:[/?#]|$)/i.exec(url.trim());
  return m ? m[1].toLowerCase() : null;
}

/** Store pages a store build may open: where Google / Apple manage subscriptions. */
const STORE_MANAGE_HOSTS: ReadonlySet<string> = new Set(["play.google.com", "apps.apple.com"]);
/** The iPhone app opens only Apple's own page (App Review 3.1.1: no other store, no website). */
const APP_STORE_MANAGE_HOSTS: ReadonlySet<string> = new Set(["apps.apple.com"]);

/**
 * "Manage subscription": the server's manage_url, https only. A store build
 * opens only a store's own subscriptions page — never our site (for a plan
 * paid on cleanway.ai the store build just says where it was paid). The
 * iPhone app opens only the App Store's page.
 */
export function manageUrlFor(
  ent: StoreEntitlementLike | null | undefined,
  distribution: string,
): string | null {
  if (!ent || !paid(ent) || !ent.manage_url) return null;
  const host = httpsHost(ent.manage_url);
  if (!host) return null;
  if (distribution === "site") return ent.manage_url.trim();
  const allowed = distribution === "appstore" ? APP_STORE_MANAGE_HOSTS : STORE_MANAGE_HOSTS;
  return allowed.has(host) ? ent.manage_url.trim() : null;
}

/** Google Play's subscriptions page for this app — when the server sent no manage_url. */
export function playSubscriptionsUrl(packageName: string): string {
  return `https://play.google.com/store/account/subscriptions?package=${encodeURIComponent(packageName)}`;
}

/** Apple's subscriptions page (opens Settings → Apple ID → Subscriptions on an iPhone). */
export const APP_STORE_SUBSCRIPTIONS_URL = "https://apps.apple.com/account/subscriptions";

/**
 * "Manage subscription" with a fallback: the server's page (manageUrlFor),
 * else — for a plan bought in this build's own store — that store's
 * subscriptions page, so an App Store subscriber can always reach the place
 * where Apple lets them cancel. Null for the free plan and for a plan paid
 * somewhere this build must not link to.
 */
export function manageSubscriptionUrl(
  ent: StoreEntitlementLike | null | undefined,
  distribution: string,
  androidPackage: string,
): string | null {
  const fromServer = manageUrlFor(ent, distribution);
  if (fromServer || !ent || !paid(ent)) return fromServer;
  if (ent.source === "app_store" && distribution === "appstore") return APP_STORE_SUBSCRIPTIONS_URL;
  if (ent.source === "google_play" && distribution === "play") return playSubscriptionsUrl(androidPackage);
  return null;
}

/**
 * Deleting the account does not stop a store subscription: Google Play (and
 * the App Store) let only the person cancel it. Before the delete, a paid
 * plan from a store is named so the app can send them there first.
 */
export function storeSubscriptionToCancel(
  ent: StoreEntitlementLike | null | undefined,
): "google_play" | "app_store" | null {
  if (!ent || !paid(ent)) return null;
  return ent.source === "google_play" || ent.source === "app_store" ? ent.source : null;
}
