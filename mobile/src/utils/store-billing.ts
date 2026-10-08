/**
 * Paying in the app through Google Play (RevenueCat SDK), pure — no React
 * Native — so mobile/scripts/test-store-billing.mjs runs it under plain node.
 * The SDK calls themselves are in src/services/store-billing.ts.
 *
 *   • Only the Play build pays in the app (EXPO_PUBLIC_DISTRIBUTION=play on
 *     Android) and only with a public Play key (goog_…). Anything else — the
 *     APK from our site, RuStore, a missing or wrong key — is "off" with a
 *     reason, never a crash.
 *   • The plan is the `cleanway.devices` subscription, monthly and yearly,
 *     from the RevenueCat offering `default`. Prices are the store's own
 *     strings (localised currency); nothing here invents a price.
 *   • Store errors become a few kinds the paywall can say in words.
 *   • RevenueCat knows the person by the Supabase account id, read from the
 *     session's access token (`sub`).
 *
 * Server side and store setup: docs/runbooks/revenuecat.md.
 */

// ── Config ────────────────────────────────────────────────────────────

export interface StoreBillingEnv {
  EXPO_PUBLIC_DISTRIBUTION?: string;
  EXPO_PUBLIC_REVENUECAT_ANDROID_KEY?: string;
}

export type StoreBillingConfig =
  | { kind: "on"; apiKey: string }
  /**
   * not_play — not the Google Play build (site APK, RuStore, iOS);
   * no_key   — the Play build was made without EXPO_PUBLIC_REVENUECAT_ANDROID_KEY;
   * bad_key  — the value is not a public Play key (a secret sk_ key or an
   *            App Store appl_ key must never ship in the app).
   */
  | { kind: "off"; why: "not_play" | "no_key" | "bad_key" };

const PUBLIC_PLAY_KEY = /^goog_[A-Za-z0-9]+$/;

export function readStoreBillingConfig(env: StoreBillingEnv, os: string): StoreBillingConfig {
  const dist = (env.EXPO_PUBLIC_DISTRIBUTION ?? "").trim().toLowerCase();
  if (dist !== "play" || os !== "android") return { kind: "off", why: "not_play" };
  const key = (env.EXPO_PUBLIC_REVENUECAT_ANDROID_KEY ?? "").trim();
  if (!key) return { kind: "off", why: "no_key" };
  if (!PUBLIC_PLAY_KEY.test(key)) return { kind: "off", why: "bad_key" };
  return { kind: "on", apiKey: key };
}

/**
 * Start the SDK when the app starts? Only for a signed-in person on this
 * phone who has started a store purchase before: the SDK must then run to
 * finish a pending ("slow card") purchase and acknowledge it, or Google
 * refunds it after 3 days. Everyone else meets RevenueCat only when they
 * open the paywall or tap "Restore purchases" — no request on every start.
 */
export function configureAtStart(input: {
  billing: StoreBillingConfig;
  signedIn: boolean;
  purchaseStarted: boolean;
}): boolean {
  return input.billing.kind === "on" && input.signedIn && input.purchaseStarted;
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

/** The sentence under the button after a failed store call; null when there is nothing to say (cancelled). */
export function storeErrorNoteKey(kind: StoreErrorKind): string | null {
  return kind === "cancelled" ? null : ERROR_NOTE_KEYS[kind];
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

/**
 * "Manage subscription": the server's manage_url, https only. A store build
 * opens only a store's own subscriptions page — never our site (for a plan
 * paid on cleanway.ai the store build just says where it was paid).
 */
export function manageUrlFor(
  ent: StoreEntitlementLike | null | undefined,
  distribution: string,
): string | null {
  if (!ent || !paid(ent) || !ent.manage_url) return null;
  const host = httpsHost(ent.manage_url);
  if (!host) return null;
  if (distribution === "site") return ent.manage_url.trim();
  return STORE_MANAGE_HOSTS.has(host) ? ent.manage_url.trim() : null;
}

/** Google Play's subscriptions page for this app — when the server sent no manage_url. */
export function playSubscriptionsUrl(packageName: string): string {
  return `https://play.google.com/store/account/subscriptions?package=${encodeURIComponent(packageName)}`;
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
