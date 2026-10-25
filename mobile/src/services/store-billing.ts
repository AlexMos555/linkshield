/**
 * Paying in the app through Google Play or the App Store, via the RevenueCat
 * SDK (react-native-purchases). The rules are pure, in src/utils/store-billing.ts;
 * this file makes the SDK calls. Store and server setup:
 * docs/runbooks/revenuecat.md, docs/IOS.md.
 *
 * Only the Play build (EXPO_PUBLIC_DISTRIBUTION=play) with a public Play key
 * (EXPO_PUBLIC_REVENUECAT_ANDROID_KEY=goog_…), and the iPhone app with a
 * public App Store key (EXPO_PUBLIC_REVENUECAT_IOS_KEY=appl_…), ever load the
 * SDK. In every other Android build the require below is dropped from the
 * release bundle (Metro inlines EXPO_PUBLIC_* and Platform.OS and folds the
 * comparison), and mobile/react-native.config.js keeps the native library —
 * Play Billing and its BILLING permission — out of the APK. Without a key
 * the store build says "paying in the app is coming soon" instead of crashing.
 *
 * Identity: RevenueCat knows the person by the Supabase account id, so a
 * purchase lands on the account (the webhook files it under that id).
 *   • Google Play: a purchase is never started without it — signed out, the
 *     paywall sends the person to sign in first.
 *   • The iPhone app (STORE_PURCHASE_WITHOUT_ACCOUNT; App Review 5.1.1,
 *     docs/STORE_DECISIONS_2026-10.md §3, option Б): signed out, the purchase
 *     and "Restore purchases" run under RevenueCat's anonymous id, and the
 *     phone keeps its own plan (services/freemium.ts rememberStorePlan) — it
 *     has no account the server could answer for. Signing in later calls
 *     Purchases.logIn: RevenueCat makes the anonymous buyer an alias of the
 *     account, and the app asks our server to re-read the account
 *     (POST /me/entitlement/refresh) so Android and the extension see the
 *     plan too. When RevenueCat does not merge (the account already has an
 *     anonymous alias of its own), the app suggests "Restore purchases".
 * Sign-out (any path — services/auth.ts emits it) logs the SDK out.
 *
 * When the SDK talks to RevenueCat: when the paywall loads prices, on a
 * purchase or a restore, and — only for someone who has started a purchase
 * (or, on the iPhone, a restore) on this phone — at app start, so a pending
 * purchase can finish and the phone learns of a renewal or an end.
 */
import { NativeModules, Platform } from "react-native";
import type { CustomerInfo, PurchasesPackage } from "react-native-purchases";

import { authEvents, getSessionState } from "./auth";
import { getEntitlement, refreshEntitlement, type EntitlementResponse } from "./api";
import {
  FREEMIUM,
  applyEntitlement,
  rememberStorePlan,
  setStorePlanRefresher,
  storePlanOnThisPhone,
} from "./freemium";
import { getSetting, setSetting } from "./database";
import { storePurchaseWithoutAccount } from "../utils/freemium";
import {
  accountIdFromAccessToken,
  configureAtStart,
  payingAs,
  planOptions,
  readStoreBillingConfig,
  restoreSuggested,
  storeErrorKind,
  storeHasPlan,
  storePlanFromInfo,
  type BillingStore,
  type PlanOption,
  type StoreBillingConfig,
  type StoreErrorKind,
  type StorePlanCache,
} from "../utils/store-billing";

// Literal process.env.EXPO_PUBLIC_* reads: Expo inlines exactly these at build time.
export const STORE_BILLING: StoreBillingConfig = readStoreBillingConfig(
  {
    EXPO_PUBLIC_DISTRIBUTION: process.env.EXPO_PUBLIC_DISTRIBUTION,
    EXPO_PUBLIC_REVENUECAT_ANDROID_KEY: process.env.EXPO_PUBLIC_REVENUECAT_ANDROID_KEY,
    EXPO_PUBLIC_REVENUECAT_IOS_KEY: process.env.EXPO_PUBLIC_REVENUECAT_IOS_KEY,
  },
  Platform.OS,
);

/** The store this build pays through — for the store-named sentences; Google Play when off. */
export const BILLING_STORE: BillingStore =
  STORE_BILLING.kind === "on" ? STORE_BILLING.store : Platform.OS === "ios" ? "app_store" : "google_play";

/**
 * Buy and restore signed out? The iPhone app with App Store billing only
 * (utils/freemium.ts storePurchaseWithoutAccount). Google Play keeps "sign in
 * first", and an iPhone build without its appl_ key sells nothing at all.
 */
export const STORE_PURCHASE_WITHOUT_ACCOUNT: boolean =
  STORE_BILLING.kind === "on" && storePurchaseWithoutAccount(FREEMIUM.distribution);

/**
 * Set once this phone has opened the store's purchase sheet (or, on the
 * iPhone, restored a plan): the SDK then starts with the app.
 */
const PURCHASE_STARTED_KEY = "store_purchase_started";
/** "1" while the plan bought on this phone signed out did not follow the account (restoreSuggested). */
const RESTORE_HINT_KEY = "store_restore_hint";

type Sdk = (typeof import("react-native-purchases"))["default"];

let _sdk: Sdk | null | undefined;

function loadSdk(): Sdk | null {
  if (_sdk !== undefined) return _sdk;
  _sdk = null;
  if (STORE_BILLING.kind !== "on") return null;
  // Keep this a plain `=== "play"` on the literal env read (or the inlined
  // Platform.OS): in a release bundle of any other Android build it folds to
  // `if (false)` and the SDK's JS is not bundled at all. Every iOS build is
  // the App Store one (utils/freemium.ts distributionFor).
  if (process.env.EXPO_PUBLIC_DISTRIBUTION === "play" || Platform.OS === "ios") {
    // The native half is linked only when the build was made with the same
    // env (react-native.config.js); without it, purchases are "unavailable".
    if (NativeModules.RNPurchases) {
      try {
        _sdk = (require("react-native-purchases") as typeof import("react-native-purchases")).default;
      } catch {
        _sdk = null;
      }
    }
  }
  return _sdk;
}

/** Can this build pay through its store right now (on, with the native SDK present)? */
export function storeBillingOn(): boolean {
  return loadSdk() !== null;
}

// ── Identity ──────────────────────────────────────────────────────────

/** undefined = not configured yet; null = configured, anonymous; else the account id it is logged in as. */
let _configuredAs: string | null | undefined;
// configure / logIn / logOut one at a time: a sign-out racing a purchase's
// logIn must not leave the SDK logged in as the wrong person.
let _chain: Promise<unknown> = Promise.resolve();

function serial<T>(fn: () => Promise<T>): Promise<T> {
  const run = _chain.then(fn, fn);
  _chain = run.catch(() => undefined);
  return run;
}

async function currentAccountId(): Promise<string | null> {
  const st = await getSessionState();
  return st.kind === "ok" ? accountIdFromAccessToken(st.session.accessToken) : null;
}

/**
 * Who is here, for a purchase or a restore: the account id; null when
 * signed out; undefined when signed in but the account cannot be read right
 * now (the session could not be refreshed offline) — never "anonymous".
 */
async function currentPayer(): Promise<string | null | undefined> {
  const st = await getSessionState();
  if (st.kind === "none") return null;
  return st.kind === "ok" ? accountIdFromAccessToken(st.session.accessToken) ?? undefined : undefined;
}

async function boughtHere(): Promise<boolean> {
  return (await getSetting(PURCHASE_STARTED_KEY).catch(() => "")) === "1";
}

/** The iPhone app: keep what RevenueCat says about the plan of whoever the SDK is on this phone. */
function keepPlan(info: CustomerInfo | null | undefined): Promise<void> {
  return STORE_PURCHASE_WITHOUT_ACCOUNT && info ? rememberStorePlan(storePlanFromInfo(info, Date.now())) : Promise.resolve();
}

function setRestoreHint(on: boolean): Promise<void> {
  if (!STORE_PURCHASE_WITHOUT_ACCOUNT) return Promise.resolve();
  return setSetting(RESTORE_HINT_KEY, on ? "1" : "").catch(() => undefined);
}

/**
 * The SDK, configured and — when [accountId] is given — logged in as that
 * account. Null when this build cannot pay in the app. Rejects when the
 * login itself failed (offline): a purchase must not go on under another id.
 *
 * [anonymous]: a signed-out purchase or restore in the iPhone app — make
 * sure the SDK is RevenueCat's anonymous id, not an account it kept (a
 * sign-out it never saw, a logOut that failed offline).
 */
function ready(accountId: string | null, anonymous: boolean = false): Promise<Sdk | null> {
  return serial(async () => {
    const P = loadSdk();
    if (!P || STORE_BILLING.kind !== "on") return null;
    if (_configuredAs === undefined) {
      // In the iPhone app a phone that bought here may hold an anonymous
      // buyer: start as whoever the SDK kept (appUserID null reuses it), and
      // the logIn below merges it into the account. Everyone else starts as
      // the account right away — an extra empty anonymous id would take the
      // account's one anonymous alias for nothing.
      const resume = STORE_PURCHASE_WITHOUT_ACCOUNT && accountId !== null && (await boughtHere());
      P.configure({ apiKey: STORE_BILLING.apiKey, appUserID: resume ? null : accountId });
      _configuredAs = resume ? null : accountId;
      if (STORE_PURCHASE_WITHOUT_ACCOUNT) {
        // appUserID null reuses whatever id the SDK kept — maybe an account.
        if (_configuredAs === null && !(await P.isAnonymous())) _configuredAs = await P.getAppUserID();
        P.addCustomerInfoUpdateListener((info) => void keepPlan(info));
      }
    }
    if (accountId && _configuredAs !== accountId) {
      const before = STORE_PURCHASE_WITHOUT_ACCOUNT ? await storePlanOnThisPhone() : null;
      const { customerInfo } = await P.logIn(accountId);
      _configuredAs = accountId;
      if (STORE_PURCHASE_WITHOUT_ACCOUNT) await afterLogIn(before, customerInfo);
    } else if (anonymous && !accountId && (_configuredAs !== null || !(await P.isAnonymous()))) {
      await keepPlan(await P.logOut());
      _configuredAs = null;
    }
    return P;
  });
}

/** ready() for who pays (payingAs): the account, or — signed out in the iPhone app — anonymous. */
function readyFor(who: { kind: "account"; id: string } | { kind: "anonymous" }): Promise<Sdk | null> {
  return who.kind === "account" ? ready(who.id) : ready(null, true);
}

/**
 * Signed in on the iPhone. When the account now has the plan (RevenueCat
 * merged the anonymous buyer, or the account paid already), our server is
 * asked to re-read it — no webhook says "merged". When the plan bought here
 * did not come along, "Restore purchases" will move it: the screens say so.
 */
async function afterLogIn(before: StorePlanCache | null, info: CustomerInfo): Promise<void> {
  const now = Date.now();
  const after = storePlanFromInfo(info, now);
  await keepPlan(info);
  await setRestoreHint(restoreSuggested(before, after, now));
  // Not awaited: the SDK chain must not wait on our server.
  if (after.paid) void settleWithServer().catch(() => undefined);
}

function onSession(accessToken: unknown): void {
  const accountId = typeof accessToken === "string" ? accountIdFromAccessToken(accessToken) : null;
  if (!accountId || _configuredAs === accountId) return;
  if (_configuredAs === undefined) {
    // Not started yet: it starts as this account when first needed.
    void startIfPurchaseStarted(accountId);
    return;
  }
  void ready(accountId).catch(() => undefined);
}

function onSignedOut(): void {
  void serial(async () => {
    if (STORE_PURCHASE_WITHOUT_ACCOUNT) {
      // Whatever the SDK says next, the account's plan is not this phone's
      // any more: RevenueCat gives a signed-out phone a new anonymous id, and
      // "Restore purchases" brings a plan of this Apple ID back.
      await rememberStorePlan({ paid: false, expiresAt: null, checkedAt: Date.now() });
      await setRestoreHint(false);
    }
    const P = _sdk;
    if (!P || _configuredAs === undefined || _configuredAs === null) return;
    try {
      await keepPlan(await P.logOut());
    } catch {
      // Already anonymous, or offline: the next logIn replaces the id anyway,
      // and in the iPhone app ready(null) logs out before a purchase.
    }
    _configuredAs = null;
  });
}

async function startIfPurchaseStarted(accountId: string | null): Promise<void> {
  try {
    const purchaseStarted = await boughtHere();
    if (configureAtStart({
      billing: STORE_BILLING,
      signedIn: accountId !== null,
      purchaseStarted,
      withoutAccount: STORE_PURCHASE_WITHOUT_ACCOUNT,
    })) {
      const P = await ready(accountId);
      // The iPhone: learn of a renewal, an end or an approved Ask to Buy now.
      if (P && STORE_PURCHASE_WITHOUT_ACCOUNT) await keepPlan(await P.getCustomerInfo());
    }
  } catch {
    // Best-effort: the paywall starts it when needed.
  }
}

/**
 * Re-read this phone's plan from RevenueCat (the iPhone app). Only for a
 * phone that bought or restored here, or already talks to RevenueCat in
 * this run — no request for anyone else.
 */
async function refreshStorePlan(): Promise<void> {
  if (!STORE_PURCHASE_WITHOUT_ACCOUNT) return;
  if (_configuredAs === undefined && !(await boughtHere())) return;
  const P = await ready(await currentAccountId());
  if (P) await keepPlan(await P.getCustomerInfo());
}

/**
 * The plan bought on this phone signed out did not follow the account on
 * sign-in: say "Restore purchases" moves it (the paywall, the account screen).
 */
export async function storeRestoreSuggested(): Promise<boolean> {
  if (!STORE_PURCHASE_WITHOUT_ACCOUNT) return false;
  return (await getSetting(RESTORE_HINT_KEY).catch(() => "")) === "1";
}

let _initialised = false;

/** Once, at app start. Does nothing outside the store builds. */
export function initStoreBilling(): void {
  if (_initialised || STORE_BILLING.kind !== "on") return;
  _initialised = true;
  authEvents.on("session", onSession);
  authEvents.on("signed_out", onSignedOut);
  if (STORE_PURCHASE_WITHOUT_ACCOUNT) setStorePlanRefresher(refreshStorePlan);
  void (async () => {
    await startIfPurchaseStarted(await currentAccountId().catch(() => null));
  })();
}

// ── Prices ────────────────────────────────────────────────────────────

export type StorePlan = PlanOption<PurchasesPackage>;

export type StorePlansResult =
  | { kind: "ok"; plans: StorePlan[] }
  /** The store has nothing to sell here (offering not set up, product not in this country). */
  | { kind: "empty" }
  | { kind: "unavailable" }
  | { kind: "error"; error: StoreErrorKind };

/** The plans with Google Play's own prices (the paywall shows nothing it did not get from here). */
export async function loadStorePlans(): Promise<StorePlansResult> {
  try {
    const P = await ready(await currentAccountId());
    if (!P) return { kind: "unavailable" };
    const plans = planOptions(await P.getOfferings());
    return plans.length > 0 ? { kind: "ok", plans } : { kind: "empty" };
  } catch (e) {
    return { kind: "error", error: storeErrorKind(e) };
  }
}

// ── Buying and restoring ──────────────────────────────────────────────

interface Settled {
  ent: EntitlementResponse | null;
  paid: boolean;
}

/**
 * Ask our server to re-read the store (POST …/entitlement/refresh) and keep
 * the answer. When the refresh fails, the plain read still sees a plan the
 * webhook already delivered.
 */
async function settleWithServer(): Promise<Settled> {
  const r = await refreshEntitlement();
  if (r.data && (await applyEntitlement(r.data))) return { ent: r.data, paid: true };
  const g = await getEntitlement();
  if (g.data) return { ent: g.data, paid: await applyEntitlement(g.data) };
  return { ent: r.data, paid: false };
}

export type StorePurchaseResult =
  /** Paid. [ent] is the account's plan; null when bought without an account (the iPhone app). */
  | { kind: "purchased"; ent: EntitlementResponse | null }
  /** Google took the payment; our server has not confirmed it yet (usually seconds). */
  | { kind: "processing" }
  /** A slow payment: the plan starts when Google confirms it. */
  | { kind: "pending" }
  | { kind: "cancelled" }
  | { kind: "signed_out" }
  | { kind: "unavailable" }
  | { kind: "error"; error: StoreErrorKind };

export type StoreRestoreResult =
  /** Restored. [ent] is the account's plan; null when restored without an account (the iPhone app). */
  | { kind: "restored"; ent: EntitlementResponse | null }
  /** Google Play has the plan; our server has not confirmed it yet. */
  | { kind: "processing" }
  /** No subscription on this Google account / Apple ID. */
  | { kind: "none" }
  | { kind: "signed_out" }
  | { kind: "unavailable" }
  | { kind: "error"; error: StoreErrorKind };

/**
 * Buy [plan] through the store — for the signed-in account, or in the
 * iPhone app signed out under RevenueCat's anonymous id — then let our server
 * confirm it when there is an account.
 */
export async function startStorePurchase(plan: StorePlan): Promise<StorePurchaseResult> {
  const payer = await currentPayer();
  // Signed in but offline: never buy anonymously on the iPhone; Google Play, as before.
  if (payer === undefined) return STORE_PURCHASE_WITHOUT_ACCOUNT ? { kind: "error", error: "network" } : { kind: "signed_out" };
  const who = payingAs(payer, STORE_PURCHASE_WITHOUT_ACCOUNT);
  if (who.kind === "sign_in_first") return { kind: "signed_out" };
  let P: Sdk | null;
  try {
    P = await readyFor(who);
  } catch (e) {
    return { kind: "error", error: storeErrorKind(e) };
  }
  if (!P) return { kind: "unavailable" };
  await setSetting(PURCHASE_STARTED_KEY, "1").catch(() => undefined);
  let info: CustomerInfo;
  try {
    ({ customerInfo: info } = await P.purchasePackage(plan.pkg));
  } catch (e) {
    const error = storeErrorKind(e);
    if (error === "cancelled") return { kind: "cancelled" };
    if (error === "pending") return { kind: "pending" };
    if (error === "already_owned") {
      // This store account pays already (maybe under another Cleanway
      // account): restoring moves it here (RevenueCat "transfer" behaviour).
      const restored = await restoreStorePurchases();
      if (restored.kind === "restored") return { kind: "purchased", ent: restored.ent };
      if (restored.kind === "processing") return { kind: "processing" };
    }
    return { kind: "error", error };
  }
  await keepPlan(info);
  const storeHasIt = storeHasPlan(info);
  if (who.kind === "anonymous") return storeHasIt ? { kind: "purchased", ent: null } : { kind: "processing" };
  await setRestoreHint(false);
  const settled = await settleWithServer();
  if (settled.paid) return { kind: "purchased", ent: settled.ent };
  // The iPhone counts its own plan at once; the account follows with the webhook.
  return STORE_PURCHASE_WITHOUT_ACCOUNT && storeHasIt ? { kind: "purchased", ent: settled.ent } : { kind: "processing" };
}

/**
 * "Restore purchases": the store account's subscriptions (Google account /
 * Apple ID) → this Cleanway account; in the iPhone app signed out → this
 * phone, under RevenueCat's anonymous id.
 */
export async function restoreStorePurchases(): Promise<StoreRestoreResult> {
  const payer = await currentPayer();
  if (payer === undefined) return STORE_PURCHASE_WITHOUT_ACCOUNT ? { kind: "error", error: "network" } : { kind: "signed_out" };
  const who = payingAs(payer, STORE_PURCHASE_WITHOUT_ACCOUNT);
  if (who.kind === "sign_in_first") return { kind: "signed_out" };
  let info: CustomerInfo;
  try {
    const P = await readyFor(who);
    if (!P) return { kind: "unavailable" };
    info = await P.restorePurchases();
  } catch (e) {
    return { kind: "error", error: storeErrorKind(e) };
  }
  const storeHasIt = storeHasPlan(info);
  await keepPlan(info);
  if (STORE_PURCHASE_WITHOUT_ACCOUNT && storeHasIt) {
    // The SDK starts with the app from now on: renewals and the end reach the phone.
    await setSetting(PURCHASE_STARTED_KEY, "1").catch(() => undefined);
    await setRestoreHint(false);
  }
  if (who.kind === "anonymous") return storeHasIt ? { kind: "restored", ent: null } : { kind: "none" };
  const settled = await settleWithServer();
  if (settled.paid) return { kind: "restored", ent: settled.ent };
  // The store's answer decides "nothing to restore"; when it has the plan
  // and our server has not caught up (or could not be reached), it is on its
  // way — and the iPhone counts its own plan already.
  if (!storeHasIt) return { kind: "none" };
  return STORE_PURCHASE_WITHOUT_ACCOUNT ? { kind: "restored", ent: settled.ent } : { kind: "processing" };
}
