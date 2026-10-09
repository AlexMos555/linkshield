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
 * purchase lands on the account (the webhook files it under that id). A
 * purchase is never started without it — signed out, the paywall sends the
 * person to sign in first. Sign-out (any path — services/auth.ts emits it)
 * logs the SDK out.
 *
 * When the SDK talks to RevenueCat: when the paywall loads prices, on a
 * purchase or a restore, and — only for someone who has started a purchase
 * on this phone — at app start, so a pending purchase can finish.
 */
import { NativeModules, Platform } from "react-native";
import type { CustomerInfo, PurchasesPackage } from "react-native-purchases";

import { authEvents, getSessionState } from "./auth";
import { getEntitlement, refreshEntitlement, type EntitlementResponse } from "./api";
import { applyEntitlement } from "./freemium";
import { getSetting, setSetting } from "./database";
import {
  accountIdFromAccessToken,
  configureAtStart,
  planOptions,
  readStoreBillingConfig,
  storeErrorKind,
  storeHasPlan,
  type BillingStore,
  type PlanOption,
  type StoreBillingConfig,
  type StoreErrorKind,
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

/** Set once this phone has opened the store's purchase sheet: the SDK then starts with the app. */
const PURCHASE_STARTED_KEY = "store_purchase_started";

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
 * The SDK, configured and — when [accountId] is given — logged in as that
 * account. Null when this build cannot pay in the app. Rejects when the
 * login itself failed (offline): a purchase must not go on under another id.
 */
function ready(accountId: string | null): Promise<Sdk | null> {
  return serial(async () => {
    const P = loadSdk();
    if (!P || STORE_BILLING.kind !== "on") return null;
    if (_configuredAs === undefined) {
      P.configure({ apiKey: STORE_BILLING.apiKey, appUserID: accountId });
      _configuredAs = accountId;
      return P;
    }
    if (accountId && _configuredAs !== accountId) {
      await P.logIn(accountId);
      _configuredAs = accountId;
    }
    return P;
  });
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
    const P = _sdk;
    if (!P || _configuredAs === undefined || _configuredAs === null) return;
    try {
      await P.logOut();
    } catch {
      // Already anonymous, or offline: the next logIn replaces the id anyway.
    }
    _configuredAs = null;
  });
}

async function startIfPurchaseStarted(accountId: string | null): Promise<void> {
  try {
    const purchaseStarted = (await getSetting(PURCHASE_STARTED_KEY)) === "1";
    if (configureAtStart({ billing: STORE_BILLING, signedIn: accountId !== null, purchaseStarted })) {
      await ready(accountId);
    }
  } catch {
    // Best-effort: the paywall starts it when needed.
  }
}

let _initialised = false;

/** Once, at app start. Does nothing outside the store builds. */
export function initStoreBilling(): void {
  if (_initialised || STORE_BILLING.kind !== "on") return;
  _initialised = true;
  authEvents.on("session", onSession);
  authEvents.on("signed_out", onSignedOut);
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
  | { kind: "restored"; ent: EntitlementResponse | null }
  /** Google Play has the plan; our server has not confirmed it yet. */
  | { kind: "processing" }
  /** No subscription on this Google account. */
  | { kind: "none" }
  | { kind: "signed_out" }
  | { kind: "unavailable" }
  | { kind: "error"; error: StoreErrorKind };

/** Buy [plan] through the store for the signed-in account, then let our server confirm it. */
export async function startStorePurchase(plan: StorePlan): Promise<StorePurchaseResult> {
  const accountId = await currentAccountId();
  if (!accountId) return { kind: "signed_out" };
  let P: Sdk | null;
  try {
    P = await ready(accountId);
  } catch (e) {
    return { kind: "error", error: storeErrorKind(e) };
  }
  if (!P) return { kind: "unavailable" };
  await setSetting(PURCHASE_STARTED_KEY, "1").catch(() => undefined);
  try {
    await P.purchasePackage(plan.pkg);
  } catch (e) {
    const error = storeErrorKind(e);
    if (error === "cancelled") return { kind: "cancelled" };
    if (error === "pending") return { kind: "pending" };
    if (error === "already_owned") {
      // This Google account pays already (maybe under another Cleanway
      // account): restoring moves it here (RevenueCat "transfer" behaviour).
      const restored = await restoreStorePurchases();
      if (restored.kind === "restored") return { kind: "purchased", ent: restored.ent };
      if (restored.kind === "processing") return { kind: "processing" };
    }
    return { kind: "error", error };
  }
  const settled = await settleWithServer();
  return settled.paid ? { kind: "purchased", ent: settled.ent } : { kind: "processing" };
}

/** "Restore purchases": the store account's subscriptions (Google account / Apple ID) → this Cleanway account. */
export async function restoreStorePurchases(): Promise<StoreRestoreResult> {
  const accountId = await currentAccountId();
  if (!accountId) return { kind: "signed_out" };
  let info: CustomerInfo;
  try {
    const P = await ready(accountId);
    if (!P) return { kind: "unavailable" };
    info = await P.restorePurchases();
  } catch (e) {
    return { kind: "error", error: storeErrorKind(e) };
  }
  const settled = await settleWithServer();
  if (settled.paid) return { kind: "restored", ent: settled.ent };
  // Google Play's answer decides "nothing to restore"; when it has the plan
  // and our server has not caught up (or could not be reached), it is on its way.
  return storeHasPlan(info) ? { kind: "processing" } : { kind: "none" };
}
