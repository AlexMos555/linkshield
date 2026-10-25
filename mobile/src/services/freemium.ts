/**
 * The free plan on this phone: the daily counter, the first-days trial and
 * the paid status, stored in the app's settings table. The rules themselves
 * are pure (src/utils/freemium.ts); this file reads and writes their state.
 *
 * With EXPO_PUBLIC_FREEMIUM_ENABLED off (the default) nothing here touches
 * storage or the network: every check is detailed, as before.
 *
 * No analytics: nothing about the counter, the paywall or a purchase leaves
 * the phone. The only request is GET /api/v1/me/entitlement, when signed in —
 * and in the iPhone app, for a phone that bought or restored there, RevenueCat
 * itself (services/store-billing.ts refreshStorePlan): the iPhone app sells
 * without an account, so the phone also counts its own App Store plan.
 */
import { EventEmitter } from "events";
import { Platform } from "react-native";

import { getSetting, setSetting } from "./database";
import { getSessionState } from "./auth";
import { getEntitlement, type EntitlementResponse } from "./api";
import {
  accessFor,
  entitlementFresh,
  gateCheck,
  installedAtOr,
  isPaidEntitlement,
  localDayKey,
  paidFromCache,
  parseEntitlementCache,
  quotaForDay,
  readFreemiumConfig,
  storePurchaseWithoutAccount,
  withPaywallShown,
  type Access,
  type EntitlementCache,
  type FreemiumConfig,
  type QuotaState,
} from "../utils/freemium";
import {
  paidPlansOffered,
  parseStorePlanCache,
  readStoreBillingConfig,
  storePlanActive,
  storePlanStale,
  type StorePlanCache,
} from "../utils/store-billing";

/**
 * Does this build show paid plans at all (utils/store-billing.ts
 * paidPlansOffered)? False only in an iPhone build without App Store billing:
 * then no Plan / Upgrade row, no paywall and no daily limit. Read here from
 * the pure rule rather than services/store-billing.ts, which imports this
 * file — a cycle would leave one of the two constants undefined at load.
 */
export const PAID_PLANS_OFFERED: boolean = paidPlansOffered(
  readStoreBillingConfig(
    {
      EXPO_PUBLIC_DISTRIBUTION: process.env.EXPO_PUBLIC_DISTRIBUTION,
      EXPO_PUBLIC_REVENUECAT_ANDROID_KEY: process.env.EXPO_PUBLIC_REVENUECAT_ANDROID_KEY,
      EXPO_PUBLIC_REVENUECAT_IOS_KEY: process.env.EXPO_PUBLIC_REVENUECAT_IOS_KEY,
    },
    Platform.OS,
  ),
  Platform.OS,
);

// Literal process.env.EXPO_PUBLIC_* reads: Expo inlines exactly these at build time.
export const FREEMIUM: FreemiumConfig = readFreemiumConfig(
  typeof process !== "undefined"
    ? {
        EXPO_PUBLIC_FREEMIUM_ENABLED: process.env.EXPO_PUBLIC_FREEMIUM_ENABLED,
        EXPO_PUBLIC_FREE_CHECKS_PER_DAY: process.env.EXPO_PUBLIC_FREE_CHECKS_PER_DAY,
        EXPO_PUBLIC_FREE_TRIAL_DAYS: process.env.EXPO_PUBLIC_FREE_TRIAL_DAYS,
        EXPO_PUBLIC_DISTRIBUTION: process.env.EXPO_PUBLIC_DISTRIBUTION,
      }
    : {},
  // iOS is always the App Store build (distributionFor): no web checkout, no self-update.
  Platform.OS,
  // No paid plans in this build: no limit either (nothing would lift it).
  PAID_PLANS_OFFERED,
);

/**
 * Does this phone count its own store plan (utils/store-billing.ts
 * storePlanActive)? Only the iPhone app that sells: it buys and restores
 * without an account. False on every Android build and in an iPhone build
 * without App Store billing — those read the plan from the server alone.
 */
const DEVICE_PLAN: boolean = PAID_PLANS_OFFERED && storePurchaseWithoutAccount(FREEMIUM.distribution);

const QUOTA_KEY = "freemium_quota";
const INSTALLED_KEY = "freemium_installed_at";
const ENTITLEMENT_KEY = "freemium_entitlement";
const STORE_PLAN_KEY = "freemium_store_plan";

/** "changed": the counter or the paid status moved — counters on screen re-read. */
export const freemiumEvents = new EventEmitter();

function parseJson(raw: string): unknown {
  try {
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

async function readQuota(now: number): Promise<QuotaState> {
  return quotaForDay(parseJson(await getSetting(QUOTA_KEY)), localDayKey(now));
}

/** First launch with the limit on; stored the first time it is asked for. */
async function installedAt(now: number): Promise<number> {
  const raw = await getSetting(INSTALLED_KEY);
  const at = installedAtOr(raw, now);
  if (!raw) await setSetting(INSTALLED_KEY, String(at));
  return at;
}

async function readCache(): Promise<EntitlementCache | null> {
  return parseEntitlementCache(parseJson(await getSetting(ENTITLEMENT_KEY)));
}

function accountOf(session: Awaited<ReturnType<typeof getSessionState>>): string | null {
  if (session.kind === "none") return null;
  return session.kind === "ok" ? session.session.email : session.email ?? "";
}

async function writeCache(cache: EntitlementCache, before: EntitlementCache | null): Promise<void> {
  await setSetting(ENTITLEMENT_KEY, JSON.stringify(cache));
  if (cache.paid !== (before?.paid ?? false)) freemiumEvents.emit("changed");
}

/** Keep a plan answer the app already has (sign-in, heartbeat, Account screen). */
export async function rememberEntitlement(ent: EntitlementResponse): Promise<void> {
  if (!FREEMIUM.enabled) return;
  try {
    const account = accountOf(await getSessionState());
    if (account === null) return;
    await writeCache({ account, paid: isPaidEntitlement(ent), fetchedAt: Date.now() }, await readCache());
  } catch {
    // Best-effort: the next check asks the server itself.
  }
}

/**
 * A plan answer right after a purchase or a restore: kept whatever the
 * EXPO_PUBLIC_FREEMIUM_ENABLED switch says (the paywall's paid check reads
 * the same cache), so every counter on screen sees "paid" at once.
 */
export async function applyEntitlement(ent: EntitlementResponse): Promise<boolean> {
  const paid = isPaidEntitlement(ent);
  try {
    const account = accountOf(await getSessionState());
    if (account !== null) await writeCache({ account, paid, fetchedAt: Date.now() }, await readCache());
  } catch {
    // Best-effort: the next check asks the server itself.
  }
  return paid;
}

/** Ask the server; null when it could not answer. */
async function fetchPaid(account: string, before: EntitlementCache | null): Promise<boolean | null> {
  const { data } = await getEntitlement();
  if (!data) return null;
  const paid = isPaidEntitlement(data);
  await writeCache({ account, paid, fetchedAt: Date.now() }, before);
  return paid;
}

// ── This phone's own plan (the iPhone app) ────────────────────────────

let _storePlanRefresher: (() => Promise<void>) | null = null;

/**
 * How to re-read this phone's plan from RevenueCat — handed over by
 * services/store-billing.ts at start (it imports this file; an import the
 * other way would be a cycle).
 */
export function setStorePlanRefresher(refresh: (() => Promise<void>) | null): void {
  _storePlanRefresher = refresh;
}

/** The last answer about this phone's own plan; null outside the iPhone app or when there is none. */
export async function storePlanOnThisPhone(): Promise<StorePlanCache | null> {
  if (!DEVICE_PLAN) return null;
  return parseStorePlanCache(parseJson(await getSetting(STORE_PLAN_KEY)));
}

/** Keep what RevenueCat just said about this phone's plan (purchase, restore, sign-in / out, a re-read). */
export async function rememberStorePlan(plan: StorePlanCache): Promise<void> {
  if (!DEVICE_PLAN) return;
  try {
    const before = await storePlanOnThisPhone();
    await setSetting(STORE_PLAN_KEY, JSON.stringify(plan));
    const now = Date.now();
    if (storePlanActive(before, now) !== storePlanActive(plan, now)) freemiumEvents.emit("changed");
  } catch {
    // Best-effort: the next purchase / restore / re-read writes it again.
  }
}

/**
 * Paid by this phone's own App Store plan? Always false outside the iPhone
 * app. A stale answer is re-read from RevenueCat in the background (only for
 * a phone that bought or restored here — store-billing.ts decides); [force],
 * from the paywall, waits for it.
 */
export async function devicePlanPaid(force: boolean = false): Promise<boolean> {
  if (!DEVICE_PLAN) return false;
  try {
    let plan = await storePlanOnThisPhone();
    const refresh = _storePlanRefresher;
    if (refresh && (force || (plan !== null && storePlanStale(plan, Date.now())))) {
      const run = refresh().catch(() => undefined);
      if (force) {
        await run;
        plan = await storePlanOnThisPhone();
      }
    }
    return storePlanActive(plan, Date.now());
  } catch {
    return false;
  }
}

/** The account's plan, from the server or its cache (see isPaid). */
async function accountPaid(session: Awaited<ReturnType<typeof getSessionState>>, force: boolean): Promise<boolean> {
  const account = accountOf(session);
  if (account === null) return false;
  const now = Date.now();
  const cache = await readCache();
  if (session.kind === "offline") return paidFromCache(cache, account, now);
  if (!force && entitlementFresh(cache, account, now)) return cache?.paid ?? false;
  if (!force && cache !== null && cache.account === account) {
    void fetchPaid(account, cache).catch(() => null);
    return paidFromCache(cache, account, now);
  }
  const paid = await fetchPaid(account, cache).catch(() => null);
  return paid ?? paidFromCache(cache, account, now);
}

/**
 * Paid right now? Not signed in is free — except an iPhone whose own App
 * Store plan RevenueCat reports (devicePlanPaid; the iPhone app sells without
 * an account, and the phone that paid keeps its plan even when the account's
 * device seats are all taken). Signed in: also the account's plan — the
 * cached answer while fresh. A stale one answers at once (a paid one within
 * the offline grace) and the server is asked in the background, so a check
 * never waits on a slow network for the plan. Only with no answer at all —
 * or [force], from the paywall — does it wait for the server.
 */
export async function isPaid(force: boolean = false): Promise<boolean> {
  const session = await getSessionState();
  const [account, device] = await Promise.all([accountPaid(session, force), devicePlanPaid(force)]);
  return account || device;
}

/** What the next check gets — for the "N checks left today" hint. */
export async function currentAccess(): Promise<Access> {
  if (!FREEMIUM.enabled) return { kind: "unlimited", why: "off" };
  const now = Date.now();
  const [paid, at, quota] = await Promise.all([isPaid(), installedAt(now), readQuota(now)]);
  return accessFor({ config: FREEMIUM, paid, installedAt: at, quota, nowMs: now });
}

export interface CheckDecision {
  detailed: boolean;
  /** Open the paywall by itself (the first time the limit stops a check today). */
  autoPaywall: boolean;
}

// Two screens asking at once (a share arriving over an open check) must not
// both spend the same last check: decisions run one after another.
let chain: Promise<unknown> = Promise.resolve();

/**
 * A detailed check is about to start. Decides, and spends one free check
 * when it is allowed. [key] = the site (re-opening it today is free); null =
 * a message, which always counts. Any storage failure lets the check
 * through — a broken counter never hides an analysis.
 */
export function beginDetailedCheck(key: string | null): Promise<CheckDecision> {
  if (!FREEMIUM.enabled) return Promise.resolve({ detailed: true, autoPaywall: false });
  const run = chain.then(async (): Promise<CheckDecision> => {
    try {
      const now = Date.now();
      const [paid, at, quota] = await Promise.all([isPaid(), installedAt(now), readQuota(now)]);
      const access = accessFor({ config: FREEMIUM, paid, installedAt: at, quota, nowMs: now });
      const gate = gateCheck(access, quota, key);
      if (gate.quota !== quota) {
        await setSetting(QUOTA_KEY, JSON.stringify(gate.quota));
        freemiumEvents.emit("changed");
      }
      return { detailed: gate.detailed, autoPaywall: gate.autoPaywall };
    } catch {
      return { detailed: true, autoPaywall: false };
    }
  });
  chain = run.catch(() => undefined);
  return run;
}

/** The paywall opened by itself: it does not again today (the in-place card still offers it). */
export function notePaywallShown(): Promise<void> {
  if (!FREEMIUM.enabled) return Promise.resolve();
  const run = chain.then(async () => {
    try {
      const quota = await readQuota(Date.now());
      await setSetting(QUOTA_KEY, JSON.stringify(withPaywallShown(quota)));
    } catch {
      // At worst it opens by itself once more.
    }
  });
  chain = run;
  return run;
}
