/**
 * What the phone keeps about its subscription, in SecureStore (Android
 * Keystore-backed), and the one piece of local history the founder's open
 * decision needs: whether this phone was installed before the paid launch.
 *
 * Nothing here is personal: a device id and its secret, the last signed pass,
 * the last status snapshot, a few timestamps. No phone number is ever stored
 * on the phone — the server keeps it, encrypted, in the Russian database.
 *
 * Every read tolerates a missing or unreadable store (a fresh install, a
 * phone restored from backup where the keystore did not come along): the
 * app then behaves as a new phone and registers again.
 */
import * as SecureStore from "expo-secure-store";

import type { PlanInfo } from "../lib/billing-api";
import type { EntitlementStatus } from "../utils/billing-view";

const KEY_DEVICE = "billing.device";
const KEY_PASS = "billing.pass";
const KEY_STATUS = "billing.status";
const KEY_HAD_SUBSCRIPTION = "billing.had_subscription";
const KEY_INSTALL_MARKER = "billing.install_marker";
const KEY_REMINDERS = "billing.reminders";
const KEY_PLANS = "billing.plans";
const KEY_CHECKOUT = "billing.checkout";

export interface DeviceCredentials {
  id: string;
  secret: string;
}

/**
 * "Installed before the paid launch" (billing plan §2.3). Written once, on
 * the first launch that has this code, and never changed: whichever way the
 * grandfathering decision goes, the fact is on the phone to act on.
 */
export interface InstallMarker {
  /** Unix seconds of the launch that wrote the marker. */
  firstRunAt: number;
  installedBeforePaid: boolean;
}

export interface ReminderBookkeeping {
  /** Ids handed to the notification scheduler the last time; cancelled before the next schedule. */
  scheduled: string[];
  /** Ids of one-shot reminders already shown (a lapse is announced once). */
  shown: string[];
}

export interface PendingCheckout {
  id: string;
  plan: string;
  startedAt: number;
}

export interface CachedPlans {
  plans: PlanInfo[];
  trialDays: number;
  graceDays: number;
  lapsePolicy: "basic" | "off";
  consentDocVersion: string;
  providers: string[];
  fetchedAt: number;
}

async function readJson<T>(key: string): Promise<T | null> {
  try {
    const raw = await SecureStore.getItemAsync(key);
    return raw ? (JSON.parse(raw) as T) : null;
  } catch {
    return null;
  }
}

async function writeJson(key: string, value: unknown | null): Promise<void> {
  try {
    if (value === null || value === undefined) await SecureStore.deleteItemAsync(key);
    else await SecureStore.setItemAsync(key, JSON.stringify(value));
  } catch {
    // A write that fails leaves the previous value; the next refresh writes again.
  }
}

async function readString(key: string): Promise<string | null> {
  try {
    return await SecureStore.getItemAsync(key);
  } catch {
    return null;
  }
}

async function writeString(key: string, value: string | null): Promise<void> {
  try {
    if (value === null) await SecureStore.deleteItemAsync(key);
    else await SecureStore.setItemAsync(key, value);
  } catch {
    // see writeJson
  }
}

/**
 * Pure: the marker after a launch. An existing marker is never rewritten.
 * A phone with no marker but with evidence of an earlier install (the
 * onboarding was completed by a build without billing) was installed before
 * the paid launch whatever the switch says now; otherwise the switch decides:
 * a build with billing off is, by definition, before the paid launch.
 */
export function installMarkerAfterLaunch(
  existing: InstallMarker | null,
  input: { flagOn: boolean; priorInstall: boolean; nowSec: number },
): InstallMarker {
  if (existing) return existing;
  return { firstRunAt: input.nowSec, installedBeforePaid: input.priorInstall || !input.flagOn };
}

export const billingStore = {
  device: () => readJson<DeviceCredentials>(KEY_DEVICE),
  saveDevice: (d: DeviceCredentials | null) => writeJson(KEY_DEVICE, d),

  pass: () => readString(KEY_PASS),
  savePass: (token: string | null) => writeString(KEY_PASS, token),

  status: () => readJson<EntitlementStatus>(KEY_STATUS),
  saveStatus: (s: EntitlementStatus | null) => writeJson(KEY_STATUS, s),

  hadSubscription: async () => (await readString(KEY_HAD_SUBSCRIPTION)) === "1",
  markHadSubscription: () => writeString(KEY_HAD_SUBSCRIPTION, "1"),

  installMarker: () => readJson<InstallMarker>(KEY_INSTALL_MARKER),
  saveInstallMarker: (m: InstallMarker) => writeJson(KEY_INSTALL_MARKER, m),

  reminders: async (): Promise<ReminderBookkeeping> =>
    (await readJson<ReminderBookkeeping>(KEY_REMINDERS)) ?? { scheduled: [], shown: [] },
  saveReminders: (r: ReminderBookkeeping) => writeJson(KEY_REMINDERS, r),

  plans: () => readJson<CachedPlans>(KEY_PLANS),
  savePlans: (p: CachedPlans | null) => writeJson(KEY_PLANS, p),

  checkout: () => readJson<PendingCheckout>(KEY_CHECKOUT),
  saveCheckout: (c: PendingCheckout | null) => writeJson(KEY_CHECKOUT, c),
};
