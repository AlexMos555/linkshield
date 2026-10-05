/**
 * The subscription on this phone (billing plan A.10) — one store the screens
 * read through useBilling(), and the actions behind their buttons.
 *
 * The order of truth: the signed device pass first (src/lib/entitlement.ts;
 * its clock rule keeps working offline), the server's status snapshot for
 * the details, and nothing else. Whatever the pass says is handed to the
 * native shield (setProtectionPass), which follows it on its own from then
 * on — the trial ending at 03:00 ends at 03:00 with the app closed.
 *
 * With the build switch off (config/billing.ts) boot() clears any pass the
 * shield may hold and returns: no network call, no screen, no change.
 */
import { AppState, Platform } from "react-native";
import Constants from "expo-constants";

import i18n from "../i18n";
import { billingEnabled, passPublicKeys, CONSENT_DOC_VERSION } from "../config/billing";
import { type BillingApi, type CheckoutState, type PlanInfo, createBillingApi } from "../lib/billing-api";
import { type LapsePolicy, type PassClaims, type ProtectionMode, PassInvalid, decodePass, verifyPass } from "../lib/entitlement";
import { type BillingView, type EntitlementStatus, billingView, effectiveMode } from "../utils/billing-view";
import { remindersFor } from "../utils/billing-reminders";
import { nativeProtectionMode, setProtectionPass, trialFingerprint } from "../../modules/cleanway-vpn";
import { getSetting } from "./database";
import { getInstallId, randomUuid } from "./install-id";
import { cancelReminders, scheduleReminders } from "./billing-notify";
import { type CachedPlans, type DeviceCredentials, type PendingCheckout, billingStore, installMarkerAfterLaunch } from "./billing-store";

export interface BillingState {
  enabled: boolean;
  /** The stored facts are loaded; before that every screen shows "loading". */
  ready: boolean;
  /** A request is in flight. */
  busy: boolean;
  view: BillingView;
  /** What the pass entitles this phone to right now. */
  mode: ProtectionMode;
  /** The server's policy after a lapse (from the pass, else from /plans, else basic). */
  lapsePolicy: LapsePolicy;
  status: EntitlementStatus | null;
  claims: PassClaims | null;
  hadSubscription: boolean;
  plans: CachedPlans | null;
  deviceId: string | null;
  /** The last failure: a server code, `network`, `timeout`, `pass_invalid`, `keys_missing`; null when none. */
  error: string | null;
  /** The native shield took the pass; false on a build that cannot; null until tried. */
  nativeApplied: boolean | null;
  checkout: PendingCheckout | null;
  /** The last time the server answered (unix seconds), null when never. */
  refreshedAt: number | null;
}

type Listener = () => void;

const now = (): number => Math.floor(Date.now() / 1000);
/** A foreground after this long since the last answer asks the server again. */
const REFRESH_AFTER_SEC = 15 * 60;

let api: BillingApi | null = null;
let device: DeviceCredentials | null = null;
let booted = false;
let bootPromise: Promise<void> | null = null;

const listeners = new Set<Listener>();

let state: BillingState = {
  enabled: billingEnabled(),
  ready: false,
  busy: false,
  view: { kind: "hidden" },
  mode: "full",
  lapsePolicy: "basic",
  status: null,
  claims: null,
  hadSubscription: false,
  plans: null,
  deviceId: null,
  error: null,
  nativeApplied: null,
  checkout: null,
  refreshedAt: null,
};

function set(patch: Partial<BillingState>): void {
  const next = { ...state, ...patch };
  const nowSec = now();
  state = {
    ...next,
    view: billingView({ enabled: next.enabled, status: next.status, claims: next.claims, hadSubscription: next.hadSubscription, nowSec }),
    mode: effectiveMode(next.claims, nowSec),
    lapsePolicy: next.claims?.lapse_policy ?? next.status?.lapse_policy ?? next.plans?.lapsePolicy ?? next.lapsePolicy,
  };
  listeners.forEach((l) => l());
}

function getApi(): BillingApi {
  if (!api) api = createBillingApi();
  return api;
}

// ── The pass → the shield ──

function handToShield(claims: PassClaims | null): void {
  const applied = setProtectionPass(claims ? JSON.stringify(claims) : null);
  set({ nativeApplied: applied });
}

// ── Reminders ──

async function syncReminders(): Promise<void> {
  const book = await billingStore.reminders();
  await cancelReminders(book.scheduled);
  const nowSec = now();
  const due = remindersFor(state.view, nowSec, new Set(book.shown));
  const scheduled = await scheduleReminders(due, (key) => i18n.t(key), nowSec);
  const shownNow = due.filter((r) => r.atSec <= nowSec && scheduled.includes(r.id)).map((r) => r.id);
  await billingStore.saveReminders({ scheduled: scheduled.filter((id) => !shownNow.includes(id)), shown: [...book.shown, ...shownNow] });
}

// ── Persisting an answer ──

async function applyEntitlement(answer: { token: string; status: EntitlementStatus }): Promise<boolean> {
  const keys = passPublicKeys();
  if (Object.keys(keys).length === 0) {
    // A build without the public key cannot trust any pass: keep the old one, show the status, say why.
    await billingStore.saveStatus(answer.status);
    set({ status: answer.status, error: "keys_missing", refreshedAt: now() });
    return false;
  }
  let claims: PassClaims;
  try {
    claims = verifyPass(answer.token, keys, now());
  } catch (e) {
    await billingStore.saveStatus(answer.status);
    set({ status: answer.status, error: e instanceof PassInvalid ? `pass_${e.reason}` : "pass_invalid", refreshedAt: now() });
    return false;
  }
  const paid = answer.status.subscription !== null && answer.status.subscription.status !== "pending";
  if (paid && !state.hadSubscription) await billingStore.markHadSubscription();
  await Promise.all([billingStore.savePass(answer.token), billingStore.saveStatus(answer.status)]);
  set({ claims, status: answer.status, hadSubscription: state.hadSubscription || paid, error: null, refreshedAt: now() });
  handToShield(claims);
  await syncReminders();
  return true;
}

// ── Device ──

async function priorInstallEvidence(): Promise<boolean> {
  try {
    return (await getSetting("onboarding_done")) === "true";
  } catch {
    return false;
  }
}

async function ensureDevice(): Promise<DeviceCredentials | null> {
  if (device) return device;
  const stored = await billingStore.device();
  if (stored) {
    device = stored;
    set({ deviceId: stored.id });
    return stored;
  }
  const marker = await billingStore.installMarker();
  const { data, error } = await getApi().registerDevice({
    platform: Platform.OS === "ios" ? "ios" : "android",
    app_version: Constants.expoConfig?.version ?? null,
    legacy_claim: marker?.installedBeforePaid ?? false,
  });
  if (!data) {
    set({ error: error.code });
    return null;
  }
  device = { id: data.device_id, secret: data.device_secret };
  await billingStore.saveDevice(device);
  set({ deviceId: device.id, error: null });
  return device;
}

async function fingerprint(): Promise<string> {
  return trialFingerprint() ?? (await getInstallId()) ?? randomUuid();
}

/** A phone with no entitlement yet gets its trial — no number, no consent, by itself (billing plan §2.2). */
async function trialIfDue(secret: string, status: EntitlementStatus): Promise<boolean> {
  const due = status.source === "none" && !status.trial_used && status.subscription === null;
  if (!due) return false;
  const { data, error } = await getApi().startTrial(secret, await fingerprint());
  if (!data) {
    // `trial_already_used`, `already_subscribed`: the entitlement above already says so.
    set({ error: error.code });
    return false;
  }
  await applyEntitlement(data);
  return true;
}

// ── Public actions ──

async function refresh(): Promise<void> {
  if (!state.enabled || state.busy) return;
  set({ busy: true });
  try {
    const d = await ensureDevice();
    if (!d) return;
    const { data, error } = await getApi().getEntitlement(d.secret);
    if (!data) {
      if (error.status === 401) {
        // The server no longer knows this device (a wiped billing database in dev, a revoked secret): start over.
        device = null;
        await billingStore.saveDevice(null);
      }
      set({ error: error.code });
      return;
    }
    if (!(await trialIfDue(d.secret, data.status))) await applyEntitlement(data);
  } finally {
    set({ busy: false });
  }
}

async function loadPlans(): Promise<CachedPlans | null> {
  if (!state.enabled) return null;
  const { data, error } = await getApi().getPlans();
  if (!data) {
    set({ error: error.code });
    return state.plans;
  }
  const cached: CachedPlans = {
    plans: data.plans, trialDays: data.trial_days, graceDays: data.grace_days, lapsePolicy: data.lapse_policy,
    consentDocVersion: data.consent_doc_version, providers: data.providers, fetchedAt: now(),
  };
  await billingStore.savePlans(cached);
  set({ plans: cached, error: null });
  return cached;
}

/** Starts a checkout; the answer says how the operator confirms (`await_sms` with the Fake and MIXPLAT providers). */
async function buy(planCode: string, msisdn: string, provider: string) {
  const d = await ensureDevice();
  if (!d) return { data: null, error: { kind: "api" as const, status: 0, code: state.error ?? "device", message: "" } };
  const result = await getApi().startCheckout(d.secret, {
    plan_code: planCode, provider, msisdn, consent_doc_version: state.plans?.consentDocVersion ?? CONSENT_DOC_VERSION, consent_method: "app_button",
  }, randomUuid());
  if (result.data) {
    const checkout = { id: result.data.checkout_id, plan: planCode, startedAt: now() };
    await billingStore.saveCheckout(checkout);
    set({ checkout, error: null });
  } else {
    set({ error: result.error.code });
  }
  return result;
}

/** One poll of the pending checkout (the SMS screen asks every few seconds). */
async function pollCheckout(): Promise<CheckoutState | null> {
  const pending = state.checkout;
  const d = device ?? (await billingStore.device());
  if (!pending || !d) return null;
  const { data } = await getApi().getCheckout(d.secret, pending.id);
  if (!data) return null;
  if (data.status !== "pending") {
    await billingStore.saveCheckout(null);
    set({ checkout: null });
    if (data.status === "active") await refresh();
  }
  return data;
}

async function forgetCheckout(): Promise<void> {
  await billingStore.saveCheckout(null);
  set({ checkout: null });
}

async function cancel() {
  const d = await ensureDevice();
  if (!d) return { data: null, error: { kind: "api" as const, status: 0, code: state.error ?? "device", message: "" } };
  const result = await getApi().cancelSubscription(d.secret);
  if (result.data) await refresh();
  else set({ error: result.error.code });
  return result;
}

async function createClaimCode() {
  const d = await ensureDevice();
  if (!d) return { data: null, error: { kind: "api" as const, status: 0, code: state.error ?? "device", message: "" } };
  return getApi().createClaimCode(d.secret, randomUuid());
}

async function claim(code: string) {
  const d = await ensureDevice();
  if (!d) return { data: null, error: { kind: "api" as const, status: 0, code: state.error ?? "device", message: "" } };
  const result = await getApi().claimSeat(d.secret, code);
  if (result.data) await refresh();
  return result;
}

async function listDevices() {
  const d = await ensureDevice();
  if (!d) return { data: null, error: { kind: "api" as const, status: 0, code: state.error ?? "device", message: "" } };
  return getApi().listDevices(d.secret);
}

async function removeSeat(deviceId: string) {
  const d = await ensureDevice();
  if (!d) return { data: null, error: { kind: "api" as const, status: 0, code: state.error ?? "device", message: "" } };
  const result = await getApi().removeSeat(d.secret, deviceId);
  if (result.data) await refresh();
  return result;
}

/** The screens' clock: re-derive the view from the same facts at a new "now" (a focus, a minute passing). */
function recompute(): void {
  set({});
}

async function boot(): Promise<void> {
  if (bootPromise) return bootPromise;
  bootPromise = (async () => {
    booted = true;
    if (!state.enabled) {
      // The switch is off: make sure the shield holds no pass from an earlier build, and stop.
      if (nativeProtectionMode() !== null && nativeProtectionMode() !== "full") setProtectionPass(null);
      set({ ready: true });
      return;
    }
    const [storedDevice, token, status, hadSubscription, plans, checkout, marker] = await Promise.all([
      billingStore.device(), billingStore.pass(), billingStore.status(), billingStore.hadSubscription(),
      billingStore.plans(), billingStore.checkout(), billingStore.installMarker(),
    ]);
    if (!marker) {
      await billingStore.saveInstallMarker(
        installMarkerAfterLaunch(null, { flagOn: true, priorInstall: await priorInstallEvidence(), nowSec: now() }),
      );
    }
    device = storedDevice;
    let claims: PassClaims | null = null;
    if (token) {
      try {
        claims = decodePass(token).claims;
      } catch {
        await billingStore.savePass(null);
      }
    }
    set({ ready: true, claims, status, hadSubscription, plans, checkout, deviceId: storedDevice?.id ?? null });
    if (claims) handToShield(claims);
    void refresh();
    AppState.addEventListener("change", (s) => {
      if (s !== "active") return;
      recompute();
      if (!state.refreshedAt || now() - state.refreshedAt > REFRESH_AFTER_SEC) void refresh();
    });
  })();
  return bootPromise;
}

export const billing = {
  getState: (): BillingState => state,
  subscribe(listener: Listener): () => void {
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  },
  boot,
  refresh,
  recompute,
  loadPlans,
  buy,
  pollCheckout,
  forgetCheckout,
  cancel,
  createClaimCode,
  claim,
  listDevices,
  removeSeat,
  /** The plan catalogue entry for [code], from the last /plans answer. */
  plan(code: string | null): PlanInfo | null {
    return state.plans?.plans.find((p) => p.code === code) ?? null;
  },
  /** For tests and the boot gate. */
  isBooted: (): boolean => booted,
};
