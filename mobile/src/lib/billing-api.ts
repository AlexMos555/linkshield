/**
 * The phone's side of `/billing/v1` (billing plan A.6; api/billing/router.py).
 *
 * A device speaks for itself: `Authorization: Bearer <device_secret>` from
 * `POST /devices`, no e-mail, no password. A phone number crosses this file
 * exactly once — in the checkout body — and is never logged, never kept in an
 * error, never put in a URL. Every answer is the project envelope
 * `{success, data, error:{code,message}}`, mapped here to a `BillingResult`
 * so screens handle "no network" and "the server said no" as two different
 * things.
 *
 * Until the billing role is live the base URL points at a host that does not
 * answer; with the build switch off (config/billing.ts) nothing here is called.
 */
import Constants from "expo-constants";

import { billingApiBase } from "../config/billing";
import type { EntitlementStatus } from "../utils/billing-view";

export type BillingErrorKind = "network" | "timeout" | "api";

export interface BillingApiError {
  kind: BillingErrorKind;
  /** HTTP status; 0 when no answer came. */
  status: number;
  /** The server's machine word (`already_subscribed`, `code_invalid`, …), or `network` / `timeout` / `http_<status>`. */
  code: string;
  message: string;
}

export type BillingResult<T> = { data: T; error: null } | { data: null; error: BillingApiError };

// ── Answers (the `data` of each envelope) ──

export interface DeviceRegistration {
  device_id: string;
  /** Returned once; the server keeps only its hash. */
  device_secret: string;
  legacy_free: boolean;
}

export interface EntitlementAnswer {
  token: string;
  claims: Record<string, unknown>;
  status: EntitlementStatus;
}

export interface TrialAnswer extends EntitlementAnswer {
  trial: { started_at: number; ends_at: number };
}

export interface PlanInfo {
  code: string;
  seats: number;
  price_kopecks: number;
  price_rub: number;
  period: string;
}

export interface PlansAnswer {
  currency: string;
  plans: PlanInfo[];
  trial_days: number;
  grace_days: number;
  lapse_policy: "basic" | "off";
  consent_doc_version: string;
  providers: string[];
  billing_ru_enabled: boolean;
}

export interface CheckoutRequest {
  plan_code: string;
  provider: string;
  msisdn: string | null;
  consent_doc_version: string;
  consent_method: string;
}

export interface CheckoutStart {
  checkout_id: string;
  /** `await_sms` (the operator confirms by SMS), `redirect` (a page to open), `granted`. */
  kind: string;
  url: string | null;
  sdk_params: unknown;
  status: string;
  provider: string;
}

export interface CheckoutState {
  checkout_id: string;
  /** `pending` | `active` | `failed` | … (a subscription status). */
  status: string;
  plan: string | null;
  /** `no_money` | `payments_banned` | `passport` | `corporate` | `user_declined` | `timeout` | `other` | null. */
  failure_reason: string | null;
  period_end: number | null;
}

export interface CancelAnswer {
  status: string;
  period_end: number | null;
  cancel_requested_at: number | null;
}

export interface ClaimCodeAnswer {
  code: string;
  expires_at: number;
  qr_payload: string;
  install_url: string;
  seats_used: number;
  seats_total: number;
}

export interface ClaimAnswer {
  subscription_id: string;
  plan: string;
  seats_used: number;
  seats_total: number;
  period_end: number | null;
}

export interface SeatDevice {
  device_id: string;
  role: "owner" | "member";
  claimed_at: number;
  is_this_device: boolean;
}

export interface DevicesAnswer {
  subscription_id: string;
  plan: string;
  seats_total: number;
  seats_used: number;
  is_payer: boolean;
  devices: SeatDevice[];
}

// ── The client ──

export interface BillingApiOptions {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  appVersion?: string;
  timeoutMs?: number;
}

interface Call {
  method: "GET" | "POST" | "DELETE";
  body?: unknown;
  secret?: string;
  idempotencyKey?: string;
}

interface Envelope<T> {
  success?: boolean;
  data?: T;
  error?: { code?: string; message?: string } | null;
}

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_SECRET_LENGTH = 128;

function failure(kind: BillingErrorKind, status: number, code: string, message: string): BillingResult<never> {
  return { data: null, error: { kind, status, code, message } };
}

export function createBillingApi(opts: BillingApiOptions = {}) {
  const baseUrl = (opts.baseUrl ?? billingApiBase()).replace(/\/+$/, "");
  const fetchImpl = opts.fetchImpl ?? fetch;
  const appVersion = opts.appVersion ?? Constants.expoConfig?.version ?? "0.0.0";
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  async function call<T>(path: string, c: Call): Promise<BillingResult<T>> {
    if (c.secret !== undefined && (!c.secret || c.secret.length > MAX_SECRET_LENGTH)) {
      return failure("api", 401, "device_secret_missing", "no device secret on this phone");
    }
    const headers: Record<string, string> = {
      Accept: "application/json",
      "X-Client": "mobile",
      "X-Client-Version": appVersion,
    };
    if (c.body !== undefined) headers["Content-Type"] = "application/json";
    if (c.secret) headers.Authorization = `Bearer ${c.secret}`;
    if (c.idempotencyKey) headers["Idempotency-Key"] = c.idempotencyKey;

    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), timeoutMs);
    let response: Response;
    try {
      response = await fetchImpl(`${baseUrl}${path}`, {
        method: c.method,
        headers,
        body: c.body === undefined ? undefined : JSON.stringify(c.body),
        signal: abort.signal,
      });
    } catch {
      clearTimeout(timer);
      // No request detail in the error: the body may carry a phone number.
      return abort.signal.aborted
        ? failure("timeout", 0, "timeout", "the billing server did not answer in time")
        : failure("network", 0, "network", "could not reach the billing server");
    }
    clearTimeout(timer);
    let envelope: Envelope<T> | null = null;
    try {
      envelope = (await response.json()) as Envelope<T>;
    } catch {
      envelope = null;
    }
    if (response.ok && envelope && envelope.success === true && envelope.data !== undefined && envelope.data !== null) {
      return { data: envelope.data, error: null };
    }
    const code = envelope?.error?.code || `http_${response.status}`;
    const message = envelope?.error?.message || "";
    return failure("api", response.status, code, message);
  }

  return {
    baseUrl,

    registerDevice(body: { platform: "android" | "ios"; app_version: string | null; legacy_claim: boolean }) {
      return call<DeviceRegistration>("/billing/v1/devices", { method: "POST", body });
    },
    startTrial(secret: string, fingerprint: string) {
      return call<TrialAnswer>("/billing/v1/trial", { method: "POST", body: { fingerprint }, secret });
    },
    getEntitlement(secret: string) {
      return call<EntitlementAnswer>("/billing/v1/entitlement", { method: "GET", secret });
    },
    getPlans() {
      return call<PlansAnswer>("/billing/v1/plans", { method: "GET" });
    },
    startCheckout(secret: string, body: CheckoutRequest, idempotencyKey: string) {
      return call<CheckoutStart>("/billing/v1/checkout", { method: "POST", body, secret, idempotencyKey });
    },
    getCheckout(secret: string, checkoutId: string) {
      return call<CheckoutState>(`/billing/v1/checkout/${encodeURIComponent(checkoutId)}`, { method: "GET", secret });
    },
    cancelSubscription(secret: string) {
      return call<CancelAnswer>("/billing/v1/subscription/cancel", { method: "POST", secret });
    },
    createClaimCode(secret: string, idempotencyKey: string) {
      return call<ClaimCodeAnswer>("/billing/v1/subscription/codes", { method: "POST", secret, idempotencyKey });
    },
    claimSeat(secret: string, code: string) {
      return call<ClaimAnswer>("/billing/v1/claim", { method: "POST", body: { code }, secret });
    },
    listDevices(secret: string) {
      return call<DevicesAnswer>("/billing/v1/subscription/devices", { method: "GET", secret });
    },
    removeSeat(secret: string, deviceId: string) {
      return call<{ removed: string }>(`/billing/v1/subscription/seats/${encodeURIComponent(deviceId)}`, { method: "DELETE", secret });
    },
  };
}

export type BillingApi = ReturnType<typeof createBillingApi>;
