/**
 * Pure rules behind the signed-in session and the account screen, kept free
 * of React and expo so mobile/scripts/test-account-session.mjs can pin them.
 *
 *   • when the access token must be refreshed (before it expires, not after
 *     the first 401);
 *   • one refresh at a time — GoTrue rotates the refresh token on every use,
 *     so two parallel refreshes would make the second one present an already
 *     spent token and sign the person out;
 *   • what a device registration / heartbeat answer means for the app;
 *   • how a plan, a source and a device are labelled.
 */

/** Refresh when fewer than this many seconds are left on the access token. */
export const REFRESH_WINDOW_SECONDS = 120;

/** Heartbeat the device at most this often (app start / return to foreground). */
export const HEARTBEAT_INTERVAL_MS = 6 * 60 * 60 * 1000;

/** True when the token expiring at `expiresAt` (epoch s) should be refreshed now. */
export function needsRefresh(
  expiresAt: number,
  nowSeconds: number,
  windowSeconds: number = REFRESH_WINDOW_SECONDS,
): boolean {
  if (!Number.isFinite(expiresAt) || expiresAt <= 0) return true;
  return expiresAt - nowSeconds <= windowSeconds;
}

/** Milliseconds until the proactive refresh should run (0 = now). */
export function refreshDelayMs(
  expiresAt: number,
  nowSeconds: number,
  windowSeconds: number = REFRESH_WINDOW_SECONDS,
): number {
  if (needsRefresh(expiresAt, nowSeconds, windowSeconds)) return 0;
  return (expiresAt - windowSeconds - nowSeconds) * 1000;
}

/**
 * Wrap an async function so concurrent callers share ONE in-flight run.
 * The next call after it settles starts a new run.
 */
export function singleFlight<T>(fn: () => Promise<T>): () => Promise<T> {
  let inFlight: Promise<T> | null = null;
  return () => {
    if (!inFlight) {
      inFlight = fn().finally(() => {
        inFlight = null;
      });
    }
    return inFlight;
  };
}

export function heartbeatDue(lastAtMs: number | null, nowMs: number): boolean {
  if (lastAtMs === null || !Number.isFinite(lastAtMs) || lastAtMs > nowMs) return true;
  return nowMs - lastAtMs >= HEARTBEAT_INTERVAL_MS;
}

export interface ApiFailureLike {
  readonly kind?: string;
  readonly status?: number;
  readonly code?: string;
}

/**
 * What a failed account call means:
 *   revoked    — this install was unlinked: sign out here, make a new install id
 *   limit      — no free device seat: offer "unlink one" / "add a device"
 *   signed_out — the session is gone (401 after a refresh attempt)
 *   retry      — offline / server trouble: keep everything, try later
 */
export type AccountFailure = "revoked" | "limit" | "signed_out" | "retry";

export function accountFailure(error: ApiFailureLike | null | undefined): AccountFailure {
  if (!error) return "retry";
  if (error.code === "device_revoked") return "revoked";
  if (error.code === "device_limit_reached") return "limit";
  if (error.kind === "unauthorized" || error.status === 401) return "signed_out";
  return "retry";
}

const KNOWN_PLANS = new Set(["free", "personal", "family", "business"]);
const KNOWN_SOURCES = new Set([
  "stripe", "google_play", "app_store", "rustore", "operator_ru", "promo", "partner",
]);
const KNOWN_PLATFORMS = new Set(["android", "ios", "extension", "web"]);

/** i18n key of the plan name. Unknown paid plans read as "Paid plan". */
export function planKey(plan: string | null | undefined): string {
  if (plan && KNOWN_PLANS.has(plan)) return `mobile.account.plan_${plan}`;
  return "mobile.account.plan_paid";
}

/** i18n key of "where it was paid", or null for the free plan. */
export function sourceKey(source: string | null | undefined): string | null {
  if (!source) return null;
  return KNOWN_SOURCES.has(source) ? `mobile.account.source_${source}` : "mobile.account.source_other";
}

/**
 * i18n key of the plan's status line. `{{date}}` is filled by the caller
 * when there is an end date; past_due always asks to fix the payment.
 */
export function statusKey(status: string | null | undefined, hasEnd: boolean): string | null {
  switch (status) {
    case "trialing":
      return hasEnd ? "mobile.account.status_trial_until" : "mobile.account.status_trial";
    case "past_due":
      return "mobile.account.status_past_due";
    case "active":
      return hasEnd ? "mobile.account.status_paid_until" : "mobile.account.status_active";
    default:
      return null;
  }
}

export function platformKey(platform: string | null | undefined): string {
  return KNOWN_PLATFORMS.has(platform ?? "")
    ? `mobile.account.platform_${platform}`
    : "mobile.account.platform_web";
}

/**
 * The name this phone registers with: the model ("Pixel 8"), else the name
 * the owner gave the phone, else nothing (the list then shows the platform).
 */
export function defaultDeviceName(model: unknown, deviceName: unknown): string | null {
  for (const v of [model, deviceName]) {
    if (typeof v === "string") {
      const t = v.replace(/\s+/g, " ").trim();
      if (t) return t.slice(0, 80);
    }
  }
  return null;
}

/** RFC 4122 v4 UUID from 16 random bytes (the caller supplies the randomness). */
export function uuidFromBytes(b: Uint8Array): string {
  if (b.length < 16) throw new Error("need 16 random bytes");
  const x = Uint8Array.from(b.slice(0, 16));
  x[6] = (x[6] & 0x0f) | 0x40;
  x[8] = (x[8] & 0x3f) | 0x80;
  const hex = Array.from(x, (v) => v.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
