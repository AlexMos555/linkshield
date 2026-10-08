/**
 * Remote config — switches the server can flip for the on-phone checks
 * without a new APK. Today: the SMS text model (MessageModel.kt), which can be
 * turned off or made quieter if it starts raising false alarms in the field.
 *
 * Source: `remote_config` in GET /api/v1/mobile/version (api/routers/mobile.py,
 * env-driven), the same answer as the update check. The message check runs in
 * Kotlin, so the app hands the switches to the native module, which keeps them
 * in SharedPreferences (RemoteConfig.kt) and reads them on every message.
 *
 * Fail-safe, in this order: the last answer the phone stored → the defaults
 * (model on, shipped thresholds). A failed fetch or an answer without a valid
 * block never touches what is stored — an outage cannot flip a switch.
 *
 * Pure, no imports: mobile/scripts/test-remote-config.mjs runs it as is.
 */

export interface RemoteConfig {
  smsTextModelEnabled: boolean;
  /** In (0, 1), or null for the shipped threshold. The phone only ever raises a threshold with it. */
  smsTextModelCautionThresholdOverride: number | null;
  /** In (0, 1), or null for the shipped threshold. The phone only ever raises a threshold with it. */
  smsTextModelDangerThresholdOverride: number | null;
}

export const DEFAULT_REMOTE_CONFIG: RemoteConfig = Object.freeze({
  smsTextModelEnabled: true,
  smsTextModelCautionThresholdOverride: null,
  smsTextModelDangerThresholdOverride: null,
});

function threshold(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) && v > 0 && v < 1 ? v : null;
}

/**
 * The server's `remote_config` block, or null when it is absent or not a
 * config (no boolean `sms_text_model_enabled`) — the caller then leaves the
 * stored switches alone. A bad threshold is dropped on its own.
 */
export function parseRemoteConfig(raw: unknown): RemoteConfig | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const o = raw as Record<string, unknown>;
  if (typeof o.sms_text_model_enabled !== "boolean") return null;
  return {
    smsTextModelEnabled: o.sms_text_model_enabled,
    smsTextModelCautionThresholdOverride: threshold(o.sms_text_model_caution_threshold_override),
    smsTextModelDangerThresholdOverride: threshold(o.sms_text_model_danger_threshold_override),
  };
}

/** The JSON the native module stores — the server's snake_case keys, which RemoteConfig.kt reads. */
export function remoteConfigWire(c: RemoteConfig): string {
  return JSON.stringify({
    sms_text_model_enabled: c.smsTextModelEnabled,
    sms_text_model_caution_threshold_override: c.smsTextModelCautionThresholdOverride,
    sms_text_model_danger_threshold_override: c.smsTextModelDangerThresholdOverride,
  });
}

// ── when to ask the server ────────────────────────────────────────────────

/** While the app stays open, ask again after this long (the update check's cadence). */
export const REFRESH_INTERVAL_MS = 20 * 60 * 60 * 1000;
/**
 * Never ask more often than this, whatever the trigger: a crash/launch loop,
 * or an endpoint that keeps failing, costs at most one request an hour.
 */
export const MIN_GAP_MS = 60 * 60 * 1000;

/** "start": the app was opened (the home screen mounted). "resume": it came back to the foreground. */
export type RefreshTrigger = "start" | "resume";

/**
 * Should the app ask the server now?
 *  - never within MIN_GAP_MS of the last attempt (success or not);
 *  - on app start, yes — so a switch flipped on the server reaches a phone at
 *    its next launch, not up to a day later;
 *  - on returning to the foreground, once the last success is REFRESH_INTERVAL_MS old.
 * A stamp in the future (the clock was ahead when it was written — common on
 * cheap phones booting without network) counts as stale, never as "recent",
 * or the check would be off until the clock caught up.
 */
export function refreshDue(
  trigger: RefreshTrigger,
  now: number,
  lastAttempt: number,
  lastSuccess: number,
): boolean {
  const usable = (t: number) => Number.isFinite(t) && t > 0 && t <= now;
  if (usable(lastAttempt) && now - lastAttempt < MIN_GAP_MS) return false;
  if (trigger === "start") return true;
  return !usable(lastSuccess) || now - lastSuccess >= REFRESH_INTERVAL_MS;
}

/** A stored epoch-ms stamp, or 0 when absent or unreadable. */
export function readStamp(raw: string | null | undefined): number {
  if (!raw) return 0;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
}
