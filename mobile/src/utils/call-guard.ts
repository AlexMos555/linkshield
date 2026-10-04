/**
 * The stop screen during and after a phone call — the pure part.
 *
 * Every phone scam ends with the same request: switch the protection off,
 * open this site, allow it, install this app. Cleanway cannot hear the call
 * and must not ask for the permissions that would (no READ_PHONE_STATE, no
 * call-screening role); it only knows, from the phone's audio mode, THAT a
 * call is going on and when the last one ended (CallState.kt). That is
 * enough to put a screen between the request and the action:
 *
 *   "You are on the phone. If you are asked to switch protection off, open
 *    a site or install an app — it's a scam. Hang up."
 *
 * with "hang up and keep protection" as the big button, and the original
 * action behind a deliberately slower path: "I understand, this is my call",
 * enabled only after a [COUNTDOWN_SECONDS] countdown.
 *
 * The screen applies for the whole call and for [AFTER_CALL_WINDOW_MS] after
 * it: "hang up, I'll call you back" is the standard move.
 *
 * Pure functions here (table-tested by scripts/test-call-guard.mjs); the
 * hook and the screen live in src/hooks/useCallState.ts and
 * src/components/call/.
 */

/** Mirror of the native CallStatePayload (structural, so this file has no native import). */
export interface CallSnapshot {
  inCall: boolean;
  ringing: boolean;
  callStartedAt: number;
  callEndedAt: number;
  windowEndsAt: number;
  guardActive: boolean;
}

/** The actions the stop screen stands in front of. "exclude_app" is the hook for the VPN-exclusion picker (#60). */
export type GuardedActionKind = "pause" | "allow" | "open_anyway" | "exclude_app";

/** Why the screen is up: a call is going on, or one ended less than 30 minutes ago. */
export type GuardReason = "in_call" | "after_call";

/** Same as CallState.AFTER_CALL_WINDOW_MS. */
export const AFTER_CALL_WINDOW_MS = 30 * 60_000;

/** The slow path: "I understand, this is my call" unlocks after this many seconds. */
export const COUNTDOWN_SECONDS = 5;

/**
 * Whether the stop screen applies right now, and why. Computed from the
 * times, not from the native `guardActive` flag: that flag was true when the
 * snapshot was taken, and the screen may be shown minutes later.
 * No snapshot (a build that cannot see calls) → never.
 */
export function guardReason(snapshot: CallSnapshot | null, now: number = Date.now()): GuardReason | null {
  if (!snapshot) return null;
  if (snapshot.inCall) return "in_call";
  if (snapshot.callEndedAt > 0) {
    const since = now - snapshot.callEndedAt;
    if (since >= 0 && since < AFTER_CALL_WINDOW_MS) return "after_call";
  }
  return null;
}

/**
 * When the after-call window closes (epoch ms), so the screen can re-check
 * itself at that moment instead of polling; 0 when there is nothing to wait for.
 */
export function windowEndsAt(snapshot: CallSnapshot | null): number {
  if (!snapshot || snapshot.inCall || snapshot.callEndedAt <= 0) return 0;
  return snapshot.callEndedAt + AFTER_CALL_WINDOW_MS;
}

/**
 * Seconds left on the slow path's countdown, from when the screen opened.
 * Never negative; a clock stepped backwards only makes the wait longer, never
 * shorter — the delay is the point.
 */
export function countdownLeft(openedAt: number, now: number, seconds: number = COUNTDOWN_SECONDS): number {
  const elapsed = Math.floor((now - openedAt) / 1000);
  if (!Number.isFinite(elapsed) || elapsed < 0) return seconds;
  return Math.max(0, seconds - elapsed);
}

/** Merge a native event into the held snapshot: the event is the truth, an absent field keeps the old value. */
export function applyCallEvent(previous: CallSnapshot | null, event: Partial<CallSnapshot>): CallSnapshot {
  const base: CallSnapshot = previous ?? {
    inCall: false, ringing: false, callStartedAt: 0, callEndedAt: 0, windowEndsAt: 0, guardActive: false,
  };
  return {
    inCall: typeof event.inCall === "boolean" ? event.inCall : base.inCall,
    ringing: typeof event.ringing === "boolean" ? event.ringing : base.ringing,
    callStartedAt: typeof event.callStartedAt === "number" ? event.callStartedAt : base.callStartedAt,
    callEndedAt: typeof event.callEndedAt === "number" ? event.callEndedAt : base.callEndedAt,
    windowEndsAt: typeof event.windowEndsAt === "number" ? event.windowEndsAt : base.windowEndsAt,
    guardActive: typeof event.guardActive === "boolean" ? event.guardActive : base.guardActive,
  };
}
