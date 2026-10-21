import type { SmsShieldStatus } from "../../modules/cleanway-vpn/src/CleanwayVpn.types";

/**
 * What the "SMS messages" card (and its Settings row) may say about the
 * automatic SMS check, from the state the phone reports (smsShieldStatus()).
 *
 * The check counts as ON — green card, one more verified shield in the hero —
 * only when every link of the chain holds: Android delivers SMS to Cleanway
 * (permission granted), Cleanway listens (receiver enabled), a warning can
 * reach the person (notifications allowed) and Android does not hold the app
 * back (battery not restricted). Anything short of that is said out loud,
 * with the ONE thing that fixes it:
 *
 *   setup          off; "Turn on" (first time / paused / refused before)
 *   restricted     Android 15+ "restricted settings": the App info ⋮ steps,
 *                  AND "Turn on" to ask again once they are done. The app
 *                  cannot tell that they are: measured on Android 15
 *                  (2026-09-25), the state still read "restricted" after
 *                  "Allow restricted settings" — so the way forward stays open
 *   blocked        refused, and Android will not ask again (a second no,
 *                  "don't ask again", or an installer that never allowed SMS
 *                  for this app): App info → Permissions → SMS, and "Turn on"
 *   permission_off on, but SMS access is gone and Android can ask again
 *                  (revoked, or an unused-app reset)
 *   notifications  checking, but a warning would never show
 *   battery        Android may hold the check back
 *   on             verified
 *
 * Pure — no React Native — so scripts/test-sms-shield-ui.mjs runs it under
 * plain node. Only type imports, for the same reason as history-model.ts.
 */

export type SmsShieldView =
  | { kind: "unsupported" }
  | { kind: "setup"; why: "first" | "paused" | "refused" }
  | { kind: "restricted" }
  | { kind: "blocked" }
  | { kind: "permission_off" }
  | { kind: "notifications" }
  | { kind: "battery" }
  | { kind: "on"; checked: number };

export type SmsShieldViewKind = SmsShieldView["kind"];

/** The fix each state offers: one button, one screen. */
export type SmsShieldAction =
  | "enable"
  | "open_app_settings"
  | "request_sms"
  | "open_notifications"
  | null;

/**
 * A blocklist fetched within this counts as fresh. Past it the card says the
 * list is old: the refresh job fetches every 6 hours while the check is on,
 * so a day means something is holding it back (no network, battery limits).
 */
export const SMS_LIST_STALE_MS = 24 * 3_600_000;

export function smsShieldView(status: SmsShieldStatus): SmsShieldView {
  if (!status.supported) return { kind: "unsupported" };
  // Checked before "enabled": while Android restricts the permission, the
  // steps in App info come first, whatever the switch says.
  if (status.permission === "restricted_maybe") return { kind: "restricted" };
  // Refused and Android will not ask again: "Turn on" alone would do nothing.
  if (status.permission === "denied" && !status.canAskAgain) return { kind: "blocked" };
  if (!status.enabled) {
    const why = status.permission === "granted" ? "paused"
      : status.permission === "denied" ? "refused"
      : "first";
    return { kind: "setup", why };
  }
  if (status.permission !== "granted") return { kind: "permission_off" };
  if (!status.notificationsEnabled) return { kind: "notifications" };
  if (status.backgroundRestricted) return { kind: "battery" };
  return { kind: "on", checked: status.checkedCount };
}

/**
 * Does the card's own button say "Turn on"? For a switch that is off, and for
 * a restricted install: after "Allow restricted settings" the only step left
 * is asking again, and nothing tells the app that moment has come.
 */
export function offersTurnOn(view: SmsShieldView): boolean {
  return view.kind === "setup" || view.kind === "restricted" || view.kind === "blocked";
}

/** Counts toward the hero's verified shields. */
export function isSmsShieldVerified(view: SmsShieldView): boolean {
  return view.kind === "on";
}

/**
 * Is the check doing anything at all right now? True while it runs, even when
 * a warning could not reach the person — used for copy that must not say
 * "Cleanway does not read your SMS" to someone whose SMS it does read.
 */
export function isSmsShieldListening(view: SmsShieldView): boolean {
  return view.kind === "on" || view.kind === "notifications" || view.kind === "battery";
}

export function smsShieldAction(view: SmsShieldView): SmsShieldAction {
  switch (view.kind) {
    case "setup":
      return "enable";
    case "restricted":
    case "blocked":
    case "battery":
      return "open_app_settings";
    case "permission_off":
      return "request_sms";
    case "notifications":
      return "open_notifications";
    case "on":
    case "unsupported":
      return null;
  }
}

/** What the list line under the card says: nothing while fresh. */
export function smsListNote(view: SmsShieldView, listAgeMs: number | null): "missing" | "stale" | null {
  if (!isSmsShieldListening(view)) return null;
  if (listAgeMs === null) return "missing";
  return listAgeMs > SMS_LIST_STALE_MS ? "stale" : null;
}
