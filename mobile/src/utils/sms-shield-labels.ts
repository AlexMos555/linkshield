import type { TFunction } from "i18next";
import type { SmsShieldAction, SmsShieldView } from "./sms-shield-view";

/**
 * i18n keys for the automatic SMS check, shared by its home card and its
 * Settings row so both say the same thing about the same state.
 *
 * Full literal keys, not `…state_${kind}`: scripts/check-mobile-i18n.py can
 * only verify literal keys, and the Record type fails the build when an
 * action gains no words.
 */

export function smsStateCopy(view: SmsShieldView, t: TFunction): string {
  switch (view.kind) {
    case "on":
      return t("mobile.shield.sms_auto.state_on", { count: view.checked });
    case "setup":
      return view.why === "paused" ? t("mobile.shield.sms_auto.state_paused")
        : view.why === "refused" ? t("mobile.shield.sms_auto.state_refused")
        : t("mobile.shield.sms_auto.state_setup");
    case "restricted":
      return t("mobile.shield.sms_auto.state_restricted");
    case "blocked":
      return t("mobile.shield.sms_auto.state_blocked");
    case "permission_off":
      return t("mobile.shield.sms_auto.state_permission_off");
    case "notifications":
      return t("mobile.shield.sms_auto.state_notifications");
    case "battery":
      return t("mobile.shield.sms_auto.state_battery");
    case "unsupported":
      return "";
  }
}

/** The fix's own words; "enable" has none — the card's button and the switch say it. */
export const SMS_ACTION_KEYS: Record<Exclude<SmsShieldAction, "enable" | null>, string> = {
  open_app_settings: "mobile.shield.sms_auto.action_app_settings",
  request_sms: "mobile.shield.sms_auto.action_allow_sms",
  open_notifications: "mobile.shield.sms_auto.action_notifications",
};

/**
 * Steps that do not fit in the card's narrow text column: said in full, full
 * width, under the card — a person follows them in another app, from memory.
 */
export function smsFixStepsKey(view: SmsShieldView): string | null {
  switch (view.kind) {
    case "restricted":
      return "mobile.shield.sms_auto.restricted_steps";
    case "blocked":
      return "mobile.shield.sms_auto.blocked_steps";
    case "battery":
      return "mobile.shield.sms_auto.battery_steps";
    default:
      return null;
  }
}

/** The action that gets its own button row, or null ("enable" is the card's button). */
export function smsFixRow(action: SmsShieldAction): Exclude<SmsShieldAction, "enable" | null> | null {
  return action === null || action === "enable" ? null : action;
}
