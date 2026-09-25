import type { TFunction } from "i18next";
import type { CheckLevel, HistoryFilter, ShieldKind, ShieldSource, SmsAlertItem } from "./history-model";

/**
 * i18n keys for the History tab.
 *
 * Full literal keys, not `mobile.history.filter.${f}`: the Record types make
 * TypeScript fail when a filter, kind or source gains no copy, and
 * scripts/check-mobile-i18n.py can only verify literal keys — so a missing
 * translation fails CI instead of showing a dotted key on screen.
 */

export const FILTER_KEYS: Record<HistoryFilter, string> = {
  all: "mobile.history.filter.all",
  blocked: "mobile.history.filter.blocked",
  warned: "mobile.history.filter.warned",
  checked: "mobile.history.filter.checked",
  sms: "mobile.history.filter.sms",
};

/** One line under the chips saying exactly what the filter shows — the counters' definition, in words. */
export const FILTER_HINT_KEYS: Record<HistoryFilter, string> = {
  all: "mobile.history.filter_hint.all",
  blocked: "mobile.history.filter_hint.blocked",
  warned: "mobile.history.filter_hint.warned",
  checked: "mobile.history.filter_hint.checked",
  sms: "mobile.history.filter_hint.sms",
};

/**
 * The SMS chip's hint where the automatic SMS check exists (RuStore build):
 * the chip then lists its warnings too, not only messages checked by hand.
 */
export const SMS_AUTO_FILTER_HINT_KEY = "mobile.history.filter_hint.sms_auto";

/** Who warned about a flagged SMS: the automatic check, by the name its home card has. */
export const SMS_ALERT_SOURCE_KEY = "mobile.history.source.sms_auto";

/** A flagged SMS row's "how": nobody handed it over — "Checked automatically". */
export const SMS_ALERT_ROW_META_KEY = "mobile.history.sms_alert.checked_auto";

/**
 * The Warned chip's hint where the automatic SMS check exists: that chip then
 * lists its warnings too (history-model.ts).
 */
export const WARNED_SMS_AUTO_FILTER_HINT_KEY = "mobile.history.filter_hint.warned_sms_auto";

/**
 * The hint under the chips. Where SMS warnings can exist (the RuStore build,
 * or warnings already stored), the SMS and Warned chips list them too, and
 * their hints say so.
 */
export function filterHintKey(filter: HistoryFilter, smsWarnings: boolean): string {
  if (smsWarnings && filter === "sms") return SMS_AUTO_FILTER_HINT_KEY;
  if (smsWarnings && filter === "warned") return WARNED_SMS_AUTO_FILTER_HINT_KEY;
  return FILTER_HINT_KEYS[filter];
}

/** "SMS from 900", or "SMS from an unknown sender" — the row and sheet title of a flagged SMS. */
export function smsAlertTitle(item: Pick<SmsAlertItem, "sender">, t: TFunction): string {
  return item.sender
    ? t("mobile.history.sms_alert.row_title", { sender: item.sender })
    : t("mobile.history.sms_alert.row_title_unknown");
}

/** What happened, in plain words. "warned" is never worded as a block. */
export const SHIELD_KIND_KEYS: Record<ShieldKind, string> = {
  blocked: "mobile.history.shield_blocked",
  warned: "mobile.history.shield_warned",
  allowed: "mobile.history.shield_allowed",
};

/** Which shield acted, by the name its card has on the home screen. */
export const SHIELD_SOURCE_KEYS: Record<ShieldSource, string> = {
  dns: "mobile.history.source.dns",
  link: "mobile.history.source.link",
};

export const CHECK_LEVEL_KEYS: Record<CheckLevel, string> = {
  safe: "mobile.result.verdict_safe",
  caution: "mobile.result.verdict_caution",
  dangerous: "mobile.result.verdict_dangerous",
};
