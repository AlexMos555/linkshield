import type { CheckLevel, HistoryFilter, ShieldKind, ShieldSource } from "./history-model";

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
