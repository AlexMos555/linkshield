import type {
  MessageLegitShape,
  MessageVerdict,
} from "../../modules/cleanway-vpn/src/CleanwayVpn.types";
import type { AdviceKey, LinkVerdict, MessageCheckReason } from "./message-verdict";

/**
 * i18n keys for everything the message check can say.
 *
 * Full literal keys on purpose, not `mobile.message.reason.${code}`: the
 * Record types make TypeScript fail when the native side gains a code with no
 * copy, and scripts/check-mobile-i18n.py can only see literal keys — so a key
 * missing from the locale files fails CI instead of showing a dotted key to
 * someone's grandmother.
 */

/** There is deliberately no "safe": the calmest verdict says no signs were found. */
export const VERDICT_KEYS: Record<MessageVerdict, string> = {
  dangerous: "mobile.message.verdict.dangerous",
  caution: "mobile.message.verdict.caution",
  no_signals: "mobile.message.verdict.no_signals",
};

export const VERDICT_SUB_KEYS: Record<MessageVerdict, string> = {
  dangerous: "mobile.message.verdict_sub.dangerous",
  caution: "mobile.message.verdict_sub.caution",
  no_signals: "mobile.message.verdict_sub.no_signals",
};

/**
 * The headline instead of "no signs of fraud" while a link is still being
 * checked, or when one could not be checked at all.
 */
export const LINKS_HEADLINE_KEYS: Record<"checking" | "unchecked", { title: string; sub: string }> = {
  checking: { title: "mobile.message.verdict.checking_links", sub: "mobile.message.verdict_sub.checking_links" },
  unchecked: { title: "mobile.message.verdict.links_unchecked", sub: "mobile.message.verdict_sub.links_unchecked" },
};

export const REASON_KEYS: Record<MessageCheckReason, string> = {
  link_blocklisted: "mobile.message.reason.link_blocklisted",
  link_checked_dangerous: "mobile.message.reason.link_checked_dangerous",
  link_checked_caution: "mobile.message.reason.link_checked_caution",
  claims_organisation: "mobile.message.reason.claims_organisation",
  threat_or_urgency: "mobile.message.reason.threat_or_urgency",
  asks_to_confirm_data: "mobile.message.reason.asks_to_confirm_data",
  reward_bait: "mobile.message.reason.reward_bait",
  call_unknown_number: "mobile.message.reason.call_unknown_number",
  link_not_official: "mobile.message.reason.link_not_official",
  link_shortener: "mobile.message.reason.link_shortener",
  link_messenger: "mobile.message.reason.link_messenger",
  link_ip_address: "mobile.message.reason.link_ip_address",
  link_lookalike: "mobile.message.reason.link_lookalike",
  link_imitates_brand: "mobile.message.reason.link_imitates_brand",
  link_apk: "mobile.message.reason.link_apk",
  asks_for_code: "mobile.message.reason.asks_for_code",
  safe_account: "mobile.message.reason.safe_account",
  asks_for_payment: "mobile.message.reason.asks_for_payment",
  relative_in_trouble: "mobile.message.reason.relative_in_trouble",
  install_app: "mobile.message.reason.install_app",
  malware_lure: "mobile.message.reason.malware_lure",
  sms_transfer_command: "mobile.message.reason.sms_transfer_command",
  disguised_letters: "mobile.message.reason.disguised_letters",
  sender_personal_number: "mobile.message.reason.sender_personal_number",
  sender_mismatch: "mobile.message.reason.sender_mismatch",
};

/** Shown only next to "no signals": what the message most likely is, and the one rule that still applies. */
export const SHAPE_KEYS: Record<MessageLegitShape, string> = {
  login_code: "mobile.message.shape.login_code",
  payment_alert: "mobile.message.shape.payment_alert",
  pickup_code: "mobile.message.shape.pickup_code",
  public_alert: "mobile.message.shape.public_alert",
  safety_notice: "mobile.message.shape.safety_notice",
};

export const LINK_KEYS: Record<LinkVerdict, string> = {
  blocked: "mobile.message.link.blocked",
  allowed: "mobile.message.link.allowed",
  system: "mobile.message.link.system",
  shortener: "mobile.message.link.shortener",
  messenger: "mobile.message.link.messenger",
  checking: "mobile.message.link.checking",
  dangerous: "mobile.message.link.dangerous",
  caution: "mobile.message.link.caution",
  clean: "mobile.message.link.clean",
  not_checked: "mobile.message.link.not_checked",
  rate_limited: "mobile.message.link.rate_limited",
  offline: "mobile.message.link.offline",
  timeout: "mobile.message.link.timeout",
  failed: "mobile.message.link.failed",
};

export const ADVICE_KEYS: Record<AdviceKey, string> = {
  no_link: "mobile.message.advice.no_link",
  no_reply: "mobile.message.advice.no_reply",
  no_code: "mobile.message.advice.no_code",
  no_money: "mobile.message.advice.no_money",
  no_install: "mobile.message.advice.no_install",
  call_yourself: "mobile.message.advice.call_yourself",
  call_relative: "mobile.message.advice.call_relative",
  delete: "mobile.message.advice.delete",
};
