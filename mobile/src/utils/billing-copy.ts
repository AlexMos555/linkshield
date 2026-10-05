/**
 * Small pure helpers between the billing facts and the words on screen:
 * plan names, the operator's failure reasons, the client's error codes, and
 * the Russian phone number the checkout screen takes.
 */
import { PLAN_CODES } from "./billing-view";

/** i18next's `t`, or anything shaped like it. */
type Translate = (key: string) => string;

/** "3 телефона" for a plan code; the code itself when the server adds one this build does not know. */
export function planLabel(t: Translate, code: string | null): string {
  if (!code) return "";
  return (PLAN_CODES as readonly string[]).includes(code) ? t(`mobile.billing.plan_${code}`) : code;
}

const FAILURE_REASONS = new Set(["no_money", "payments_banned", "passport", "corporate", "user_declined", "timeout", "other"]);

/** The i18n key for an operator's failure reason (checkout `failure_reason`); unknown reasons read as "other". */
export function failureCopyKey(reason: string | null | undefined): string {
  return `mobile.billing.fail_${reason && FAILURE_REASONS.has(reason) ? reason : "other"}`;
}

/**
 * The i18n key for a billing error code, or null when the generic line with
 * the code is all there is to say. `keys_missing` / `pass_*` / `native_missing`
 * are the app's own; the rest are the server's machine words.
 */
export function errorCopyKey(code: string | null | undefined): string | null {
  switch (code) {
    case null:
    case undefined:
      return null;
    case "network":
    case "timeout":
      return "mobile.billing.error_network";
    case "keys_missing":
      return "mobile.billing.keys_missing";
    case "native_missing":
      return "mobile.billing.native_missing";
    case "already_subscribed":
      return "mobile.billing.checkout_already";
    case "provider_unavailable":
    case "provider_error":
    case "not_configured":
      return "mobile.billing.checkout_provider_unavailable";
    case "consent_version_stale":
      return "mobile.billing.checkout_stale_consent";
    case "no_free_seats":
      return "mobile.billing.add_no_seats";
    case "not_owner":
      return "mobile.billing.devices_not_payer";
    case "code_format":
      return "mobile.billing.join_format";
    case "code_invalid":
      return "mobile.billing.join_invalid";
    default:
      return null;
  }
}

/**
 * A Russian mobile number as E.164 (`+79XXXXXXXXX`), from whatever a person
 * types: `8 915 123-45-67`, `9151234567`, `+7 (915) 123 45 67`. Null when it
 * is not one — the screen then says the format it wants, and nothing is sent.
 */
export function normalizeRuPhone(raw: string): string | null {
  const digits = raw.replace(/\D/g, "");
  const national = digits.length === 11 && (digits.startsWith("7") || digits.startsWith("8")) ? digits.slice(1)
    : digits.length === 10 ? digits
    : null;
  if (!national || !/^9\d{9}$/.test(national)) return null;
  return `+7${national}`;
}

/** `+7 915 ***-**-67` — the number as the consent screen shows it back, and as the SMS screen names it. */
export function maskPhone(e164: string): string {
  const m = /^\+7(\d{3})(\d{3})(\d{2})(\d{2})$/.exec(e164);
  if (!m) return e164;
  return `+7 ${m[1]} ***-**-${m[4]}`;
}

/** `+7 915 123-45-67` — the number as the checkout screen echoes it in full. */
export function formatPhone(e164: string): string {
  const m = /^\+7(\d{3})(\d{3})(\d{2})(\d{2})$/.exec(e164);
  if (!m) return e164;
  return `+7 ${m[1]} ${m[2]}-${m[3]}-${m[4]}`;
}
