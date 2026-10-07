/**
 * The decisions behind /signup and /auth/callback, kept free of React and
 * Supabase so they can be table-tested (scripts/test-signup-flow.mjs).
 *
 * /signup sends a one-time code (Supabase `signInWithOtp`) and then lets the
 * person TYPE the 6-digit code from the email — the same thing the app does.
 * The magic-link click still works for the recovery / email-change mails, and
 * a link that fails lands back on /signup with a stable `?error=` code that
 * this module turns into a sentence in the reader's language.
 *
 * Why a code and not only a link: the code works on whichever device the
 * email is read, while a PKCE magic link only works in the browser that asked
 * for it (the verifier is a cookie there). A person who starts on the laptop
 * and opens the mail on the phone used to get a dead link; now she reads the
 * six digits off the phone and types them on the laptop.
 */

/** Must match mobile/src/services/auth.ts OTP_CODE_LEN and Supabase mailer_otp_length. */
export const OTP_CODE_LEN = 6;

/**
 * Seconds before «Отправить ещё раз» re-enables. Supabase refuses a second
 * code to the same address inside 60 s (smtp_max_frequency); 62 s keeps the
 * button from deterministically failing the moment it lights up. Same value
 * as the app.
 */
export const RESEND_COOLDOWN_S = 62;

/**
 * GoTrue issues a different token kind to a brand-new address (signup
 * confirmation) than to an existing one (magic link); current servers accept
 * both under "email", older ones only under "signup". Try in this order and
 * fall back only when the server rejected the TOKEN — never on a network error.
 */
export const OTP_VERIFY_TYPES = ["email", "signup"] as const;
export type OtpVerifyType = (typeof OTP_VERIFY_TYPES)[number];

export interface AuthFailure {
  readonly status?: number;
  readonly code?: string;
}

/** Keys in the Signup i18n namespace for a failed code REQUEST. */
export type SendErrorKey = "error_rate_limited" | "error_send_failed";

/**
 * Supabase reports throttling as HTTP 429 or an `over_*_rate_limit` code; that
 * one deserves "wait a few minutes". Everything else gets the generic "try
 * later" — the raw provider message ("Error sending magic link email") is
 * English jargon that tells a person nothing they can act on.
 */
export function sendErrorKey(error: AuthFailure): SendErrorKey {
  if (isRateLimited(error)) return "error_rate_limited";
  return "error_send_failed";
}

/** Keys in the Signup i18n namespace for a failed code CHECK. */
export type VerifyErrorKey = "error_code_wrong" | "error_rate_limited" | "error_send_failed";

/**
 * GoTrue answers a wrong code AND an expired one with 403 `otp_expired`
 * ("Token has expired or is invalid"), so there is one honest message for
 * both: check the digits or ask for a new code. 429 means too many tries.
 */
export function verifyErrorKey(error: AuthFailure): VerifyErrorKey {
  if (isRateLimited(error)) return "error_rate_limited";
  if (isTokenRejected(error)) return "error_code_wrong";
  return "error_send_failed";
}

/** Only a rejected token is worth retrying under the other verify type. */
export function isTokenRejected(error: AuthFailure): boolean {
  return error.status === 400 || error.status === 401 || error.status === 403 || error.code === "otp_expired";
}

function isRateLimited(error: AuthFailure): boolean {
  return error.status === 429 || (error.code ?? "").includes("rate_limit");
}

/** Digits only, at most six — what the code input is allowed to hold. */
export function normalizeOtpInput(raw: string): string {
  return raw.replace(/\D/g, "").slice(0, OTP_CODE_LEN);
}

export function isCompleteOtpCode(value: string): boolean {
  return new RegExp(`^\\d{${OTP_CODE_LEN}}$`).test(value);
}

// ─── /auth/callback → /signup?error=… ─────────────────────────────

export type CallbackErrorCode = "otp_expired" | "missing_code" | "exchange_failed";

/**
 * What the callback can tell from the URL Supabase redirected to, BEFORE
 * exchanging anything. An expired or already-used link arrives as
 * `?error=access_denied&error_code=otp_expired&error_description=…` with no
 * `code`; a plain missing `code` is someone opening the URL by hand or a
 * mail scanner that stripped the query.
 */
export function callbackPrecheck(search: URLSearchParams): CallbackErrorCode | null {
  if (search.get("code")) return null;
  if (search.get("error_code") === "otp_expired") return "otp_expired";
  return "missing_code";
}

/** Keys in the Signup i18n namespace for a failed LINK, shown above the form. */
export type QueryErrorKey = "error_link_expired" | "error_link_failed";

export function queryErrorKey(value: string | null | undefined): QueryErrorKey | null {
  switch (value) {
    case "otp_expired":
      return "error_link_expired";
    case "missing_code":
    case "exchange_failed":
      return "error_link_failed";
    default:
      return null;
  }
}

/**
 * Where to send a failed link: the signup page in the LOCALE the person was
 * heading to, not the English apex. `nextPath` is the already-validated
 * same-origin `next` target ("/ru/pricing?plan=family", "/").
 */
export function signupErrorPath(
  nextPath: string,
  code: CallbackErrorCode,
  locales: readonly string[],
  defaultLocale: string,
): string {
  const first = nextPath.split("/")[1]?.split("?")[0] ?? "";
  const locale = locales.includes(first) ? first : defaultLocale;
  const prefix = locale === defaultLocale ? "" : `/${locale}`;
  return `${prefix}/signup?error=${code}`;
}
