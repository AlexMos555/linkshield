/**
 * Which translated sentence the sign-in screen shows for a failed GoTrue call.
 *
 * GoTrue's own messages are English-only ("Token has expired or is invalid",
 * "Error sending magic link email"); shown raw they put English in front of a
 * Russian-speaking user. These two tables are the whole mapping, kept free of
 * React and expo so mobile/scripts/test-auth-error-key.mjs can pin them.
 *
 * The input is the shape of services/auth.ts `AuthError` (`code` is GoTrue's
 * symbolic `error_code`, `status` the HTTP status, 0 for network failures),
 * but any object with those two fields will do — the screen passes the caught
 * error through `authFailure()` first so a non-AuthError throw is still mapped.
 */

export interface AuthFailureLike {
  readonly code?: string;
  readonly status?: number;
}

export type OtpSendErrorKey =
  | "mobile.auth.err_captcha"
  | "mobile.auth.err_captcha_update"
  | "mobile.auth.err_rate_limited"
  | "mobile.auth.err_network"
  | "mobile.auth.generic_error";

export type OtpVerifyErrorKey =
  | "mobile.auth.err_code_wrong"
  | "mobile.auth.err_rate_limited"
  | "mobile.auth.err_network"
  | "mobile.auth.generic_error";

/** `null`/non-error throws map to the generic sentence. */
export function authFailure(error: unknown): AuthFailureLike {
  if (typeof error === "object" && error !== null) {
    const { code, status } = error as { code?: unknown; status?: unknown };
    return {
      code: typeof code === "string" ? code : undefined,
      status: typeof status === "number" ? status : undefined,
    };
  }
  return {};
}

function isOffline(e: AuthFailureLike): boolean {
  return e.code === "network_error" || e.code === "timeout";
}

/**
 * 429 is a likely early-launch answer: GoTrue caps codes per address (one a
 * minute) and per project (emails per hour). `over_*_rate_limit` is the same
 * thing in the versioned error format.
 */
function isRateLimited(e: AuthFailureLike): boolean {
  return e.status === 429 || (e.code ?? "").includes("rate_limit");
}

/**
 * Failed `POST /auth/v1/otp`.
 *
 * `captchaRequired` is whether THIS build sends a captcha token. The Supabase
 * switch is server-side and project-wide: the instant it is flipped, every
 * installed build that sends no token gets 400 `captcha_failed`. Without the
 * split that reads as "Something went wrong" — an undiagnosable launch
 * incident instead of a one-line answer ("update the app").
 */
export function otpSendErrorKey(e: AuthFailureLike, captchaRequired: boolean): OtpSendErrorKey {
  if (e.code === "captcha_failed") {
    return captchaRequired ? "mobile.auth.err_captcha" : "mobile.auth.err_captcha_update";
  }
  if (isRateLimited(e)) return "mobile.auth.err_rate_limited";
  if (isOffline(e)) return "mobile.auth.err_network";
  return "mobile.auth.generic_error";
}

/**
 * Failed `POST /auth/v1/verify`.
 *
 * GoTrue answers a WRONG code and an EXPIRED code identically (403
 * `otp_expired`, "Token has expired or is invalid"), so one honest sentence
 * covers both: check the digits or request a new code. Too many attempts is
 * 429 and gets its own line, because "try again" would be wrong advice.
 */
export function otpVerifyErrorKey(e: AuthFailureLike): OtpVerifyErrorKey {
  if (isRateLimited(e)) return "mobile.auth.err_rate_limited";
  if (e.status === 400 || e.status === 401 || e.status === 403 || e.code === "otp_expired") {
    return "mobile.auth.err_code_wrong";
  }
  if (isOffline(e)) return "mobile.auth.err_network";
  return "mobile.auth.generic_error";
}
