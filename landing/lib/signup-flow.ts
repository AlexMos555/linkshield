/**
 * The decisions behind /signup and /auth/callback, kept free of React and
 * Supabase so they can be table-tested (scripts/test-signup-flow.mjs).
 *
 * /signup sends a one-time code (Supabase `signInWithOtp`) and then lets the
 * person TYPE the code from the email — the same thing the app does.
 * The magic-link click still works for the recovery / email-change mails, and
 * a link that fails lands back on /signup with a stable `?error=` code that
 * this module turns into a sentence in the reader's language.
 *
 * Why a code and not only a link: the code works on whichever device the
 * email is read, while a PKCE magic link only works in the browser that asked
 * for it (the verifier is a cookie there). A person who starts on the laptop
 * and opens the mail on the phone used to get a dead link; now she reads the
 * digits off the phone and types them on the laptop.
 */

/**
 * Accepted code lengths — same range as mobile/src/utils/otp-code.ts.
 * Supabase `mailer_otp_length` is 6 today; the audit wants 8. Accepting the
 * whole range on both surfaces is what lets that switch happen without a
 * lock-out. With a variable length there is no "complete" digit count, so the
 * form never auto-submits.
 */
export const OTP_CODE_MIN_LEN = 6;
export const OTP_CODE_MAX_LEN = 8;

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

const CODE_IN_TEXT_RE = new RegExp(`(?:^|\\D)(\\d{${OTP_CODE_MIN_LEN},${OTP_CODE_MAX_LEN}})(?!\\d)`);
const OTP_RE = new RegExp(`^\\d{${OTP_CODE_MIN_LEN},${OTP_CODE_MAX_LEN}}$`);

/**
 * What the code input may hold: digits only, at most OTP_CODE_MAX_LEN. A paste
 * of the email's sentence ("Код: 482139, действует 10 минут") yields the
 * standalone code run, not the code glued to the "10"; otherwise every
 * non-digit is dropped so "123 456" still works.
 */
export function normalizeOtpInput(raw: string): string {
  const run = CODE_IN_TEXT_RE.exec(raw);
  if (run && /\D/.test(raw)) return run[1];
  return raw.replace(/\D/g, "").slice(0, OTP_CODE_MAX_LEN);
}

export function isCompleteOtpCode(value: string): boolean {
  return OTP_RE.test(value);
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
  // Keep a destination the form honours (the extension's connect page, the
  // restore page), so typing the code after a dead link still gets there.
  const keep = safeSignupNext(nextPath, locales);
  return `${prefix}/signup?error=${code}${keep ? `&next=${encodeURIComponent(keep)}` : ""}`;
}

// ─── /signup?plan=…&interval=… ─────────────────────────────────────

/**
 * Plans a link to /signup may name. /pricing sends a signed-out buyer with
 * the device plan, "devices" (PricingClient's 401 branch); the retired plans
 * are still accepted from old links. Anything else is dropped.
 */
export const SIGNUP_PLANS = ["devices", "personal", "family", "business"] as const;
export type SignupPlan = (typeof SIGNUP_PLANS)[number];
export type SignupInterval = "monthly" | "yearly";

export function signupPlan(raw: string | null | undefined): SignupPlan | null {
  return (SIGNUP_PLANS as readonly string[]).includes(raw ?? "") ? (raw as SignupPlan) : null;
}

export function signupInterval(raw: string | null | undefined): SignupInterval | null {
  return raw === "monthly" || raw === "yearly" ? raw : null;
}

/**
 * Where /signup sends the reader once the code is accepted: a checked `next`
 * (safeSignupNext) wins; a buyer who came from /pricing goes back there with
 * the plan and interval, where checkout resumes; everyone else goes home.
 * `pricingPath` / `homePath` are already in the reader's locale.
 */
export function signupDestination(args: {
  next: string | null;
  plan: SignupPlan | null;
  interval: SignupInterval | null;
  pricingPath: string;
  homePath: string;
}): string {
  if (args.next) return args.next;
  if (!args.plan) return args.homePath;
  return `${args.pricingPath}?plan=${args.plan}${args.interval ? `&interval=${args.interval}` : ""}`;
}

// ─── /signup?next=… ───────────────────────────────────────────────

const CONNECT_STATE_RE = /^[A-Za-z0-9_-]{43}$/;

/**
 * Where /signup may send the reader after the code is accepted, besides its
 * own pricing/home default. Only three pages ask for it: the browser
 * extension's connect page (it must come back with the SAME state the
 * extension is waiting for), the account-restore page and the account
 * page (plan + devices).
 *
 * An allowlist, not "any same-origin path": `next` arrives in a link anyone
 * can craft, and the connect page hands a session to the extension, so a
 * signup that could bounce anywhere is not worth the generality. Returns the
 * canonical path, or null to fall back to the default.
 */
export function safeSignupNext(raw: string | null | undefined, locales: readonly string[]): string | null {
  if (!raw || raw.length > 300 || !raw.startsWith("/") || raw.startsWith("//") || raw.includes("\\")) {
    return null;
  }
  let url: URL;
  try {
    url = new URL(raw, "https://cleanway.invalid");
  } catch {
    return null;
  }
  if (url.origin !== "https://cleanway.invalid" || url.hash) return null;

  const segments = url.pathname.split("/").filter(Boolean);
  const prefix = segments.length > 0 && locales.includes(segments[0]) ? `/${segments.shift()}` : "";
  const path = `/${segments.join("/")}`;
  const params = [...url.searchParams.entries()];

  if (path === "/extension/connect") {
    if (params.length !== 1 || params[0][0] !== "state" || !CONNECT_STATE_RE.test(params[0][1])) return null;
    return `${prefix}/extension/connect?state=${params[0][1]}`;
  }
  if (path === "/account") {
    return params.length === 0 ? `${prefix}/account` : null;
  }
  if (path === "/account/restore") {
    if (params.length === 0) return `${prefix}/account/restore`;
    if (params.length === 1 && params[0][0] === "reason" && params[0][1] === "locked") {
      return `${prefix}/account/restore?reason=locked`;
    }
  }
  return null;
}
