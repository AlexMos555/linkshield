/**
 * Password sign-in for the stores' app reviewers, and for nobody else.
 *
 * WHY
 * Sign-in is a one-time code sent by email (src/services/auth.ts). App Store,
 * Google Play and RuStore reviewers sign in with an account we give them, and
 * a code sent to that address lands in our inbox, not theirs: review stalls.
 * So one review account (docs/runbooks/app-review-account.md) has a long
 * random password, and the sign-in screen asks for a password only when the
 * typed address is EXACTLY one on the build's allowlist,
 * EXPO_PUBLIC_REVIEW_EMAILS (comma-separated, case-insensitive, trimmed;
 * unset = off). Only @cleanway.ai addresses count: the variable reaches a
 * build through eas.json, mobile/.env or a shell export, and a typo or a
 * pasted personal address must not show a real person a password field.
 * Every other address keeps the code flow: no field, no new request, the
 * same bytes as before.
 *
 * NOT A SECURITY BOUNDARY
 * Hiding the field is presentation. GoTrue's password grant is open to any
 * client that has the public key; what protects the review account is its
 * random password and GoTrue's per-IP limit on /auth/v1/token. People who
 * signed up by code have no password, so the grant cannot open their
 * accounts, allowlisted or not.
 *
 * Kept free of React / expo, and of imports (node's TS stripper does not
 * resolve extensionless paths), so mobile/scripts/test-auth-error-key.mjs can
 * pin it.
 */

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
/** The only domain the allowlist accepts (exact: no subdomains, no lookalikes). */
const REVIEW_DOMAIN = "@cleanway.ai";

/** The form addresses are compared in: trimmed, lower case. */
export function canonicalEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * EXPO_PUBLIC_REVIEW_EMAILS → the allowlist. Unset, blank, an unexpanded
 * "$…" reference (a build profile naming a variable that was never defined),
 * anything that is not an address and any address not on @cleanway.ai
 * contribute nothing.
 */
export function parseReviewEmails(raw: string | undefined | null): readonly string[] {
  const out: string[] = [];
  for (const part of (raw ?? "").split(",")) {
    if (part.trim().startsWith("$")) continue;
    const email = canonicalEmail(part);
    if (!EMAIL_RE.test(email) || !email.endsWith(REVIEW_DOMAIN)) continue;
    if (!out.includes(email)) out.push(email);
  }
  return out;
}

/** Exact match only: no +tags, no prefixes, no lookalike letters. */
export function isReviewEmail(email: string, allowlist: readonly string[]): boolean {
  return allowlist.length > 0 && allowlist.includes(canonicalEmail(email));
}

/**
 * Body of `POST /auth/v1/token?grant_type=password`. With no token it is
 * exactly `{"email":…,"password":…}`; a captcha token rides in
 * `gotrue_meta_security.captcha_token`, as on the code request
 * (src/utils/otp-request.ts) and in supabase-js's signInWithPassword.
 */
export function passwordSignInBody(
  email: string,
  password: string,
  captchaToken?: string,
): Record<string, unknown> {
  return {
    email,
    password,
    ...(captchaToken ? { gotrue_meta_security: { captcha_token: captchaToken } } : {}),
  };
}

export interface ReviewSignInDeps<S> {
  /** Whether this build has a challenge page (src/services/captcha.ts). */
  readonly captchaConfigured: boolean;
  /** The password grant; throws the service's error (AuthError) on failure. */
  signIn(email: string, password: string, captchaToken?: string): Promise<S>;
  /** Run the challenge; null when it did not complete for any reason. */
  getCaptchaToken(): Promise<string | null>;
}

export type ReviewSignInOutcome<S> =
  | { readonly kind: "signed_in"; readonly session: S }
  /** The challenge was needed but not completed: show "try again". */
  | { readonly kind: "captcha_cancelled" }
  /** Not an allowlisted address: nothing was sent. */
  | { readonly kind: "not_review_email" };

/** Same test as otp-request.ts `isCaptchaRejection` (kept import-free, see top). */
function isCaptchaRejection(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { code?: unknown }).code === "captcha_failed";
}

/**
 * The password sign-in the screen calls. It refuses any address that is not
 * on the allowlist BEFORE anything is sent, so a wiring mistake on the screen
 * cannot turn the password grant on for everyone.
 *
 * The captcha is solved on demand, like the code request: the plain request
 * first, and only a `captcha_failed` answer (Supabase captcha switched on)
 * opens the challenge and retries once with the token. Any other failure, a
 * wrong password included, is rethrown untouched for the screen to word.
 *
 * The password is trimmed: the review password is generated without
 * whitespace (scripts/create_review_account.py), and one pasted from the
 * review notes often carries a trailing newline.
 */
export function createReviewSignIn<S>(
  allowlist: readonly string[],
  deps: ReviewSignInDeps<S>,
): (email: string, password: string) => Promise<ReviewSignInOutcome<S>> {
  return async function reviewSignIn(email, password) {
    if (!isReviewEmail(email, allowlist)) return { kind: "not_review_email" };
    const address = canonicalEmail(email);
    const secret = password.trim();
    try {
      return { kind: "signed_in", session: await deps.signIn(address, secret) };
    } catch (err) {
      if (!deps.captchaConfigured || !isCaptchaRejection(err)) throw err;
    }
    const token = await deps.getCaptchaToken();
    if (!token) return { kind: "captcha_cancelled" };
    return { kind: "signed_in", session: await deps.signIn(address, secret, token) };
  };
}
