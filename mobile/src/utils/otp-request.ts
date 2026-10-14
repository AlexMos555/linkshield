/**
 * Requesting a sign-in code, with the captcha solved ON DEMAND.
 *
 * WHY ON DEMAND
 * Supabase's captcha switch is project-wide and server-side. The moment it is
 * flipped, a request without a token gets 400 `captcha_failed`. Builds up to
 * 1.0.4 send no token and cannot be fixed after the fact; 1.0.5 must be able
 * to answer that BEFORE the switch is flipped, or the switch can never be
 * flipped without locking people out.
 *
 * Asking for a captcha up front (what the screen did before 1.0.5) would make
 * that readiness expensive: every sign-in would leave the app for a browser
 * challenge while the server does not even check it. So when a challenge URL
 * is configured (src/services/captcha.ts), the request goes out plain first,
 * and only a `captcha_failed` answer opens the challenge and re-sends with the
 * token. A rejected request sends no email, so the probe costs one round trip
 * and nothing else. Once the server has asked, later requests in this app
 * session (a resend) go captcha-first instead of probing again.
 *
 * Without a challenge URL nothing here changes today's flow: one plain request,
 * and a `captcha_failed` goes to the screen, which says "update the app".
 *
 * Kept free of React / expo so mobile/scripts/test-captcha-service.mjs can pin
 * it; the screen wires the real `sendEmailOtp` and `requestCaptchaToken`.
 */

/**
 * Body of `POST /auth/v1/otp`. With no token it is EXACTLY
 * `{"email":…,"create_user":true}` — the bytes the app has always sent. With
 * one, the token rides in `gotrue_meta_security.captcha_token`: the field
 * GoTrue reads, and what supabase-js's `options.captchaToken` becomes.
 */
export function otpRequestBody(
  email: string,
  captchaToken?: string,
): Record<string, unknown> {
  return {
    email,
    create_user: true,
    ...(captchaToken ? { gotrue_meta_security: { captcha_token: captchaToken } } : {}),
  };
}

/** GoTrue's answer to a missing or rejected captcha token. */
export function isCaptchaRejection(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    (err as { code?: unknown }).code === "captcha_failed"
  );
}

export interface OtpRequestDeps {
  /** Whether this build has a challenge page to send the user to. */
  readonly captchaConfigured: boolean;
  /** Request the code; throws the service's error (AuthError) on failure. */
  send(email: string, captchaToken?: string): Promise<void>;
  /** Run the challenge; null when it did not complete for any reason. */
  getCaptchaToken(): Promise<string | null>;
}

export type OtpRequestOutcome =
  | { readonly kind: "sent" }
  /** The challenge was needed but not completed — show "try again". */
  | { readonly kind: "captcha_cancelled" };

/**
 * One requester per app session: it remembers whether the server has asked
 * for a captcha, so a resend does not probe again.
 */
export function createOtpRequester(
  deps: OtpRequestDeps,
): (email: string) => Promise<OtpRequestOutcome> {
  let captchaFirst = false;

  async function sendWithCaptcha(email: string): Promise<OtpRequestOutcome> {
    const token = await deps.getCaptchaToken();
    if (!token) return { kind: "captcha_cancelled" };
    // A rejection here (bad or expired token) is rethrown, never retried:
    // looping a person through challenge after challenge helps nobody.
    await deps.send(email, token);
    return { kind: "sent" };
  }

  return async function requestOtp(email: string): Promise<OtpRequestOutcome> {
    if (!deps.captchaConfigured) {
      await deps.send(email);
      return { kind: "sent" };
    }
    if (captchaFirst) return sendWithCaptcha(email);
    try {
      await deps.send(email);
      return { kind: "sent" };
    } catch (err) {
      if (!isCaptchaRejection(err)) throw err;
      captchaFirst = true;
      return sendWithCaptcha(email);
    }
  };
}
