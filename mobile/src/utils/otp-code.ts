/**
 * The one-time sign-in code: how long it may be and what the input keeps.
 *
 * WHY A RANGE, NOT ONE LENGTH
 * The code length is a Supabase project setting (`mailer_otp_length`, 6 today).
 * The security audit recommends raising it to 8, but installed builds up to
 * 1.0.4 accept exactly six digits — flipping the setting would lock every one
 * of them out of sign-in. From 1.0.5 the app accepts any length in
 * [OTP_CODE_MIN_LEN, OTP_CODE_MAX_LEN], so the server can move to 8 once
 * enough people have updated, with no further app release. The same range is
 * mirrored in landing/lib/signup-flow.ts.
 *
 * WHY NO AUTO-SUBMIT
 * With a variable length there is no digit count at which "complete" is
 * certain: six digits may be a whole code or the first six of eight. The user
 * taps Verify (or Return). Do not add an auto-submit on length.
 *
 * Kept free of React / expo so mobile/scripts/test-auth-error-key.mjs can pin
 * it with node's TS stripper.
 */

export const OTP_CODE_MIN_LEN = 6;
export const OTP_CODE_MAX_LEN = 8;

/** A standalone 6–8 digit run inside pasted text ("Your code: 48213907."). */
const CODE_IN_TEXT_RE = new RegExp(
  `(?:^|\\D)(\\d{${OTP_CODE_MIN_LEN},${OTP_CODE_MAX_LEN}})(?!\\d)`,
);
const OTP_RE = new RegExp(`^\\d{${OTP_CODE_MIN_LEN},${OTP_CODE_MAX_LEN}}$`);

/**
 * What the code field holds after a keystroke or a paste: digits only, at most
 * OTP_CODE_MAX_LEN of them.
 *
 * A paste of a whole sentence from the email ("Код: 482139, действует 10
 * минут") must yield the code, not the code glued to the "10". So when the raw
 * text contains a standalone run of a plausible code length, that run wins;
 * otherwise every non-digit is dropped, which keeps typed digits and codes
 * pasted with separators ("123 456", "1234-5678") working.
 *
 * `\d` is ASCII-only in JS: a full-width digit is dropped, never guessed at.
 */
export function normalizeOtpInput(raw: string): string {
  const run = CODE_IN_TEXT_RE.exec(raw);
  if (run && /\D/.test(raw)) return run[1];
  return raw.replace(/\D/g, "").slice(0, OTP_CODE_MAX_LEN);
}

/** True when `v` is a well-formed login code of any accepted length. */
export function isValidOtpCode(v: string): boolean {
  return OTP_RE.test(v.trim());
}
