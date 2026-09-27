/**
 * The number behind "Позвонить близкому" — typed by the person or taken
 * from their address book.
 *
 * normalizePhone mirrors ProtectionCheckup.dialable (Kotlin): digits and one
 * leading "+", 3 to 15 digits, visual separators dropped, anything else
 * refused — "*" and "#" would make a USSD code, letters and ";" or "," an
 * extension or a pause. The two must agree. test-checkup.mjs and
 * ProtectionCheckupTest.kt run the same table, but CI runs only the JS one:
 * change both rules together and run the Kotlin test locally.
 */

const MIN_DIGITS = 3;
const MAX_DIGITS = 15;
// JS's \s already covers every Unicode space (U+00A0, U+2009, U+202F, U+FEFF…);
// Kotlin spells the same set out as \s\p{Z}\uFEFF. Plus the dashes U+2010–U+2015.
const SEPARATORS = /[\s\u2010-\u2015\-().]/g;
const ASCII_DIGITS = /^[0-9]+$/;

/** The number as the dialer should receive it, or null when it is not a plain phone number. */
export function normalizePhone(raw: string | null | undefined): string | null {
  if (typeof raw !== "string") return null;
  const compact = raw.trim().replace(SEPARATORS, "");
  const plus = compact.startsWith("+");
  const digits = plus ? compact.slice(1) : compact;
  if (digits.length < MIN_DIGITS || digits.length > MAX_DIGITS) return null;
  if (!ASCII_DIGITS.test(digits)) return null;
  return plus ? `+${digits}` : digits;
}

/**
 * Easier to read back: a Russian mobile number grouped the way it is
 * spoken ("+7 916 123-45-67", "8 916 123-45-67"); any other number as is.
 */
export function formatPhone(number: string): string {
  const ru = /^(\+7|8)(\d{3})(\d{3})(\d{2})(\d{2})$/.exec(number);
  if (!ru) return number;
  const [, prefix, code, a, b, c] = ru;
  return `${prefix} ${code} ${a}-${b}-${c}`;
}
