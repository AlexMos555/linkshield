/**
 * The decisions behind /extension/connect — where the browser extension's
 * "Sign in" lands — kept free of React and Supabase so they can be
 * table-tested (scripts/test-signup-flow.mjs).
 *
 * The extension opens /<locale>/extension/connect?state=<43 random chars>.
 * The page needs a signed-in website session; it asks the API for a session
 * OF THE EXTENSION'S OWN (POST /api/v1/auth/extension-session) and posts it,
 * with the state, to its own window. The extension's content script on this
 * exact origin and path (packages/extension-core/src/content/connect-relay.js)
 * forwards it to the extension, which checks the state it started with.
 *
 * Why the extension gets its own session: Supabase rotates refresh tokens
 * and revokes the whole session when a rotated one is presented again. The
 * website and the extension refreshing ONE session would sign each other out.
 *
 * The message names below must match connect-relay.js;
 * scripts/test-extension-auth.mjs fails if they drift.
 */

export const MSG_FROM_PAGE = "cleanway-web";
export const MSG_FROM_EXTENSION = "cleanway-extension";
export const MSG_HELLO = "cleanway:hello";
export const MSG_READY = "cleanway:extension-ready";
export const MSG_CONNECT = "cleanway:connect";
export const MSG_RESULT = "cleanway:connect-result";

/** How long Connect waits for the extension's answer. */
export const RESULT_TIMEOUT_MS = 10_000;
/** How long Connect waits for the extension to say it is there at all. */
export const READY_TIMEOUT_MS = 1_500;

/** 32 random bytes, base64url — what the extension's generateState() makes. */
const STATE_RE = /^[A-Za-z0-9_-]{43}$/;

export function isValidConnectState(value: unknown): value is string {
  return typeof value === "string" && STATE_RE.test(value);
}

/** Keys in the ExtensionConnect i18n namespace for a failed connect. */
export type ConnectErrorKey =
  | "error_no_extension"
  | "error_state"
  | "error_failed"
  | "error_network"
  | "error_locked";

/** The extension's refusal code → the sentence the reader sees. */
export function extensionErrorKey(code: string | null | undefined): ConnectErrorKey {
  switch (code) {
    case "state_mismatch":
    case "state_expired":
      return "error_state";
    default:
      return "error_failed";
  }
}

/** What the API's answer to POST /auth/extension-session means for the page. */
export type MintOutcome = "ok" | "signin" | ConnectErrorKey;

export function mintOutcome(status: number): MintOutcome {
  if (status === 200) return "ok";
  if (status === 401) return "signin"; // the website session ran out: sign in again
  if (status === 410) return "error_locked";
  return "error_failed";
}

export interface MintedSession {
  access_token: string;
  refresh_token: string;
  expires_at: number;
}

export function isMintedSession(body: unknown): body is MintedSession {
  if (!body || typeof body !== "object") return false;
  const b = body as Record<string, unknown>;
  return (
    typeof b.access_token === "string" && b.access_token.length > 0 &&
    typeof b.refresh_token === "string" && b.refresh_token.length > 0 &&
    typeof b.expires_at === "number"
  );
}

function withLocale(locale: string, path: string, defaultLocale: string): string {
  return locale === defaultLocale ? path : `/${locale}${path}`;
}

/** /ru/extension/connect?state=… — the page itself, in the reader's locale. */
export function connectPath(locale: string, state: string, defaultLocale: string): string {
  return `${withLocale(locale, "/extension/connect", defaultLocale)}?state=${encodeURIComponent(state)}`;
}

/** Sign in first, then come back to this very page with the same state. */
export function signupForConnectPath(locale: string, state: string, defaultLocale: string): string {
  const back = connectPath(locale, state, defaultLocale);
  return `${withLocale(locale, "/signup", defaultLocale)}?next=${encodeURIComponent(back)}`;
}
