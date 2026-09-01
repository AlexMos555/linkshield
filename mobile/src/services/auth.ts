/**
 * Auth service — thin wrapper over Supabase GoTrue REST endpoints.
 *
 * Why talk to GoTrue directly instead of `@supabase/supabase-js`?
 * - The SDK pulls in a large dependency graph; we only need 5 endpoints.
 * - Custom error handling (typed `AuthError`) for cleaner UI surfaces.
 * - SecureStore-backed session persistence is trivial to wire this way.
 *
 * Endpoints used (Supabase GoTrue v1):
 * - `POST /auth/v1/signup`
 * - `POST /auth/v1/token?grant_type=password`
 * - `POST /auth/v1/token?grant_type=refresh_token`
 * - `POST /auth/v1/logout`
 * - `POST /auth/v1/recover` (password reset email)
 *
 * Session persistence contract:
 * - On `signIn` / `signUp` success we stash `access_token`, `refresh_token`,
 *   `user_email`, and `token_expires_at` in SecureStore.
 * - `restoreSession` reads them on app boot and returns an `AuthSession`
 *   or `null`; if the access token is <2 min from expiry it transparently
 *   refreshes before returning.
 * - `signOut` clears all four keys and hits the logout endpoint best-effort.
 *
 * All network calls have a 10-second timeout (`AbortController`) so the
 * UI can't hang on a dead server.
 */

import * as SecureStore from "expo-secure-store";
import { setAuthToken } from "./api";
import {
  SUPABASE_URL,
  SUPABASE_ANON_KEY,
  isSupabaseConfigured,
  SupabaseNotConfiguredError,
} from "./supabase";

// ─── Types ────────────────────────────────────────────────────────

export interface AuthSession {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly email: string;
  /** Unix epoch seconds. */
  readonly expiresAt: number;
}

export class AuthError extends Error {
  readonly code: string;
  readonly status: number;
  constructor(code: string, message: string, status = 0) {
    super(message);
    this.code = code;
    this.name = "AuthError";
    this.status = status;
  }
}

// ─── Storage keys (centralized — never inline) ────────────────────

const KEY_ACCESS = "auth_token";
const KEY_REFRESH = "refresh_token";
const KEY_EMAIL = "user_email";
const KEY_EXPIRES = "token_expires_at";

// ─── Network helpers ──────────────────────────────────────────────

const NETWORK_TIMEOUT_MS = 10_000;
// Refresh if the token has <2 minutes remaining
const REFRESH_WINDOW_SECONDS = 120;

interface GoTrueTokenResponse {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  expires_at?: number;
  user?: { email?: string };
  msg?: string;
  error_description?: string;
  error?: string;
  /** GoTrue's numeric HTTP status echo (e.g. 403) in the versioned error format. */
  code?: string | number;
  /** GoTrue's SYMBOLIC name (e.g. "otp_expired") — the one worth branching on. */
  error_code?: string;
}

async function goTrue<T = GoTrueTokenResponse>(
  path: string,
  body: Record<string, unknown> | null,
  method: "GET" | "POST" = "POST",
  accessToken?: string,
): Promise<T> {
  if (!isSupabaseConfigured()) throw new SupabaseNotConfiguredError();

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), NETWORK_TIMEOUT_MS);

  try {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      apikey: SUPABASE_ANON_KEY,
    };
    if (accessToken) headers.Authorization = `Bearer ${accessToken}`;

    const resp = await fetch(`${SUPABASE_URL}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
    const data = (await resp.json().catch(() => ({}))) as T & GoTrueTokenResponse;

    if (!resp.ok) {
      // Prefer the symbolic name. GoTrue's versioned error format puts the
      // numeric HTTP status in `code` and the actual identifier in `error_code`,
      // so reading `code` first made every symbolic branch (e.g. "otp_expired")
      // unreachable — it was comparing "otp_expired" against "403".
      throw new AuthError(
        data.error_code || data.error || (data.code != null ? String(data.code) : "auth_error"),
        data.msg || data.error_description || "Authentication failed",
        resp.status,
      );
    }
    return data;
  } catch (err) {
    if (err instanceof AuthError) throw err;
    if ((err as Error).name === "AbortError") {
      throw new AuthError("timeout", "The request timed out. Check your connection.");
    }
    throw new AuthError(
      "network_error",
      "Could not reach the server. Try again later.",
    );
  } finally {
    clearTimeout(timer);
  }
}

// ─── Session persistence ──────────────────────────────────────────

async function persistSession(
  tokens: GoTrueTokenResponse,
  email: string,
): Promise<AuthSession | null> {
  if (!tokens.access_token || !tokens.refresh_token) return null;
  const now = Math.floor(Date.now() / 1000);
  const expiresAt =
    tokens.expires_at ??
    now + (typeof tokens.expires_in === "number" ? tokens.expires_in : 3600);

  await Promise.all([
    SecureStore.setItemAsync(KEY_ACCESS, tokens.access_token),
    SecureStore.setItemAsync(KEY_REFRESH, tokens.refresh_token),
    SecureStore.setItemAsync(KEY_EMAIL, email),
    SecureStore.setItemAsync(KEY_EXPIRES, String(expiresAt)),
  ]);

  // Keep the api-client's module-level token in lockstep. Before this, a
  // refresh updated only SecureStore: the client kept sending the original
  // sign-in token, and after its ~1h expiry every pull through services/api
  // silently 401'd while pushes (which read SecureStore) kept working.
  setAuthToken(tokens.access_token);

  return {
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    email,
    expiresAt,
  };
}

async function clearSession(): Promise<void> {
  await Promise.all([
    SecureStore.deleteItemAsync(KEY_ACCESS),
    SecureStore.deleteItemAsync(KEY_REFRESH),
    SecureStore.deleteItemAsync(KEY_EMAIL),
    SecureStore.deleteItemAsync(KEY_EXPIRES),
  ]);
  setAuthToken(null);
}

async function readStoredSession(): Promise<AuthSession | null> {
  const [access, refresh, email, expires] = await Promise.all([
    SecureStore.getItemAsync(KEY_ACCESS),
    SecureStore.getItemAsync(KEY_REFRESH),
    SecureStore.getItemAsync(KEY_EMAIL),
    SecureStore.getItemAsync(KEY_EXPIRES),
  ]);
  if (!access || !refresh || !email) return null;
  const expiresAt = Number(expires ?? 0);
  return { accessToken: access, refreshToken: refresh, email, expiresAt };
}

// ─── Public API ───────────────────────────────────────────────────

export async function signIn(
  email: string,
  password: string,
): Promise<AuthSession> {
  const data = await goTrue(
    "/auth/v1/token?grant_type=password",
    { email, password },
  );
  const session = await persistSession(data, data.user?.email ?? email);
  if (!session) {
    throw new AuthError("bad_response", "Server returned an unexpected response.");
  }
  return session;
}

/**
 * Create a new account. When Supabase's "Confirm Email" is enabled, no
 * `access_token` is returned until the user clicks the confirmation link —
 * in that case we resolve with `null` and the UI should instruct the user to
 * check their email.
 */
export async function signUp(
  email: string,
  password: string,
): Promise<AuthSession | null> {
  const data = await goTrue("/auth/v1/signup", { email, password });
  if (!data.access_token) {
    // Account created but awaits email confirmation
    return null;
  }
  return persistSession(data, data.user?.email ?? email);
}

// ─── Passwordless email OTP (the primary flow — unified with the web) ──
//
// The web signs up with a magic link; the app uses the SAME Supabase project,
// so a code sent here logs into the SAME account and sync just works. No
// password to set or remember (grandma-friendly), and no fragile web→app token
// handoff: the user types the 6-digit code from the email on either surface.
//
// Requires the Supabase project's email template to expose the code
// (`{{ .Token }}`); see docs/MOBILE_AUTH.md.

/**
 * Send a one-time login code to `email`. Creates the account if it's new
 * (`create_user: true`), so the same call serves sign-in and sign-up.
 * GoTrue returns 200 with an empty body; it never reveals whether the address
 * already existed (no account enumeration).
 *
 * `captchaToken` is OPTIONAL and omitted entirely when absent. Pass it only
 * when the Supabase project has captcha protection enabled — see
 * src/services/captcha.ts for how the app obtains one, and note that the
 * server-side switch is project-wide (it breaks web sign-up at the same
 * instant it protects mobile).
 */
export async function sendEmailOtp(
  email: string,
  captchaToken?: string,
): Promise<void> {
  await goTrue("/auth/v1/otp", {
    email,
    create_user: true,
    // The spread is load-bearing. With no captcha configured the body is
    // EXACTLY `{"email":…,"create_user":true}` — the same bytes as before this
    // parameter existed. Sending `gotrue_meta_security: {}` unconditionally
    // (what supabase-js does) would be tolerated by GoTrue, but "tolerated" is
    // a weaker guarantee than "unchanged", and unchanged is what the launch
    // needs while captcha is off.
    ...(captchaToken ? { gotrue_meta_security: { captcha_token: captchaToken } } : {}),
  });
}

/**
 * Exchange the 6-digit code the user typed for a session.
 *
 * Why two types are tried: GoTrue issues a different token kind depending on
 * whether the address already existed. An existing user gets a magic-link/email
 * token (`type: "email"`); a BRAND-NEW user created by `/otp` with
 * `create_user: true` gets a *signup confirmation* token, which some GoTrue
 * versions only accept as `type: "signup"`. Probing the live server was
 * inconclusive — it returns the same `otp_expired` error for every type — so
 * rather than bet first-ever sign-in on one reading of the docs, we try
 * "email" and fall back to "signup" when the server rejects the token.
 *
 * Cost of the fallback: one extra request in the rare failure path. Cost of
 * getting it wrong without the fallback: nobody can create an account.
 */
const OTP_VERIFY_TYPES = ["email", "signup"] as const;

export async function verifyEmailOtp(
  email: string,
  token: string,
): Promise<AuthSession> {
  const trimmed = token.trim();
  let lastError: unknown = null;

  for (const type of OTP_VERIFY_TYPES) {
    try {
      const data = await goTrue("/auth/v1/verify", { type, email, token: trimmed });
      const session = await persistSession(data, data.user?.email ?? email);
      if (!session) {
        throw new AuthError("bad_response", "Server returned an unexpected response.");
      }
      return session;
    } catch (err) {
      lastError = err;
      // Only a rejected TOKEN is worth retrying under the other type. A network
      // failure, timeout or malformed response means retrying would just burn
      // another round trip and delay the error the user needs to see.
      const retryable =
        err instanceof AuthError &&
        (err.status === 400 || err.status === 401 || err.status === 403);
      if (!retryable) throw err;
    }
  }
  throw lastError instanceof Error
    ? lastError
    : new AuthError("auth_error", "Authentication failed");
}

export async function signOut(): Promise<void> {
  const stored = await readStoredSession();
  // Best-effort logout: clear local state even if the API call fails.
  try {
    if (stored?.accessToken) {
      await goTrue("/auth/v1/logout", null, "POST", stored.accessToken);
    }
  } catch {
    // ignore — session is invalidated server-side eventually anyway
  }
  await clearSession();
}

/**
 * Internal refresh that keeps the failure kinds apart. Only a definitive 401
 * means the session is gone; a network failure (status 0, timeout, 5xx) means
 * WE DON'T KNOW — the refresh token is untouched in SecureStore and the next
 * online attempt will likely succeed. Collapsing both into null is what made
 * the app tell an offline-but-signed-in user to go type her password again.
 */
async function _refresh(): Promise<AuthSession | "offline" | null> {
  const stored = await readStoredSession();
  if (!stored?.refreshToken) return null;
  try {
    const data = await goTrue("/auth/v1/token?grant_type=refresh_token", {
      refresh_token: stored.refreshToken,
    });
    return await persistSession(data, stored.email);
  } catch (err) {
    // Refresh tokens don't come back — a 401 is a real logout.
    if (err instanceof AuthError && err.status === 401) {
      await clearSession();
      return null;
    }
    return "offline";
  }
}

export async function refreshAccessToken(): Promise<AuthSession | null> {
  const r = await _refresh();
  return r === "offline" ? null : r;
}

/** What a screen may honestly say about the session right now. */
export type SessionState =
  | { kind: "ok"; session: AuthSession }
  | { kind: "none" }
  /** A session exists but could not be refreshed — offline, not signed out. */
  | { kind: "offline"; email: string | null };

export async function getSessionState(): Promise<SessionState> {
  const stored = await readStoredSession();
  if (!stored) return { kind: "none" };

  const now = Math.floor(Date.now() / 1000);
  if (stored.expiresAt - now > REFRESH_WINDOW_SECONDS) {
    setAuthToken(stored.accessToken);
    return { kind: "ok", session: stored };
  }
  const refreshed = await _refresh();
  if (refreshed === "offline") return { kind: "offline", email: stored.email };
  if (refreshed === null) return { kind: "none" };
  return { kind: "ok", session: refreshed };
}

export async function sendPasswordResetEmail(email: string): Promise<void> {
  // GoTrue returns 200 even when the address doesn't exist to prevent
  // account enumeration.
  await goTrue("/auth/v1/recover", { email });
}

/**
 * Read the locally-persisted session. If the access token is close to
 * expiry, refresh it transparently before returning. Returns `null` when
 * no usable session is available.
 */
export async function restoreSession(): Promise<AuthSession | null> {
  const stored = await readStoredSession();
  if (!stored) return null;

  const now = Math.floor(Date.now() / 1000);
  if (stored.expiresAt - now > REFRESH_WINDOW_SECONDS) {
    setAuthToken(stored.accessToken);
    return stored;
  }
  // Near or past expiry — try to refresh
  const refreshed = await refreshAccessToken();
  return refreshed ?? null;
}

// ─── Validation helpers (shared between UI + tests) ───────────────

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
export const MIN_PASSWORD_LEN = 8;

export function validateEmail(v: string): string | null {
  if (!v) return "Email is required";
  if (!EMAIL_RE.test(v)) return "Enter a valid email";
  return null;
}

export function validatePassword(v: string): string | null {
  if (!v) return "Password is required";
  if (v.length < MIN_PASSWORD_LEN) {
    return `Password must be at least ${MIN_PASSWORD_LEN} characters`;
  }
  return null;
}

export const OTP_CODE_LEN = 6;
const OTP_RE = /^\d{6}$/;

/** True when `v` is a well-formed 6-digit login code. */
export function isValidOtpCode(v: string): boolean {
  return OTP_RE.test(v.trim());
}
