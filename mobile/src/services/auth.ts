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
  code?: string;
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
      throw new AuthError(
        data.code || data.error || "auth_error",
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

export async function refreshAccessToken(): Promise<AuthSession | null> {
  const stored = await readStoredSession();
  if (!stored?.refreshToken) return null;
  try {
    const data = await goTrue("/auth/v1/token?grant_type=refresh_token", {
      refresh_token: stored.refreshToken,
    });
    return await persistSession(data, stored.email);
  } catch (err) {
    // Refresh tokens don't come back — treat as logout
    if (err instanceof AuthError && err.status === 401) {
      await clearSession();
    }
    return null;
  }
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
