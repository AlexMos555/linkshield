/**
 * Cleanway Mobile API — thin wrapper over @cleanway/api-client.
 *
 * Before: hand-rolled fetch with copy-pasted DomainResult types, no timeout,
 *         throws on HTTP errors, no privacy normalization.
 * Now:    imports typed client from the monorepo — one source of truth.
 *
 * This module adds mobile-specific plumbing (Supabase session → Bearer token,
 * singleton client instance) on top of the shared core.
 */
import Constants from "expo-constants";
import {
  createClient,
  type DomainResult,
  type PublicCheckResult,
  type PricingFor,
  type ApiError,
  type CleanwayClient,
  type UserSettings,
  type Result,
} from "@cleanway/api-client";

// ─── Config ───────────────────────────────────────────────────────
// EXPO_PUBLIC_API_URL is inlined at build time. Override per-environment
// in eas.json or .env.{development,staging,production}.
const API_BASE = (
  (typeof process !== "undefined" && process.env?.EXPO_PUBLIC_API_URL) ||
  (Constants.expoConfig?.extra?.apiUrl as string | undefined) ||
  "https://api.cleanway.ai"
).replace(/\/+$/, "");

// ─── Auth token state (set by auth flow after Supabase sign-in) ──
// The api-client reads this via a callback on every request, so rotated
// tokens take effect immediately without recreating the client.
let _authToken: string | null = null;

export function setAuthToken(token: string | null): void {
  _authToken = token;
}

// ─── Account-lock (410) event bus ─────────────────────────────────
//
// The api-client returns `kind: "account_locked"` on any HTTP 410. We
// surface that to the UI via a singleton EventEmitter so that any
// screen which makes an authenticated call can transparently route
// the user to the restore flow without each call site reimplementing
// the same `if (error.kind === "account_locked") { ... }` check.
//
// The AccountLockedModal mounted in app/_layout.tsx subscribes once
// at boot and renders the restore overlay when fired. UI handlers
// only need to await the API call as before — the modal takes care
// of presenting the restore CTA, calling /restore, and clearing the
// flag on success. (Audit mobile-ts HIGH account-locked-410-unhandled.)
import { EventEmitter } from "events";

export const accountLockedEvents = new EventEmitter();

/** Last seen restoreUrl from a 410 response, for the modal. */
let _lastRestoreUrl: string | null = null;
export function getLastRestoreUrl(): string | null {
  return _lastRestoreUrl;
}

function _maybeEmitAccountLocked(error: ApiError | null): void {
  if (error && error.kind === "account_locked") {
    _lastRestoreUrl = error.restoreUrl ?? "/api/v1/user/account/restore";
    accountLockedEvents.emit("locked", { restoreUrl: _lastRestoreUrl });
  }
}

// ─── Singleton client ────────────────────────────────────────────
const _client: CleanwayClient = createClient({
  baseUrl: API_BASE,
  timeoutMs: 6_000,
  getAuthToken: () => _authToken,
  defaultHeaders: {
    "X-Client": "mobile",
    "X-Client-Version": Constants.expoConfig?.version ?? "0.0.0",
  },
});

// ─── Public API (consumers of this file) ─────────────────────────
// Keep the surface small — mobile UI should depend on these, not the client directly.

export async function checkDomain(domain: string): Promise<Result<PublicCheckResult>> {
  const r = await _client.check.publicDomain(domain);
  _maybeEmitAccountLocked(r.error);
  return r;
}

/**
 * Pull the account's settings. The other half of sync: the app only ever
 * PUSHED settings, so "keep your settings on all your devices" was a
 * one-way street — a change made in the browser extension never reached
 * this phone.
 */
export async function getAccountSettings(): Promise<Result<UserSettings>> {
  const r = await _client.user.settings();
  _maybeEmitAccountLocked(r.error);
  return r;
}

export async function getPricingForCountry(cc?: string | null): Promise<Result<PricingFor>> {
  const r = await _client.pricing.forCountry(cc);
  _maybeEmitAccountLocked(r.error);
  return r;
}

export async function checkApiHealth(): Promise<boolean> {
  const { error } = await _client.health();
  _maybeEmitAccountLocked(error);
  return error === null;
}

/**
 * POST /api/v1/user/account/restore — called by AccountLockedModal
 * when the user confirms the restore. The api-client doesn't expose
 * this verb yet because it's not in the typed surface; we do a
 * raw fetch here to keep the dependency surface small. Returns true
 * on success; the modal closes itself.
 */
export async function restoreAccount(): Promise<boolean> {
  if (!_authToken) return false;
  try {
    const resp = await fetch(`${API_BASE}/api/v1/user/account/restore`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${_authToken}`,
        "Content-Type": "application/json",
      },
    });
    if (resp.ok) {
      _lastRestoreUrl = null;
      accountLockedEvents.emit("restored");
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

// Re-export types so call sites don't need 3 imports.
//
// PublicCheckResult is what the screens actually receive from checkSingleDomain.
// It is NOT DomainResult: the public endpoint returns plain-language `signals`
// (mapped to `reasons`) and carries no TLS or domain-age facts at all.
export type { DomainResult, PublicCheckResult, PricingFor, ApiError, Result } from "@cleanway/api-client";

// Legacy shim: some older screens call `checkDomains([...])`. Keep for now —
// delete once all call sites migrate to singular checkDomain().
export interface CheckResponse {
  results: PublicCheckResult[];
  checked_at: string;
}

export async function checkDomains(domains: string[]): Promise<CheckResponse> {
  const checkedAt = new Date().toISOString();
  const results = await Promise.all(
    domains.map(async (d) => {
      const { data, error } = await _client.check.publicDomain(d);
      if (data) return data;
      // Fallback so the UI doesn't crash on a failed lookup. Note the level is
      // "unknown", NOT "safe": a check we could not perform must never be
      // rendered as a clean bill of health.
      // Callers that need error info should migrate to checkDomain() which returns Result<T>.
      return {
        domain: d,
        score: 0,
        level: "unknown",
        safe: false,
        confidence: "low",
        reasons: error ? [{ detail: error.message }] : [],
      } as PublicCheckResult;
    }),
  );
  return { results, checked_at: checkedAt };
}

/**
 * Legacy singular check — returns a plain DomainResult (throws on error).
 *
 * DEPRECATED: use `checkDomain(domain)` which returns `Result<DomainResult>` and
 * forces callers to handle errors explicitly. Kept for existing screens:
 *   - mobile/app/(tabs)/index.tsx
 *   - mobile/app/shared.tsx
 *   - mobile/app/result.tsx
 * All three should migrate to `checkDomain` + explicit error rendering.
 */
export async function checkSingleDomain(domain: string): Promise<PublicCheckResult> {
  const { data, error } = await _client.check.publicDomain(domain);
  if (data) return data;
  // Throwing preserves the old behavior so call sites work without changes.
  throw new Error(error?.message ?? "Check failed");
}

/**
 * Breach check — k-anonymity via 5-char SHA-1 prefix.
 * Legacy endpoint, not yet wrapped in @cleanway/api-client. Falls back to direct fetch.
 */
export interface BreachSuffix {
  suffix: string;
  count: number;
  latest_breach?: string;
}
export interface BreachResponse {
  prefix: string;
  suffixes: BreachSuffix[];
}

export async function checkBreach(hashPrefix: string): Promise<BreachResponse> {
  const resp = await fetch(`${API_BASE}/api/v1/breach/check/${encodeURIComponent(hashPrefix)}`, {
    method: "GET",
    headers: { Accept: "application/json" },
  });
  if (!resp.ok) {
    throw new Error(`Breach check failed: HTTP ${resp.status}`);
  }
  return (await resp.json()) as BreachResponse;
}
