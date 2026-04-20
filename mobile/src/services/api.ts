/**
 * LinkShield Mobile API — thin wrapper over @linkshield/api-client.
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
  type PricingFor,
  type ApiError,
  type LinkShieldClient,
  type Result,
} from "@linkshield/api-client";

// ─── Config ───────────────────────────────────────────────────────
// EXPO_PUBLIC_API_URL is inlined at build time. Override per-environment
// in eas.json or .env.{development,staging,production}.
const API_BASE = (
  (typeof process !== "undefined" && process.env?.EXPO_PUBLIC_API_URL) ||
  (Constants.expoConfig?.extra?.apiUrl as string | undefined) ||
  "https://web-production-fe08.up.railway.app"
).replace(/\/+$/, "");

// ─── Auth token state (set by auth flow after Supabase sign-in) ──
// The api-client reads this via a callback on every request, so rotated
// tokens take effect immediately without recreating the client.
let _authToken: string | null = null;

export function setAuthToken(token: string | null): void {
  _authToken = token;
}

// ─── Singleton client ────────────────────────────────────────────
const _client: LinkShieldClient = createClient({
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

export async function checkDomain(domain: string): Promise<Result<DomainResult>> {
  return _client.check.publicDomain(domain);
}

export async function getPricingForCountry(cc?: string | null): Promise<Result<PricingFor>> {
  return _client.pricing.forCountry(cc);
}

export async function checkApiHealth(): Promise<boolean> {
  const { error } = await _client.health();
  return error === null;
}

// Re-export types so call sites don't need 3 imports
export type { DomainResult, PricingFor, ApiError, Result } from "@linkshield/api-client";

// Legacy shim: some older screens call `checkDomains([...])`. Keep for now —
// delete once all call sites migrate to singular checkDomain().
export interface CheckResponse {
  results: DomainResult[];
  checked_at: string;
}

export async function checkDomains(domains: string[]): Promise<CheckResponse> {
  const checkedAt = new Date().toISOString();
  const results = await Promise.all(
    domains.map(async (d) => {
      const { data, error } = await _client.check.publicDomain(d);
      if (data) return data;
      // Fallback: synthesize a safe-default result on error so UI doesn't crash.
      // Callers that need error info should migrate to checkDomain() which returns Result<T>.
      return {
        domain: d,
        score: 0,
        level: "safe",
        confidence: "low",
        reasons: error ? [{ signal: "api_error", detail: error.message, weight: 0 }] : [],
      } as DomainResult;
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
export async function checkSingleDomain(domain: string): Promise<DomainResult> {
  const { data, error } = await _client.check.publicDomain(domain);
  if (data) return data;
  // Throwing preserves the old behavior so call sites work without changes.
  throw new Error(error?.message ?? "Check failed");
}

/**
 * Breach check — k-anonymity via 5-char SHA-1 prefix.
 * Legacy endpoint, not yet wrapped in @linkshield/api-client. Falls back to direct fetch.
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
