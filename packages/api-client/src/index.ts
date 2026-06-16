/**
 * @cleanway/api-client
 *
 * Thin, typed fetch wrapper for the Cleanway API. Goals:
 *   1. Single contract — consumers import types from @cleanway/api-types
 *   2. Fail predictably — timeout, typed errors (no thrown strings)
 *   3. No framework assumption — works in Next.js (server + client), RN, extensions, plain browsers
 *   4. Privacy-preserving — never serializes full URLs to the server; only domains go over the wire
 *
 * Usage:
 *   import { createClient } from "@cleanway/api-client";
 *   const api = createClient({ baseUrl: "https://api.cleanway.ai" });
 *   const { data, error } = await api.pricing.forCountry("US");
 *   if (error) return showErrorUI(error);
 *   render(data.plans.personal.monthly);
 */
import type {
  DomainResult,
  PricingFor,
  PricingTiers,
  HealthResponse,
} from "@cleanway/api-types";

// ── Error shapes ──────────────────────────────────────────────────

export type ApiErrorKind =
  | "network"           // fetch itself threw (offline, DNS, CORS, TLS)
  | "timeout"           // our AbortController fired
  | "unauthorized"      // 401 — JWT missing/expired/invalid; client should re-auth
  | "forbidden"         // 403 — auth ok but caller lacks permission
  | "rate_limited"      // 429 — back off; respect Retry-After if present
  | "account_locked"    // 410 — soft-deleted; UI must offer /restore flow
  | "http_4xx"          // other client errors (validation, not found, etc.)
  | "http_5xx"          // server error
  | "invalid_json"      // response body didn't parse
  | "contract_mismatch"; // (future) runtime schema validation failure

export interface ApiError {
  kind: ApiErrorKind;
  status?: number;
  message: string;
  /** Optional raw response body, when we could read it */
  body?: unknown;
  /** For account_locked (410), the URL to POST to restore the account. */
  restoreUrl?: string;
  /** For rate_limited (429), seconds to wait before retrying (from Retry-After). */
  retryAfterSeconds?: number;
}

export type Result<T> =
  | { data: T; error: null }
  | { data: null; error: ApiError };

// ── Client options ────────────────────────────────────────────────

export interface ClientOptions {
  baseUrl: string;
  /** ms — default 8000. Applies to every request; abort on exceed. */
  timeoutMs?: number;
  /** Optional Bearer token (Supabase JWT) — added as Authorization header */
  getAuthToken?: () => string | null | Promise<string | null>;
  /** Override fetch (useful for SSR, polyfills). Defaults to globalThis.fetch. */
  fetchImpl?: typeof fetch;
  /** Extra headers appended to every request. Use for X-Client-Version etc. */
  defaultHeaders?: Record<string, string>;
}

// ── Internal request helper ───────────────────────────────────────

async function request<T>(
  opts: ClientOptions,
  method: "GET" | "POST" | "PUT" | "DELETE",
  path: string,
  body?: unknown,
): Promise<Result<T>> {
  const url = opts.baseUrl.replace(/\/+$/, "") + path;
  const timeoutMs = opts.timeoutMs ?? 8_000;
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch;

  if (typeof fetchImpl !== "function") {
    return {
      data: null,
      error: { kind: "network", message: "fetch is not available in this environment" },
    };
  }

  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(opts.defaultHeaders ?? {}),
  };
  if (body !== undefined) headers["Content-Type"] = "application/json";

  if (opts.getAuthToken) {
    const token = await opts.getAuthToken();
    if (token) headers.Authorization = `Bearer ${token}`;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let resp: Response;
  try {
    resp = await fetchImpl(url, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: controller.signal,
      // Never send cookies by default — our API is stateless + JWT
      credentials: "omit",
    });
  } catch (e: unknown) {
    clearTimeout(timer);
    const isAbort = e instanceof DOMException && e.name === "AbortError";
    return {
      data: null,
      error: {
        kind: isAbort ? "timeout" : "network",
        message: isAbort ? `request exceeded ${timeoutMs}ms` : (e instanceof Error ? e.message : "network error"),
      },
    };
  }
  clearTimeout(timer);

  // Try to parse body even on errors — server may return { error: "..." }
  let parsed: unknown = null;
  let parseError: Error | null = null;
  const text = await resp.text();
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch (e: unknown) {
      parseError = e instanceof Error ? e : new Error(String(e));
    }
  }

  if (!resp.ok) {
    return {
      data: null,
      error: mapHttpError(resp, parsed, text),
    };
  }

  if (parseError) {
    return {
      data: null,
      error: {
        kind: "invalid_json",
        status: resp.status,
        message: parseError.message,
        body: text,
      },
    };
  }

  return { data: parsed as T, error: null };
}

/**
 * Map an HTTP error response into a typed ApiError.
 *
 * Specific statuses (401/403/410/429) get dedicated `kind` values so callers
 * can switch on them without reasoning about status codes. The 410 case
 * extracts the restore_url that the FastAPI handler embeds in `detail`.
 */
function mapHttpError(
  resp: Response,
  parsed: unknown,
  rawText: string,
): ApiError {
  const status = resp.status;
  const baseMessage = extractErrorMessage(parsed) ?? `HTTP ${status}`;

  if (status === 401) {
    return { kind: "unauthorized", status, message: baseMessage, body: parsed ?? rawText };
  }
  if (status === 403) {
    return { kind: "forbidden", status, message: baseMessage, body: parsed ?? rawText };
  }
  if (status === 410) {
    return {
      kind: "account_locked",
      status,
      message: baseMessage,
      body: parsed ?? rawText,
      restoreUrl: extractRestoreUrl(parsed),
    };
  }
  if (status === 429) {
    const retryAfter = resp.headers.get("retry-after");
    const retryAfterSeconds = retryAfter ? parseRetryAfter(retryAfter) : undefined;
    return {
      kind: "rate_limited",
      status,
      message: baseMessage,
      body: parsed ?? rawText,
      retryAfterSeconds,
    };
  }
  return {
    kind: status >= 500 ? "http_5xx" : "http_4xx",
    status,
    message: baseMessage,
    body: parsed ?? rawText,
  };
}

/** Pull restore_url out of FastAPI's `detail: {error, restore_url}` envelope. */
function extractRestoreUrl(body: unknown): string | undefined {
  if (!body || typeof body !== "object") return undefined;
  const b = body as Record<string, unknown>;
  const detail = b.detail;
  if (detail && typeof detail === "object" && !Array.isArray(detail)) {
    const d = detail as Record<string, unknown>;
    if (typeof d.restore_url === "string") return d.restore_url;
  }
  if (typeof b.restore_url === "string") return b.restore_url;
  return undefined;
}

/** Retry-After is either delta-seconds or an HTTP-date. We handle both. */
function parseRetryAfter(value: string): number | undefined {
  const asNumber = Number(value.trim());
  if (Number.isFinite(asNumber) && asNumber >= 0) return asNumber;
  const asDate = Date.parse(value);
  if (!Number.isNaN(asDate)) {
    const delta = Math.ceil((asDate - Date.now()) / 1000);
    return delta > 0 ? delta : 0;
  }
  return undefined;
}

function extractErrorMessage(body: unknown): string | undefined {
  if (!body || typeof body !== "object") return undefined;
  const b = body as Record<string, unknown>;
  // FastAPI validation error shape
  if (typeof b.detail === "string") return b.detail;
  if (Array.isArray(b.detail) && b.detail.length > 0) {
    const first = b.detail[0] as Record<string, unknown> | undefined;
    if (first && typeof first.msg === "string") return first.msg;
  }
  if (typeof b.message === "string") return b.message;
  if (typeof b.error === "string") return b.error;
  return undefined;
}

// ── Public client shape ───────────────────────────────────────────
//
// Mobile + landing + extension were each maintaining their own typed
// wrappers around overlapping endpoint subsets. The audit (shared
// MEDIUM "CleanwayClient covers 3 of 30+ API endpoints; extension-core
// maintains a parallel raw-fetch client with no shared types") flagged
// this as the biggest drift risk we'd been carrying. This file now
// exposes the full user/family/payments/breach/phone/auth/public/
// referral surface — every consumer reads from one source of typed
// truth, and adding a new endpoint is one TS file edit instead of
// three.

import type {
  AcceptInviteRequest,
  AcceptInviteResponse,
  AuthCheckEmail,
  BreachCheck,
  BreachDomain,
  CheckoutRequest,
  CheckoutResponse,
  CreateFamilyRequest,
  CreateFamilyResponse,
  DeleteAccountResponse,
  GdprExport,
  MyFamiliesResponse,
  PercentileResponse,
  PhoneLookup,
  PortalResponse,
  PublicStats,
  ReferralGenerate,
  ReferralStats,
  RestoreAccountResponse,
  ThreatStatus,
  UserProfile,
  UserSettings,
  UserSettingsUpdate,
} from "@cleanway/api-types";

export interface CleanwayClient {
  readonly baseUrl: string;
  health(): Promise<Result<HealthResponse>>;
  check: {
    /** Public domain check (no auth required). Rate limited by IP. */
    publicDomain(domain: string): Promise<Result<DomainResult>>;
  };
  pricing: {
    /** Regional pricing for a detected/selected country (ISO 3166-1 alpha-2). */
    forCountry(cc?: string | null): Promise<Result<PricingFor>>;
    /** All 4 tiers with country lists (admin/debug). */
    tiers(): Promise<Result<PricingTiers>>;
  };
  user: {
    /** GET /user/profile — devices_count + member_since + tier. */
    profile(): Promise<Result<UserProfile>>;
    /** GET /user/settings — skill_level + voice + font + parental PIN flag. */
    settings(): Promise<Result<UserSettings>>;
    /** PUT /user/settings — partial update of any settings field. */
    updateSettings(patch: UserSettingsUpdate): Promise<Result<UserSettings>>;
    /** GET /user/threats/status — freemium-threshold + gating state. */
    threatStatus(): Promise<Result<ThreatStatus>>;
    /** POST /user/threats/increment — bump lifetime block counter (best-effort). */
    incrementThreats(count?: number): Promise<Result<ThreatStatus>>;
    /** GET /user/percentile — "safer than X% of users this week". */
    percentile(): Promise<Result<PercentileResponse>>;
    /** GET /user/export — GDPR Art. 15 full SAR JSON dump. */
    exportData(): Promise<Result<GdprExport>>;
    /** DELETE /user/account — mark for deletion with 30-day grace. */
    deleteAccount(): Promise<Result<DeleteAccountResponse>>;
    /** POST /user/account/restore — cancel pending deletion. */
    restoreAccount(): Promise<Result<RestoreAccountResponse>>;
    /** POST /user/welcome — idempotent welcome-email trigger. */
    welcome(): Promise<Result<unknown>>;
  };
  payments: {
    /** POST /payments/checkout — Stripe Checkout session URL. */
    checkout(req: CheckoutRequest): Promise<Result<CheckoutResponse>>;
    /** POST /payments/portal — Stripe Customer Portal link. */
    portal(): Promise<Result<PortalResponse>>;
  };
  family: {
    /** GET /family/mine — all families this user belongs to. */
    mine(): Promise<Result<MyFamiliesResponse>>;
    /** POST /family — create a new family (caller becomes owner). */
    create(req: CreateFamilyRequest): Promise<Result<CreateFamilyResponse>>;
    /** POST /family/accept — redeem (code, PIN) invite. */
    acceptInvite(req: AcceptInviteRequest): Promise<Result<AcceptInviteResponse>>;
    /** POST /family/{family_id}/invite — generate one-time invite. */
    createInvite(familyId: string): Promise<Result<unknown>>;
    /** GET /family/{family_id}/members — public keys per member. */
    listMembers(familyId: string): Promise<Result<unknown>>;
  };
  breach: {
    /** GET /breach/check/{prefix} — HIBP-style k-anonymity check (5-hex prefix). */
    check(hashPrefix: string): Promise<Result<BreachCheck>>;
    /** GET /breach/domain/{domain} — domain-level breach reports. */
    domain(domain: string): Promise<Result<BreachDomain>>;
  };
  phone: {
    /** GET /phone/lookup/{hash} — phone-number reputation (SHA-1 prefix). */
    lookup(phoneHash: string): Promise<Result<PhoneLookup>>;
  };
  auth: {
    /** POST /auth/check-email — disposable / typo signal pre-signup. */
    checkEmail(email: string): Promise<Result<AuthCheckEmail>>;
  };
  publicApi: {
    /** GET /public/stats — homepage live counters (no auth). */
    stats(): Promise<Result<PublicStats>>;
  };
  referral: {
    /** POST /referral/generate — caller's referral code. */
    generate(): Promise<Result<ReferralGenerate>>;
    /** GET /referral/stats — caller's referral metrics. */
    stats(): Promise<Result<ReferralStats>>;
  };
}

export function createClient(opts: ClientOptions): CleanwayClient {
  return {
    baseUrl: opts.baseUrl,

    health() {
      return request<HealthResponse>(opts, "GET", "/health");
    },

    check: {
      publicDomain(domain: string) {
        // Domain normalization: strip protocol + trailing slash so consumers can't
        // accidentally send a full URL (which would break privacy invariant).
        const clean = domain
          .trim()
          .toLowerCase()
          .replace(/^https?:\/\//, "")
          .replace(/\/.*$/, "");
        return request<DomainResult>(
          opts,
          "GET",
          `/api/v1/public/check/${encodeURIComponent(clean)}`,
        );
      },
    },

    pricing: {
      forCountry(cc?: string | null) {
        const q = cc && cc.trim() ? `?cc=${encodeURIComponent(cc.trim().toUpperCase())}` : "";
        return request<PricingFor>(opts, "GET", `/api/v1/pricing/for-country${q}`);
      },
      tiers() {
        return request<PricingTiers>(opts, "GET", "/api/v1/pricing/tiers");
      },
    },

    user: {
      profile() {
        return request<UserProfile>(opts, "GET", "/api/v1/user/profile");
      },
      settings() {
        return request<UserSettings>(opts, "GET", "/api/v1/user/settings");
      },
      updateSettings(patch) {
        return request<UserSettings>(opts, "PUT", "/api/v1/user/settings", patch);
      },
      threatStatus() {
        return request<ThreatStatus>(opts, "GET", "/api/v1/user/threats/status");
      },
      incrementThreats(count = 1) {
        return request<ThreatStatus>(opts, "POST", "/api/v1/user/threats/increment", { count });
      },
      percentile() {
        return request<PercentileResponse>(opts, "GET", "/api/v1/user/percentile");
      },
      exportData() {
        return request<GdprExport>(opts, "GET", "/api/v1/user/export");
      },
      deleteAccount() {
        return request<DeleteAccountResponse>(opts, "DELETE", "/api/v1/user/account");
      },
      restoreAccount() {
        return request<RestoreAccountResponse>(opts, "POST", "/api/v1/user/account/restore");
      },
      welcome() {
        return request<unknown>(opts, "POST", "/api/v1/user/welcome");
      },
    },

    payments: {
      checkout(req) {
        return request<CheckoutResponse>(opts, "POST", "/api/v1/payments/checkout", req);
      },
      portal() {
        return request<PortalResponse>(opts, "POST", "/api/v1/payments/portal");
      },
    },

    family: {
      mine() {
        return request<MyFamiliesResponse>(opts, "GET", "/api/v1/family/mine");
      },
      create(req) {
        return request<CreateFamilyResponse>(opts, "POST", "/api/v1/family", req);
      },
      acceptInvite(req) {
        return request<AcceptInviteResponse>(opts, "POST", "/api/v1/family/accept", req);
      },
      createInvite(familyId) {
        return request<unknown>(
          opts,
          "POST",
          `/api/v1/family/${encodeURIComponent(familyId)}/invite`,
        );
      },
      listMembers(familyId) {
        return request<unknown>(
          opts,
          "GET",
          `/api/v1/family/${encodeURIComponent(familyId)}/members`,
        );
      },
    },

    breach: {
      check(hashPrefix) {
        // The path takes a SHA-1 hex 5-char prefix. Caller is responsible
        // for hashing; we don't reach into Web Crypto from here.
        const clean = hashPrefix.trim().toLowerCase();
        return request<BreachCheck>(
          opts,
          "GET",
          `/api/v1/breach/check/${encodeURIComponent(clean)}`,
        );
      },
      domain(domain) {
        const clean = domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
        return request<BreachDomain>(
          opts,
          "GET",
          `/api/v1/breach/domain/${encodeURIComponent(clean)}`,
        );
      },
    },

    phone: {
      lookup(phoneHash) {
        const clean = phoneHash.trim().toLowerCase();
        return request<PhoneLookup>(
          opts,
          "GET",
          `/api/v1/phone/lookup/${encodeURIComponent(clean)}`,
        );
      },
    },

    auth: {
      checkEmail(email) {
        return request<AuthCheckEmail>(opts, "POST", "/api/v1/auth/check-email", { email });
      },
    },

    publicApi: {
      stats() {
        return request<PublicStats>(opts, "GET", "/api/v1/public/stats");
      },
    },

    referral: {
      generate() {
        return request<ReferralGenerate>(opts, "POST", "/api/v1/referral/generate");
      },
      stats() {
        return request<ReferralStats>(opts, "GET", "/api/v1/referral/stats");
      },
    },
  };
}

// Re-export the underlying types so consumers don't need 2 imports
export type {
  AcceptInviteRequest,
  AcceptInviteResponse,
  AuthCheckEmail,
  BreachCheck,
  BreachDomain,
  CheckoutRequest,
  CheckoutResponse,
  CreateFamilyRequest,
  CreateFamilyResponse,
  DeleteAccountResponse,
  DomainResult,
  GdprExport,
  HealthResponse,
  MyFamiliesResponse,
  PercentileResponse,
  PhoneLookup,
  PortalResponse,
  PricingFor,
  PricingTiers,
  PublicStats,
  ReferralGenerate,
  ReferralStats,
  RestoreAccountResponse,
  ThreatStatus,
  UserProfile,
  UserSettings,
  UserSettingsUpdate,
} from "@cleanway/api-types";
