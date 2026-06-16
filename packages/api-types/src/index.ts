/**
 * @cleanway/api-types — public entry point.
 *
 * Re-exports hand-picked types from the auto-generated openapi.d.ts
 * with friendly short names that consumers (landing, mobile, extension) import.
 *
 * Adding a new exported type:
 *   1. Find it under `components["schemas"]["<TypeName>"]` in openapi.d.ts
 *   2. Alias it here with a short name
 *   3. The rename ensures we have a clear contract surface (smaller blast radius
 *      on schema changes — consumers use stable aliases, not raw OpenAPI refs)
 */
import type { components, paths } from "./openapi";

// ── Domain check ────────────────────────────────────────────────
export type RiskLevel = components["schemas"]["RiskLevel"];
export type ConfidenceLevel = components["schemas"]["ConfidenceLevel"];
export type DomainResult = components["schemas"]["DomainResult"];
export type CheckRequest = components["schemas"]["CheckRequest"];
export type CheckResponse = components["schemas"]["CheckResponse"];

// ── Pricing (for the landing /pricing page + checkout) ──────────
// NOTE: the pricing endpoints are defined in api/routers/pricing.py; if the
// schema is missing below, run `npm run build:api-types` after the backend
// has /api/v1/pricing/* registered.
export type PricingFor = NonNullable<
  paths["/api/v1/pricing/for-country"]["get"]["responses"][200]["content"]["application/json"]
>;
export type PricingTiers = NonNullable<
  paths["/api/v1/pricing/tiers"]["get"]["responses"][200]["content"]["application/json"]
>;

// ── Health ──────────────────────────────────────────────────────
export type HealthResponse = NonNullable<
  paths["/health"]["get"]["responses"][200]["content"]["application/json"]
>;

// ── User settings + profile + threats ────────────────────────────
//
// Aliased so client code stays insulated from the raw operationId
// names. If the backend renames a route or splits a model, the
// stable alias absorbs the churn at this layer.
export type UserProfile = NonNullable<
  paths["/api/v1/user/profile"]["get"]["responses"][200]["content"]["application/json"]
>;
export type UserSettings = NonNullable<
  paths["/api/v1/user/settings"]["get"]["responses"][200]["content"]["application/json"]
>;
export type UserSettingsUpdate = NonNullable<
  paths["/api/v1/user/settings"]["put"]["requestBody"]
>["content"]["application/json"];
export type ThreatStatus = NonNullable<
  paths["/api/v1/user/threats/status"]["get"]["responses"][200]["content"]["application/json"]
>;
export type DeleteAccountResponse = NonNullable<
  paths["/api/v1/user/account"]["delete"]["responses"][200]["content"]["application/json"]
>;
export type RestoreAccountResponse = NonNullable<
  paths["/api/v1/user/account/restore"]["post"]["responses"][200]["content"]["application/json"]
>;
export type GdprExport = NonNullable<
  paths["/api/v1/user/export"]["get"]["responses"][200]["content"]["application/json"]
>;
export type PercentileResponse = NonNullable<
  paths["/api/v1/user/percentile"]["get"]["responses"][200]["content"]["application/json"]
>;

// ── Payments ────────────────────────────────────────────────────
export type CheckoutRequest = NonNullable<
  paths["/api/v1/payments/checkout"]["post"]["requestBody"]
>["content"]["application/json"];
export type CheckoutResponse = NonNullable<
  paths["/api/v1/payments/checkout"]["post"]["responses"][200]["content"]["application/json"]
>;
export type PortalResponse = NonNullable<
  paths["/api/v1/payments/portal"]["post"]["responses"][200]["content"]["application/json"]
>;

// ── Family Hub ──────────────────────────────────────────────────
export type MyFamiliesResponse = NonNullable<
  paths["/api/v1/family/mine"]["get"]["responses"][200]["content"]["application/json"]
>;
export type CreateFamilyRequest = NonNullable<
  paths["/api/v1/family"]["post"]["requestBody"]
>["content"]["application/json"];
export type CreateFamilyResponse = NonNullable<
  paths["/api/v1/family"]["post"]["responses"][200]["content"]["application/json"]
>;
export type AcceptInviteRequest = NonNullable<
  paths["/api/v1/family/accept"]["post"]["requestBody"]
>["content"]["application/json"];
export type AcceptInviteResponse = NonNullable<
  paths["/api/v1/family/accept"]["post"]["responses"][200]["content"]["application/json"]
>;

// ── Breach + Phone + Auth probes ────────────────────────────────
export type BreachCheck = NonNullable<
  paths["/api/v1/breach/check/{hash_prefix}"]["get"]["responses"][200]["content"]["application/json"]
>;
export type BreachDomain = NonNullable<
  paths["/api/v1/breach/domain/{domain}"]["get"]["responses"][200]["content"]["application/json"]
>;
export type PhoneLookup = NonNullable<
  paths["/api/v1/phone/lookup/{phone_hash}"]["get"]["responses"][200]["content"]["application/json"]
>;
export type AuthCheckEmail = NonNullable<
  paths["/api/v1/auth/check-email"]["post"]["responses"][200]["content"]["application/json"]
>;

// ── Public ──────────────────────────────────────────────────────
export type PublicStats = NonNullable<
  paths["/api/v1/public/stats"]["get"]["responses"][200]["content"]["application/json"]
>;

// ── Referral ────────────────────────────────────────────────────
export type ReferralGenerate = NonNullable<
  paths["/api/v1/referral/generate"]["post"]["responses"][200]["content"]["application/json"]
>;
export type ReferralStats = NonNullable<
  paths["/api/v1/referral/stats"]["get"]["responses"][200]["content"]["application/json"]
>;

// ── Re-export the raw OpenAPI types for power users ─────────────
export type { paths, components, operations } from "./openapi";
