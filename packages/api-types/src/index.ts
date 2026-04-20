/**
 * @linkshield/api-types — public entry point.
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

// ── Re-export the raw OpenAPI types for power users ─────────────
export type { paths, components, operations } from "./openapi";
