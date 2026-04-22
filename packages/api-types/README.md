# @cleanway/api-types

**Generated** TypeScript types for the Cleanway FastAPI backend. Single source of truth for the HTTP contract.

## Why

Before: every client (landing, mobile, extension) invented its own `interface DomainResult { ... }` — usually wrong in subtle ways (missing `confidence`, wrong enum for `level`). API evolves, clients silently break.

**Now:** FastAPI → OpenAPI spec → auto-generated TypeScript types → every client imports the SAME types.

## How it regenerates

```bash
npm run build:api-types     # from monorepo root
# or: bash scripts/generate-api-types.sh
```

The script:
1. Boots the FastAPI app in-process (no HTTP server)
2. Calls `app.openapi()` to dump the current OpenAPI 3.1 spec → `schema/openapi.json`
3. Runs `openapi-typescript` to emit `src/openapi.d.ts`
4. `src/index.ts` re-exports hand-picked types with friendly aliases

## How to use

```typescript
import type { DomainResult, PricingFor, RiskLevel } from "@cleanway/api-types";

function renderBadge(result: DomainResult) {
  if (result.level === "dangerous") return "🔴";
  if (result.level === "caution") return "🟡";
  return "🟢";
}
```

Or for direct path-based access (advanced):

```typescript
import type { paths } from "@cleanway/api-types";

type ThisEndpointResponse = paths["/api/v1/check"]["post"]["responses"][200]["content"]["application/json"];
```

## Invariant

**Never** hand-edit `src/openapi.d.ts`. It's regenerated on every build. Safe to edit: `src/index.ts` (the alias layer).

The generated file is checked into git — consumers don't need to run Python to get types.

## When the backend changes

1. You change `api/routers/foo.py` or a Pydantic model
2. Run `npm run build:api-types`
3. Commit both the `.py` and the updated `packages/api-types/src/openapi.d.ts` + `schema/openapi.json`
4. Landing/mobile/extension now see the new types; type errors surface at build time, not at runtime
