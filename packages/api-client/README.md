# @linkshield/api-client

Typed fetch wrapper for the LinkShield API. Landing, mobile, and extensions import this — never raw `fetch()`.

## Why

Raw `fetch` + hand-rolled types = silent breakage on API changes, inconsistent error handling, no timeout, accidental privacy leaks (sending full URLs instead of domains).

This package:
- **Types from `@linkshield/api-types`** (single source of truth)
- **Result type** instead of throwing — `{ data, error }`, typed error kinds
- **Timeout** (8s default, abortable) — no hanging requests
- **Bearer token via callback** — works with async JWT retrieval (Supabase `getSession`)
- **No cookies** — stateless API, JWT only, prevents CSRF by design
- **Domain normalization** — consumer passes `"example.com"` or `"https://example.com/path"`, we strip to domain before sending (privacy invariant)

## Usage

```typescript
import { createClient } from "@linkshield/api-client";

const api = createClient({
  baseUrl: process.env.NEXT_PUBLIC_API_URL!,
  timeoutMs: 5000,
  getAuthToken: async () => {
    const { data } = await supabase.auth.getSession();
    return data.session?.access_token ?? null;
  },
});

// Public domain check
const { data, error } = await api.check.publicDomain("sberbank-fake.ru");
if (error) {
  if (error.kind === "timeout") showToast("Network slow, try again");
  else showError(error.message);
  return;
}
if (data.level === "dangerous") showBlockPage(data);

// Pricing for user's detected country
const { data: pricing } = await api.pricing.forCountry("IN");
if (pricing) {
  render(pricing.plans.personal.monthly.amount);  // 1.49 for T4 India
}
```

## Adding a new endpoint

1. Add the route in `api/routers/foo.py`
2. Run `npm run build:api-types` (regenerates `@linkshield/api-types`)
3. Add a typed method here in `src/index.ts`:
   ```typescript
   foo: {
     doThing(input: SomeType) {
       return request<SomeResponse>(opts, "POST", "/api/v1/foo/bar", input);
     }
   }
   ```
4. Export it via the `LinkShieldClient` interface

## Error taxonomy

| `kind`              | When |
|---------------------|------|
| `network`           | fetch threw — offline, DNS, CORS, TLS |
| `timeout`           | `AbortController` fired before response |
| `http_4xx`          | Server returned 4xx (use `error.status` for exact) |
| `http_5xx`          | Server returned 5xx |
| `invalid_json`      | Response wasn't parseable JSON |
| `contract_mismatch` | (future) Runtime Zod validation failed |

Design principle: consumers should be able to `switch (error.kind)` without ever touching the raw status code.

## Privacy invariants enforced here

1. **Only domains, never full URLs.** `check.publicDomain()` strips protocol + path before sending. Even if a caller passes `https://bank.com/accounts/me?balance=…`, only `bank.com` reaches the server.
2. **No cookies.** `credentials: "omit"` on every request — prevents ambient-auth CSRF and keeps the API stateless.
3. **Bearer tokens only via callback.** Never stored in the client object — re-fetched per request so rotated tokens take effect immediately.
