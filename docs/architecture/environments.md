# Environments

Cleanway runs in three isolated environments. Each has its own Supabase project, Stripe mode, Sentry project, and email provider configuration.

## Overview

```
                    ┌──────────────────────────────────┐
                    │        GitHub main branch        │
                    └──────────────┬───────────────────┘
                                   │
                    ┌──────────────┴──────────────────┐
                    │                                 │
                    ▼                                 ▼
          ┌────────────────┐              ┌────────────────────┐
          │  Pull Request  │              │  Push to main      │
          │  preview       │              │  auto-deploys to   │
          │  (Vercel)      │              │  STAGING           │
          └────────────────┘              └──────────┬─────────┘
                                                     │
                                                     ▼
                                       ┌──────────────────────┐
                                       │ STAGING environment  │
                                       │ · Railway staging    │
                                       │ · Vercel staging     │
                                       │ · Supabase staging   │
                                       │ · Stripe TEST mode   │
                                       │ · Resend sandbox     │
                                       └──────────┬───────────┘
                                                  │
                                 (manual GH Action dispatch, requires approval)
                                                  │
                                                  ▼
                                       ┌──────────────────────┐
                                       │ PRODUCTION env       │
                                       │ · Railway prod       │
                                       │ · Vercel prod        │
                                       │ · Supabase prod      │
                                       │ · Stripe LIVE mode   │
                                       │ · SES (real email)   │
                                       │ · Sentry prod        │
                                       └──────────────────────┘
```

## Comparison matrix

| Aspect | Development | Staging | Production |
|---|---|---|---|
| **Where** | Your laptop | Railway + Vercel staging | Railway + Vercel prod |
| **Trigger** | `make dev` / `docker compose up` | Merge to `main` | Manual GitHub Action dispatch |
| **Supabase** | Shared EU project OR local `supabase start` | `dsjkfcllugmlegwymmth` (EU, wiped quarterly) | `bpyqgzzclsbfvxthyfsf` (EU, backed up daily) |
| **Stripe** | `sk_test_*` | `sk_test_*` | `sk_live_*` |
| **Email provider** | `noop` (no sending) | `resend` (sandbox) | `ses` (real) |
| **Sentry** | Disabled | Separate project | Separate project |
| **Custom domain** | `localhost:8000` | `staging.yourdomain` | `yourdomain.com` |
| **Debug mode** | Allowed | Forbidden | Forbidden |
| **JWT min length** | 32 chars | 32 chars | 64 chars |
| **Real users** | 0 | Team + beta | Everyone |
| **Rollback time (RTO)** | N/A | 2 min (Railway redeploy) | 5 min (Railway redeploy) |
| **Data loss tolerance (RPO)** | N/A | 24 hours | 15 min (Supabase PITR on Pro) |

## Why three (not two)

**Why not just dev + prod?**

Staging catches the following classes of bugs before they hit real users:

1. **Environment config bugs.** A setting works on your laptop (because you set it explicitly) but forgot to tell the team → staging deploy fails before prod.
2. **Migration ordering bugs.** Schema change depends on an old row that never existed in dev → staging has real-shape data, catches this.
3. **Third-party changes.** Stripe deprecates an API; Resend changes a webhook format. Staging uses the same providers (test/sandbox mode) so these surface at merge time, not at 3am Saturday.
4. **Race conditions under real network.** Your MacBook loopback never drops packets; real cloud sometimes does. Staging reveals this.

**Why not dev + staging + prod + QA + demo?**

Overhead for a team our size. Three is the minimum safe number.

## Environment detection

All clients (extensions, landing, mobile, backend) should know which environment they're running against:

- **Backend:** `settings.environment` — Literal["development", "staging", "production"]
- **Landing:** `NEXT_PUBLIC_ENVIRONMENT` env var, consumed in `app/layout.tsx` to e.g. show a staging banner
- **Mobile:** `EXPO_PUBLIC_ENVIRONMENT` — similar
- **Extensions:** not environment-aware today (API URL override via `chrome.storage.local.api_url` is the escape hatch)

## Data flow

### Dev → Staging
- Nothing auto-promotes. Each env has its own data.
- To reproduce a prod bug in staging: get sanitized fixture from ops, load into staging.

### Staging → Prod
- **Code:** via GH Action manual dispatch, requires approval (see `docs/runbooks/deploy.md`)
- **Schema migrations:** applied to staging on every PR, applied to prod via the same dispatch
- **Secrets:** NEVER copied from one env to another. Each env has independently generated secrets.

## New environment checklist

When a new person joins or a new region gets its own environment:

- [ ] Fresh Supabase project (separate `ref` — never reuse)
- [ ] Fresh Stripe account in test mode (for staging) or verified live (for prod)
- [ ] Fresh Sentry project
- [ ] Fresh email domain (subdomain of main: `mail-eu.yourdomain.com` for EU prod, say)
- [ ] Add to Vercel environments list
- [ ] Add to Railway services list
- [ ] Update `.env-examples/.env.<name>`
- [ ] Add secrets to Railway/Vercel dashboards (NEVER to a file)
- [ ] Run migrations on the new Supabase
- [ ] Deploy, verify `/health` returns 200
- [ ] Update this document
