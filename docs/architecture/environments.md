# Environments

Cleanway runs in **two** environments: a developer's machine and production.
There is no staging (rewritten 2026-10-22; the earlier version of this page
described a staging tier, a manual production dispatch and a second-person
approval that never existed).

## Overview

```
  developer laptop                 GitHub main
  (make dev / docker compose)          │
                                       ├─→ Railway auto-deploy → production API + DNS gateway
  PR ──→ CI + Vercel preview           └─→ Vercel auto-deploy  → production landing
```

| Aspect | Development | Production |
|---|---|---|
| **Where** | your laptop | Railway project `honest-playfulness`, service `web` (EU West, 2 replicas) + `Redis`; Vercel for the landing |
| **Trigger** | `make dev` / `docker compose up` | every merge to `main` (Railway's and Vercel's GitHub integrations) |
| **Supabase** | local `supabase start`, or a throwaway project | `bpyqgzzclsbfvxthyfsf` (EU); migrations applied by hand (`docs/runbooks/deploy.md`) |
| **Stripe** | `sk_test_*` | live keys |
| **Email** | `EMAIL_PROVIDER=noop` (nothing is sent) | Resend (`alerts@` / sign-in codes through Supabase SMTP, `docs/runbooks/sign-in-email.md`) |
| **Sentry** | off (no `SENTRY_DSN`) | backend DSN in Railway; events carry `release` (the Railway commit) and `environment` (`api/services/sentry_setup.py`) |
| **Domains** | `localhost:8000` | `api.cleanway.ai`, `dns.cleanway.ai`, `cleanway.ai` |
| **Debug mode** | allowed | forbidden (`validate_settings`) |
| **Health** | — | `/health` (Railway liveness), `/health/deep`, `/health/doh` — watched by `ops/uptime-worker` every minute |
| **Rollback** | — | Railway / Vercel redeploy of the previous build (`docs/runbooks/rollback.md`) |
| **Backups** | — | Supabase's own + nightly encrypted copy in R2 (`docs/runbooks/restore.md`) |

Pull requests get a Vercel preview of the landing; the API has no preview —
CI (`.github/workflows/ci.yml`, `security.yml`, `e2e-landing.yml`) is the gate.
`deploy-staging.yml` and `deploy-production.yml` are unused leftovers of the
planned three-tier setup; do not run them.

`ENVIRONMENT=staging` is still a valid setting (`api/config.py`), so a staging
service can be added later: a second Railway environment with its own
Supabase project, Stripe test keys and secrets — never copied from production.

## Environment detection

- **Backend:** `settings.environment` — `Literal["development", "staging", "production"]`.
  Production hides `/docs` and `/openapi.json` (`GET /` shows `"docs": null`).
- **Landing / mobile:** build-time public env (`NEXT_PUBLIC_*`, `EXPO_PUBLIC_*`) points at the API.
- **Extensions:** not environment-aware (API URL override via `chrome.storage.local.api_url`).

## Secrets

Never copied from one environment to another and never committed:
Railway → `web` → Variables, Vercel → Settings → Environment Variables,
GitHub → Settings → Secrets and variables → Actions.
