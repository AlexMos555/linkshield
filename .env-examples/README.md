# Environment configuration

Three deployable environments:

| | Purpose | Runs where | Who uses it |
|---|---|---|---|
| **development** | Local laptop + CI test jobs | Your machine / `docker compose` | Developers |
| **staging** | Pre-prod validation | Railway staging service + Vercel previews | Team QA, beta testers (optional) |
| **production** | Real users | Railway prod service + Vercel prod | Everyone |

## Files in this folder

- `.env.development` — copy to `/.env` at repo root when working locally
- `.env.staging` — reference ONLY; real values live in Railway staging dashboard
- `.env.production` — reference ONLY; real values live in Railway prod dashboard

None of these are actually `.env` — they're examples. The real `.env` is gitignored.

## Invariants enforced at startup

See `api/config.py` → `validate_settings()`. Any of these fail → container refuses to boot:

| Invariant | Where |
|---|---|
| `ENVIRONMENT` ∈ {development, staging, production} | config validation |
| `DEBUG=true` requires `ENVIRONMENT=development` | config validation |
| Production requires `SUPABASE_JWT_SECRET` ≥64 chars | config validation |
| Production requires `STRIPE_SECRET_KEY` starts with `sk_live_` | config validation |
| Production requires `EMAIL_PROVIDER ≠ noop` | config validation |
| Production requires `SENTRY_DSN` set | config validation |
| Staging refuses `sk_live_*` Stripe keys (cannot charge real cards from staging) | config validation |

This stops "oops I shipped dev creds to prod" dead at startup — the container crashes on boot instead of silently running with wrong config.

## Setup sequence for a new environment

### Local dev (one-time)
```bash
cp .env-examples/.env.development .env
# edit .env with your real dev Supabase keys (DM them securely)
docker compose up -d redis
pytest tests/ -q       # should all pass
```

### Staging (one-time setup, then deploys automatically)
1. Create a new Supabase project in the EU region (e.g. `linkshield-staging`)
2. Apply migrations: `supabase db push` pointed at the staging project
3. Create a Railway service `linkshield-api-staging`, connect this repo, branch = main
4. Paste every key from `.env-examples/.env.staging` into Railway's env vars UI
5. In Vercel, create a "staging" environment; set `NEXT_PUBLIC_*` vars to staging values
6. Confirm staging deploys automatically on merge to `main`

### Production (one-time setup, then manual deploys via GitHub Action dispatch)
1. Create production Supabase project (EU for latency, separate from staging)
2. Apply migrations
3. Railway service `linkshield-api-prod`, but deploys triggered by GitHub Action workflow_dispatch (NOT automatic on main)
4. AWS: verify domain in SES, request production access, set up DKIM DNS records
5. Stripe: flip to live mode, create 24 regional price IDs (see `.planning/PRICING_MATRIX.md`)
6. All env vars in Railway prod dashboard — NONE in the repo
7. Smoke test via admin-only endpoint before announcing

## What never leaves staging

Staging is not just "prod with lower limits" — these are structurally different:

- **No real customer emails sent.** Even if `EMAIL_PROVIDER=resend` in staging, the sending domain is a test domain that is sandboxed.
- **No real money.** Stripe test mode only — `sk_test_*` keys.
- **Different Supabase project.** Staging DB gets wiped quarterly. Never load real user PII there.
- **Different Sentry project.** Keeps prod Sentry signal clean.

## Rotation

See `SECURITY.md` § "Secret Rotation Procedure". TL;DR: quarterly for Supabase JWT + Stripe + GSB. After any exposure: immediately + audit access logs.
