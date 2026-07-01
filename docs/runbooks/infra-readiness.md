# Infrastructure readiness runbook

How the stack holds up under real load, what fails gracefully, what to
monitor. This doc is for the operator — when something breaks, start
here.

## Deploy chain — the happy path

```
developer push                      │
  └→ github.com/AlexMos555/linkshield
        ├→ GitHub Actions: CI      (pytest + ruff + coverage)
        ├→ GitHub Actions: Security (gitleaks, bandit, pip-audit, trivy, hadolint)
        ├→ GitHub Actions: E2E      (Playwright landing suite)
        ├→ GitHub Actions: deploy-staging  (optional — manual dispatch)
        └→ Railway auto-deploy      (main branch → production API)
             ├→ Nixpacks builder reads railway.json + requirements.txt
             ├→ Railway security scanner blocks on CVE (e.g., next@CVE-*)
             └→ `uvicorn api.main:app` on $PORT (Procfile)
```

## Component status map

| Component | Where | Health probe | Failure mode |
|---|---|---|---|
| API (FastAPI) | Railway `honest-playfulness-web` | `GET /health` → 200 "ok"/"degraded" | Rolling deploy — old pod stays up until new passes healthcheck |
| Redis (rate limiter) | Not provisioned yet | — | Rate limiters fail-open; requests always served |
| Supabase Postgres EU | `bpyqgzzclsbfvxthyfsf.supabase.co` | `supabase projects api list --project-ref bpyqgzzclsbfvxthyfsf` | API endpoints that hit Supabase return 503 degraded; reads of `users`/`subscriptions` fall back to defaults |
| Landing (Next.js 15.1.11) | Vercel project `cleanway-landing` | Prod URL → 200 | Last-known-good SSG served; deployments auto-promote |
| Extension (Chrome/FF/Safari) | Self-hosted until store publish | Built via `bash scripts/build-extensions.sh` | User reloads from `chrome://extensions` |
| Mobile (Expo) | TestFlight / Play Internal | `expo dev` | Guest mode keeps working without backend |

## Graceful degradation (tested)

These failures are **handled** — service stays available in a reduced mode:

- **Redis down** (current production state): rate limiter returns full quota
  and logs a warning. Request processing untouched. Side-effect: user can
  burn through daily quota in a burst.
- **Supabase down**: user-scoped endpoints return defaults (empty whitelist,
  default skill level). Writes fail with 503; client retries on reconnect.
- **Safe Browsing API quota exhausted**: circuit breaker opens for 60s
  (`api/services/circuit_breaker.py`); scoring falls through to rules + ML.
  After cooldown the breaker half-opens and tests a single request.
- **ML model missing** (e.g., `data/phishing_model.cbm` gitignored again):
  scoring drops 35 points on phishing signal, test_scoring_pipeline has
  a fallback assertion path so CI doesn't red-flag logic changes.
- **catboost import fails**: `ml_scorer._load_model()` returns False, ML
  signal skipped. Heuristics still flag obvious phishing at "suspicious".

## Known footguns

1. **Railway security scanner is aggressive**. It refuses to deploy on any
   CVE in `package-lock.json`. When `next` gets a new CVE we hit
   "Deployment failed" with no obvious link to the cause. Fix:
   `npm install next@latest-patched` in `landing/` + update root lockfile
   via `npm install` at the monorepo root. Lock patch version in
   `package.json > overrides` so transitive deps (like `react-email`'s
   nested copy) don't regress.

2. **next-intl + Next.js patches sometimes break prerender** of error
   pages (`/_error`, `/500`) with React error #31. If `npm run build`
   fails after a next upgrade, fully wipe `node_modules` and
   `package-lock.json` and `npm install` fresh. Partial upgrades from
   the workspace root leave stale transitive copies that collide.

3. **ML feature extractor shared between training + inference**. Both
   `ml/train_model.py` and `api/services/ml_scorer.py` must import
   `extract_ml_features` from `api/services/ml_features.py`. Adding a
   feature there requires retraining (`python3 ml/train_model.py`) + new
   `data/phishing_model.cbm` checked in.

4. **CORS allowlist is a hot surface**. Every webmail provider we want to
   support must be added to both `api/config.py` default `allowed_origins`
   AND each of the three `manifest.json` files (Chrome MV3, Firefox MV2,
   Safari MV3). The extension-core sync script only copies src/, not
   manifests — those are per-browser by design.

5. **Pydantic settings are lazily cached**. `get_settings()` uses
   `@lru_cache` so test-time env var mutations won't take effect unless
   you call `get_settings.cache_clear()`. Production startup is a
   one-shot read so it's fine.

## Capacity planning (guardrails)

Today we have **zero paid traffic** and a free-tier Supabase + Railway
that can handle burst 100 RPS without noticing.

Targets for launch:

- **Sustained**: 50 RPS per Railway pod (Uvicorn default)
- **Burst**: 500 RPS with 5 pods (manually scale via Railway dashboard;
  we have no auto-scale wired yet — this is Phase I)
- **DB pool**: Supabase free tier = 60 concurrent connections → ~12 per
  pod is safe (we peak lazily, not held)

Scaling levers when sustained RPS climbs:

1. **Add Redis** (Upstash free tier) — unlocks the rate limiter and
   caches Safe Browsing verdicts (cuts 40 % of GSB API calls).
2. **Scale Railway replicas** — Procfile is stateless; horizontal scale
   just works.
3. **Supabase pooler** — move from direct connection to connection
   pooler (pgBouncer URL in Supabase dashboard). Bumps concurrent ceiling
   from 60 to ~10 000.
4. **CDN Safe Browsing cache** — move GSB responses into edge KV instead
   of Redis when you expect to outgrow Redis's pricing.

## Pre-launch checklist

Done ✅:
- [x] FastAPI API serves on Railway from `main`
- [x] CORS default allows webmail + landing origins
- [x] `/email/analyze` accepts anonymous + authenticated
- [x] Migration 001–004 applied on production Supabase
- [x] Landing builds clean (`next build` → 65 static pages)
- [x] 373 unit tests pass
- [x] CI workflows green after CVE + lint fixes
- [x] Extension manifests permit webmail host access

Pending (operator actions — I cannot do these without credentials):
- [ ] **Apply migration 005** (scam_protection schema):
      `supabase db push --project-ref bpyqgzzclsbfvxthyfsf` — or paste the
      SQL into the Supabase SQL Editor. Until this lands, the phone/scam
      endpoints will return 503 or silently accept-no-op.
- [ ] **Wire Redis** (Upstash free tier works). Set `REDIS_URL` in
      Railway env. Rate limiter goes from fail-open to enforce.
- [ ] **Set `ENVIRONMENT=production`** on Railway when we go paid. Right
      now default development tolerates missing sk_live_ keys etc.
- [ ] **Rotate Vercel API tokens + enable 2FA** (incident response —
      see `docs/runbooks/vercel-incident-response.md`).
- [ ] **Supabase database backup** schedule — Supabase auto-snapshots on
      paid tiers; free tier has none. Budget for Pro ($25/mo) before
      sending first production email.
- [ ] **Sentry DSN** in Railway env (`SENTRY_DSN=...`). Sentry is wired
      but dormant without the DSN.
- [ ] **Uptime probe** (UptimeRobot free tier or Better Stack). Hit
      `/health` every 5 min; alert on >60s downtime.

## If /health returns 5xx or the pod crash-loops

1. `gh api repos/AlexMos555/linkshield/commits/<sha>/status` — look at
   `honest-playfulness - web` for the Railway deploy URL.
2. Open the URL → Deployments → click the failed deploy → Build logs.
   Common failures:
   - `ModuleNotFoundError: No module named '<pkg>'` — add to
     `requirements.txt`, commit, push.
   - CVE blocker ("SECURITY VULNERABILITIES DETECTED") — upgrade the
     flagged package, add a `npm overrides` entry if transitive.
   - `ConfigError: <env var> is required in environment=production` —
     either set the env var in Railway, or unset `ENVIRONMENT` to drop
     to dev rules.
3. **Rollback**: Railway dashboard → Deployments → last green → Redeploy.
   RTO: ~90 seconds.
4. **If Railway dashboard is down**: the API's last successful deploy
   keeps serving (Railway does zero-downtime rollouts). New pushes just
   queue.

## Observability gaps

We currently log structured JSON to stdout (Railway aggregates). Gaps:

- **No APM**. Sentry wires errors only, not traces. Add OpenTelemetry →
  Honeycomb when traffic justifies ($90/mo).
- **No p95 latency dashboard**. Request logs are emitted but not
  aggregated. Short-term: `railway logs --filter 'elapsed_ms' | jq` by
  hand when debugging.
- **No DB query insight**. Supabase provides a Query Performance tab
  that shows slow queries — check weekly.

Phase I candidates: pgbouncer metrics, pod-level memory/CPU in Grafana,
user-flow RED dashboards.
