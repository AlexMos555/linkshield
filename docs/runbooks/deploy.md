# Runbook: Deploy

Promotes code from GitHub main → staging (automatic) → production (manual with approval).

## The short version

```
1. Open a PR.
2. CI runs tests. If green → merge to main.
3. Merge to main auto-deploys to STAGING.
4. Smoke-test staging (5 minutes of clicks or automated E2E).
5. Trigger the "Deploy to production" GitHub Action manually.
6. Approve in the GitHub UI (second team member).
7. Watch metrics for 10 min post-deploy.
```

## Detail

### Step 1: Open a PR

- Branch name: `feat/xyz`, `fix/abc`, `refactor/qqq`
- PR description must include:
  - What changed and why
  - Migration files added/changed (if any)
  - Env vars added (so Railway/Vercel can be updated before deploy)
  - Rollback note: "how do we undo this if it breaks in prod?"

### Step 2: CI must pass

Required checks before merge is enabled:
- `test` — pytest suite (250+ tests)
- `lint` — ruff on api/, tests/, ml/
- `security/gitleaks` — no committed secrets
- `security/bandit` — no Python SAST findings
- `security/pip-audit` — no known CVEs in deps
- `security/trivy-image` — no HIGH/CRITICAL container CVEs

Landing PRs get an automatic Vercel preview URL. Smoke-test the preview before merging.

### Step 3: Merge → auto-deploy to staging

Happens automatically via `.github/workflows/deploy-staging.yml`:
- Pulls latest main
- Builds Docker image, tags with git SHA
- Pushes to Railway staging service
- Runs schema migrations on staging Supabase
- Smoke-test: GET `/health` must return 200 within 60s of deploy

If any step fails, the staging service rolls back to the previous image automatically.

### Step 4: Smoke-test staging

Minimum checks before promoting to prod:

- [ ] `curl https://api-staging.yourdomain/health` returns `{"status":"ok"}`
- [ ] Load the staging landing page in a browser, verify LanguageSwitcher works
- [ ] Trigger a test email: admin endpoint should deliver to your inbox via Resend sandbox
- [ ] Load the extension's popup against the staging API URL (via Options page override)
- [ ] Check Sentry staging project for any startup errors

### Step 5: Trigger production deploy

1. Go to **GitHub → Actions → Deploy to production**
2. Click **Run workflow**
3. Select branch: `main`
4. Optional: enter a commit SHA to pin (defaults to HEAD)
5. Click **Run workflow**

### Step 6: Approval gate

The workflow pauses at the `production` environment gate. A **second team member** must approve via the GitHub UI:
- Navigate to the running workflow
- Click **Review deployments** → check **production** → **Approve and deploy**

Why: two-person rule prevents accidental/malicious prod deploys. A single compromised GitHub account can't push to prod alone.

### Step 7: Watch the deploy

After approval:
- Railway builds and deploys the prod image
- Supabase migrations run (if any)
- `/health` is polled every 10s for 2 min; workflow fails if not green

**During and 10 min after:**
- Watch **Sentry prod** for a spike in errors
- Watch **Railway logs** for stack traces or weird patterns
- Watch **Stripe dashboard** if the deploy touched payments — any webhook failures?

If anything looks wrong → [rollback](rollback.md) immediately. Five-minute RTO.

## Deploy approval policy

| Deploy type | Who approves | Required CI checks |
|---|---|---|
| Landing-only change | 1 engineer | lint, build |
| Extension-only change (no server API change) | 1 engineer | all |
| Backend code change | 1 engineer + ops lead | all |
| Schema migration | 1 engineer + ops lead, migration reviewed | all |
| Stripe-touching code | 1 engineer + finance lead | all |
| Multi-component change | 1 engineer + ops lead | all |

## Common issues

### "CI is red but I'm sure it's a flake"

Re-run the one failed job. If it's red again, it's not a flake. Don't merge.

### "The migration failed on staging"

The Railway deploy auto-rolled back, but the Supabase migration may be in a half-applied state. Check:
```sql
-- Against staging Supabase:
SELECT * FROM pg_stat_activity WHERE state = 'active' AND query LIKE '%migration%';
```
If idle-in-transaction: kill the session, hand-run the migration's inverse, retry deploy.

### "Staging looks fine but prod deploy fails"

Usually an env var missing on the prod Railway service that's present on staging. Compare:
```bash
railway variables --environment staging > /tmp/staging.txt
railway variables --environment production > /tmp/prod.txt
diff /tmp/staging.txt /tmp/prod.txt
```

### "I need to hotfix prod without going through staging"

**Only with ops lead approval.** Procedure:
1. Branch from `main` as `hotfix/abc`
2. Make the minimal fix
3. Self-merge (bypass review ONCE, document why in PR)
4. Deploy workflow with `skip_staging=true` input (audit-logged)
5. File an incident postmortem within 24h explaining why staging was skipped

Abuse of this path is tracked. More than twice/quarter → we fix the deploy process instead.
