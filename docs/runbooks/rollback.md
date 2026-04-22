# Runbook: Rollback

**RTO target: 5 minutes.** Prod is down or degraded → this document.

## Triage (30 seconds)

1. Is `/health` returning 5xx?
2. Is Sentry prod flooded with errors?
3. Is this deploy-correlated? Check Railway deploys timestamp vs incident start.

If all three: rollback. If unclear: still rollback; investigate after.

## Rollback paths

### Option 1: Railway one-click (fastest, ~90 seconds)

1. Go to **Railway → cleanway-api-prod → Deployments**
2. Find the last green deploy (usually just above the broken one)
3. Click its **⋯** menu → **Redeploy this version**
4. Poll `/health` every 10s until 200 OK

This restores API only. If the issue is in landing or extensions, see below.

### Option 2: Landing (Vercel) rollback (~60 seconds)

1. Vercel dashboard → `landing` project → **Deployments**
2. Find last-known-good deployment
3. Click **⋯** → **Promote to Production**

Vercel's CDN switches instantly; no service restart needed.

### Option 3: Database migration rollback (~5 minutes)

Rolling back a migration is inherently lossy. Do it only if the migration itself is the smoking gun.

**Forward fix preferred.** If migration added a bad constraint, write a new migration that drops it and deploy that.

**True rollback:**
1. Identify the broken migration file (e.g. `003_intl_pricing_skill_levels.sql`)
2. Supabase dashboard → **Database → Backups** → find snapshot from before the migration
3. **Create a new Supabase project** from that snapshot (do NOT restore into prod — always fork)
4. Switch prod `SUPABASE_URL` to point at the new project
5. Redeploy API with the old migration version
6. After stabilization, migrate forward properly

RTO: 30+ min. RPO: up to backup lag (24 hours on free, 2 min on Pro with PITR).

### Option 4: Feature flag (if you're lucky)

If the broken feature is behind an env var, flip it in Railway and redeploy. ~90 seconds, no code change.

```bash
railway variables --environment production --set FEATURE_EMAIL_WEEKLY=false
# Railway auto-redeploys on env change
```

## Post-rollback

Within 30 minutes of the incident end:

1. Announce in #incidents Slack (or ops chat): what broke, what we did, link to this runbook section
2. Open an incident in `.planning/incidents/YYYY-MM-DD-short-slug.md` using this template:

```
# Incident: <short name>

**When:** start → end (UTC)
**Duration:** X minutes
**Severity:** SEV-1 (user-facing) / SEV-2 (degraded) / SEV-3 (internal only)
**Users affected:** estimated count
**Data loss:** yes/no, scope

## Timeline
- HH:MM  Symptom noticed (how, by whom)
- HH:MM  On-call engaged
- HH:MM  Rollback started (which option)
- HH:MM  Service restored
- HH:MM  All-clear

## Root cause
<one paragraph — what actually broke, not what triggered it>

## What worked
<list>

## What didn't
<list, blameless>

## Action items
- [ ] Owner: thing to change so this doesn't happen again
- [ ] Owner: other thing
```

3. Schedule a blameless review within 7 days if SEV-1 or SEV-2.

## Scenarios we've trained for

### "Supabase is down"
- API gracefully degrades (see `api/services/analyzer.py` circuit breakers)
- Extension continues working with bloom filter + local scoring
- Landing `/pricing` falls back to base-tier defaults (already wired in `pricing/page.tsx`)
- No rollback needed; wait for Supabase recovery

### "Stripe webhook signature verification breaks"
- Payments stop reconciling. Subscriptions stay valid until renewal tries.
- Rollback the deploy that introduced the issue OR rotate webhook secret if that's the problem.

### "One locale renders broken HTML"
- Falls back to English in both email (i18n helper) and client UIs (next-intl/i18next fallbackLng: en)
- No user sees broken HTML; they just see English
- Not urgent — fix in next deploy

### "Half the users get dev-mode block page"
- Indicates env var leak between environments — STOP ALL DEPLOYS
- Audit Railway env vars for wrong-env values
- Rotate any secret that was on the wrong side
- Full incident report required even if no user data exposed

## Five-minute drill

Run this quarterly to keep skills fresh. Pick a weekday afternoon in low-traffic region.

1. Tell the team "I'm doing a rollback drill in 15 min"
2. Break staging intentionally (e.g. deploy a branch that hardcodes a bad Redis URL)
3. Time how long to roll back via each option above
4. Compare to RTO target; investigate any >2× gap
5. Update this doc if something surprised you
