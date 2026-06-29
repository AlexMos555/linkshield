# Tonight's Playbook — Cleanway

> 20 safe-now items are already being applied by Claude in parallel. This list is **only what needs your hands**, in execution order.

---

## First 30 minutes — Unblock the pipeline

Everything below is blocking something else downstream. Do these first or the rest is wasted.

### 1. Add DNS CNAME for `dns.cleanway.ai`
- **What:** Create CNAME record: `dns.cleanway.ai` → `api.cleanway.ai`
- **Where:** Your DNS provider for cleanway.ai (Cloudflare / Namecheap / wherever the apex lives)
- **Why:** Strategy #6 iOS `.mobileconfig` files are shipped and downloadable but resolve to NXDOMAIN — DoH gateway is dead until this lands. This is the single biggest unblock for "system-wide protection without an app" pitch.
- **Time:** ~5 min (DNS propagation can take longer, but the action is fast)

### 2. Rotate the Anthropic API key
- **What:** Revoke the old key, generate a new one, update `ANTHROPIC_API_KEY` in Railway production env
- **Where:** https://console.anthropic.com/settings/keys → then Railway → Variables
- **Why:** Key was exposed in chat transcripts twice. Strategy #21 (LLM Judge) and #15 (Cultural Explainer LLM path) both need this. Security hygiene first, feature activation second.
- **Time:** ~5 min

### 3. Add 5 GitHub Actions secrets
- **What:** Add these as repo secrets (Settings → Secrets and variables → Actions → New repository secret):
  - `SUPABASE_URL`
  - `SUPABASE_SERVICE_KEY`
  - `GOOGLE_SAFE_BROWSING_KEY`
  - `VT_API_KEY`
  - `PHISHTANK_API_KEY`
- **Where:** https://github.com/<your-org>/<repo>/settings/secrets/actions
- **Why:** Watchtower cron (Supabase pair) and weekly-benchmark workflow (the 3 API keys) silently fail today. The credibility moat — weekly side-by-side vs Cloudflare 1.1.1.1 for Families — depends on these. Without them, the methodology page has stale data.
- **Time:** ~10 min (slow part is fetching each key from its provider console)

### 4. Add Railway deploy tokens + service vars
- **What:** Add to GH Actions secrets:
  - `RAILWAY_TOKEN_STAGING`
  - `RAILWAY_TOKEN_PRODUCTION`
  - Any service/health URL vars referenced in the deploy workflow
- **Where:** Railway → Account Settings → Tokens (create one per env) → paste into GH secrets
- **Why:** Without these, every push to main requires a manual Railway deploy. You want CI/CD green before you hit "submit to Chrome Web Store" tomorrow, not after.
- **Time:** ~10 min

---

## Next hour — Verify what shipped

You can't sell what you haven't seen. Do not skip these — distribution-push fails embarrassingly if a visual regression sneaks in.

### 5. Manually walk the site in a browser
- **What:** Open https://cleanway.ai in Chrome incognito. Click through: home → /pricing → /check/google.com → /audit/<any-domain> → /dns → /methodology. Toggle to `/es`, `/ru`, `/de`. Note any layout breaks, untranslated strings showing in non-English locales (especially the 7 you haven't translated yet — ar/de/fr/hi/id/it/pt — sections "How it works", "Pricing teaser", "Privacy" will be in English).
- **Where:** Browser, on a real device if possible
- **Why:** Find P0 visual bugs before users do. The 308-string i18n gap is real but expected — you're verifying nothing else broke in the 20 safe-now patches.
- **Time:** ~20 min

### 6. Run the mobile horizontal-overflow E2E locally and un-skip if green
- **What:** From `/Users/aleksandrmoskotin/Desktop/LinkShield/LinkShield/landing`, run the Playwright mobile test that's currently `test.skip(...)`. If green, remove the skip and commit.
- **Where:** Terminal in landing dir → `pnpm test:e2e --grep "horizontal overflow"` (or the equivalent invocation per the existing E2E config)
- **Why:** This test was skipped pending verification. Mobile horizontal-overflow is the #1 reason a phone-based reviewer rejects a landing page. Un-skipping turns it into a regression net for the next change.
- **Time:** ~15 min

### 7. Verify Twitter handle `@cleanwayai` is registered to you
- **What:** Try logging in at https://twitter.com/cleanwayai. If it's not yours, either claim it (if available) or remove the references from `landing/app/[locale]/layout.tsx` (twitter.site) and the JSON-LD `sameAs` array in `landing/app/[locale]/page.tsx`. Also affects 8 other metadata exports across pricing/business/terms/privacy-policy/audit/check pages.
- **Where:** Twitter/X login, then either claim it or grep for `cleanwayai` and remove
- **Why:** Today Twitter cards won't enrich (handle resolves to nothing or to someone else's account) and the schema.org `sameAs` claim is misleading. Cheap fix, but needs your decision.
- **Time:** ~10 min

---

## Tomorrow / this week — Distribution push

You're now ready to push. Order matters: store submission has the longest review SLA, so it goes first.

### 8. Submit Chrome extension to Chrome Web Store
- **What:** Buy the $5 dev account if you haven't, upload the artifact from the store-artifacts ZIP builder (Strategy #18), fill in listing copy, submit for review.
- **Where:** https://chrome.google.com/webstore/devconsole/ → New item → upload `chrome.zip` from `dist/store-artifacts/`
- **Why:** Chrome Web Store review takes 1–7 days. Start the clock now so it's live when you announce.
- **Time:** ~45 min (most of it is filling in listing copy, screenshots, justifying permissions)

### 9. Translate the 3 namespaces × 7 locales (~350 strings)
- **What:** Spawn one Claude sub-agent per locale to translate `HowItWorks`, `PricingTeaser`, `Privacy` from `en.json` into `ar.json`, `de.json`, `fr.json`, `hi.json`, `id.json`, `it.json`, `pt.json`. Use `es.json` + `ru.json` as quality references. **Do not batch all 7 into one call.** After, run a parity check that each `locale[ns] != en[ns]`.
- **Where:** Files at `/Users/aleksandrmoskotin/Desktop/LinkShield/LinkShield/landing/messages/<locale>.json`
- **Why:** Today a German visitor sees the entire "How it works", "Pricing teaser", and "Privacy" sections in English on an otherwise German page. Same class of bug as the Methodology fallback you fixed in `3dc22e8`. Until this lands, the 7 weakest locales look unfinished.
- **Time:** ~1.5 hours of your time supervising the agents (their wall time is parallel)

### 10. Post the methodology + side-by-side comparison
- **What:** Share the `/methodology` page and a specific `/check/<juicy-domain>` link showing Cleanway catching what Cloudflare 1.1.1.1 for Families missed. Show HN, Twitter/X, r/privacy, r/cybersecurity.
- **Where:** Reddit, HN, X, LinkedIn — whichever channels you're comfortable with
- **Why:** Nobody else publishes head-to-head per-domain comparisons. This is the credibility moat you built specifically for press / Show HN / acquihire DD. Don't sit on it.
- **Time:** ~1 hour to draft posts, plus monitoring

### 11. Spawn the CSP Report-Only sub-task
- **What:** Open a separate Claude session to wire a `Content-Security-Policy-Report-Only` header alongside the enforcing one, plus a Sentry CSP reporting endpoint (or new FastAPI `/api/csp-report` router) and Next.js nonce middleware.
- **Where:** New Claude session, rooted at the repo
- **Why:** Prerequisite to dropping `'unsafe-inline'` from CSP. Needs Sentry DSN config + careful middleware composition with next-intl — too risky for an inline edit during a distribution push. Defer, but don't forget.
- **Time:** ~2 hours of sub-agent wall time, ~20 min of your review

### 12. (Skip for now, file mentally) Tighten CORP per-route on backend
- **What:** No action tonight. After Chrome Web Store goes live and traffic is steady, classify backend routes into `cross-origin` (extension-facing: `/v1/check`, `/v1/scam`, `/v1/explainer`, `/transparency`, `/dns-query`) vs `same-origin` (admin, family, webhook, account-purge) and switch CORP per path in middleware.
- **Why:** Defense-in-depth, not a vulnerability. Current global `cross-origin` is correct, just not maximally tight. Wrong move pre-launch — misclassification silently breaks the extensions.
- **Time:** Defer

---

## Why this order

The 30-minute block is pure unblock: every item gates something downstream (DNS gates the iOS pitch, secrets gate the cron jobs that feed the methodology page, Railway tokens gate every future deploy, the rotated Anthropic key gates two shipped features). The next-hour block is a regression-net pass — you cannot push to Chrome Web Store and announce a side-by-side comparison while a layout regression or a still-English German hero is live, so eyes-on verification happens before any external-facing action. Distribution lands last because the Chrome Web Store review clock starts the moment you submit, so the highest-latency external dependency goes earliest in that phase, with translation and posts filling the wait. CSP-Report-Only and per-route CORP are deferred on purpose: both are tech-debt cleanups whose worst-case failure mode is silently breaking Stripe Checkout or the extensions during a launch window, so they wait until after you have steady-state traffic and a baseline to compare against.
