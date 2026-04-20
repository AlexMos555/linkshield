# Security Policy

LinkShield protects people from scammers. If we get breached or backdoored, we become the attack vector. This document describes what we do to prevent that — and what to do if it happens anyway.

## Reporting Vulnerabilities

**Email:** security@linkshield.io
**PGP key:** _coming_ — request via `/contact` for now.

**Please:**
- Don't open a public GitHub issue for security findings
- Don't disclose publicly until we've shipped a fix (coordinated disclosure)
- Include reproducer + impact assessment in your report

**We will:**
- Acknowledge within **48 hours**
- Triage + fix timeline within **7 days** (CVSS-dependent)
- Credit you in changelog and `SECURITY.md` honor roll (opt-in)
- For high/critical: bug bounty up to $2k (paid via Stripe / wire / crypto)

## Scope

In scope:
- API authentication / authorization bypass
- Data leakage (full URLs or browsing history reaching server)
- SSRF, SSTI, deserialization, prototype pollution
- Extension content-script XSS / privilege escalation
- Mobile data storage / VPN tunnel issues
- Cryptographic weaknesses (E2E, k-anonymity, JWT)
- Supply-chain (dependency confusion, typosquatting)
- Container escape from our published images

Out of scope:
- Social engineering of LinkShield staff
- Physical attacks
- DoS via volumetric flooding (use Cloudflare layer)
- Attacks requiring root on user's own device
- Issues only reproducible against a deprecated version

---

## Threat Model

We model 6 attacker classes. Defenses are mapped per class.

### T1 — External attacker on the internet
**Goal:** breach API, exfiltrate user data.
**Defenses:** TLS only (HSTS), env-driven config, CORS lockdown, rate limiting, SSRF guard, JWT validation, security headers (CSP/XFO/etc.), Trivy + Bandit + pip-audit in CI, weekly dependency rescan, supabase RLS so even with API compromise the DB rejects unauthorized reads.

### T2 — Insider with read access (employee, contractor)
**Goal:** copy customer data.
**Defenses:** "Boring Database" — server stores only email + subscription, no browsing data exists to copy. Supabase RLS prevents employee from reading other users' data via API. All admin actions logged in Supabase Audit Log.

### T3 — Supply-chain attacker (compromised npm/pip dep)
**Goal:** ship malicious code via dependency update.
**Defenses:** Pinned dep versions in `requirements.txt` + `package.json`, lockfiles committed, pip-audit checks on every PR, dependabot weekly, SBOM (CycloneDX) generated for every release, no `postinstall` scripts in pinned deps verified manually for new additions.

### T4 — Stolen developer credential (GitHub, Vercel, Supabase)
**Goal:** push malicious commit, deploy backdoor.
**Defenses:** 2FA mandatory on GitHub / Vercel / Stripe / Supabase. Branch protection on `main` (required reviews, signed commits, no force push). Deploy keys scoped per service. CI runs in restricted runner with minimal `GITHUB_TOKEN` scope. Secret rotation procedure documented (below).

### T5 — Compromised user device (malware, evil browser ext)
**Goal:** read LinkShield local storage, inject scripts.
**Defenses:** Manifest V3 strict CSP, `web_accessible_resources` minimized, no `eval` or `unsafe-inline` in popup/welcome, content scripts use `chrome.runtime` message passing (no DOM injection of secrets), all stored data is non-sensitive (badges, threat counters, settings — no auth tokens longer than 1 hour).

### T6 — Compromised CDN (Cloudflare bloom-filter delivery)
**Goal:** inject false negatives, miss real scams.
**Defenses:** Bloom filter served with Subresource Integrity (SRI) hash baked into extension manifest at build time. Extension verifies SHA-256 before loading. If hash mismatch → fall back to API-only scoring + alert user.

---

## Security Features (deployed)

### Backend (FastAPI)
- **Security headers middleware:** HSTS (1 yr, includeSubDomains), CSP (strict for API, scoped for /docs), X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy strict-origin-when-cross-origin, Permissions-Policy (deny camera/mic/geo/etc.), COOP same-origin, CORP cross-origin
- **No `Server` header leak:** uvicorn started with `--no-server-header`, middleware double-checks
- **JWT validation:** HS256 with min 32-char secret enforced at startup; reject expired/malformed tokens with generic 401
- **SSRF protection:** `domain_validator.py` rejects private/loopback/link-local/multicast IPs and metadata addresses (169.254.169.254, metadata.google.internal, etc.) before any outbound HTTP
- **CORS lockdown:** allowed origins from env var, never `*`, credentials gated by exact origin match
- **Rate limiting:** per-user daily quota + burst window via Redis sliding window
- **Circuit breakers:** 14 external integrations gated by failure-count breaker; degraded mode never crashes
- **Sentry error tracking:** PII scrubbing enabled, no full URLs or auth headers logged
- **Structured logging:** JSON logs, no full URLs / no IPs / no Bearer tokens / request IDs for correlation

### Container
- **Multi-stage Dockerfile:** build tools never reach runtime image
- **Non-root user:** `app` user (UID 10001) — no root in container
- **Read-only filesystem:** `/app` and `/home/app` immutable; only `/tmp` writable (64MB tmpfs)
- **Dropped capabilities:** ALL Linux caps dropped, `no-new-privileges:true`
- **Resource limits:** 1 CPU, 512MB RAM per container — DoS containment
- **No secrets in image:** `.dockerignore` blocks `.env*`, `*.pem`, `*.key`, `secrets/`, `.aws/`, `.gcp/`
- **Healthcheck:** `/health` endpoint with 10s timeout, 3 retries
- **Pinned base image:** `python:3.11-slim-bookworm` (specific debian release)
- **OS upgrades on build:** `apt-get upgrade -y` in runtime stage to pull latest security patches
- **`tini` as PID 1:** proper signal handling + zombie reaping

### Secrets management
- **Never committed:** `.env*` blocked by `.gitignore` and `.dockerignore`
- **gitleaks pre-commit hook:** scans staged files for Supabase/Stripe/Google/JWT patterns
- **gitleaks CI workflow:** scans full history on every push + weekly schedule
- **Production secrets** stored in Railway env vars (encrypted at rest, scoped to project)
- **Rotation procedure** below

### Data architecture ("Boring Database" invariant)
| Server stores | Device stores |
|---|---|
| Email, auth provider | Full URL history |
| Subscription tier + Stripe subscription ID | Privacy Audit results (per site) |
| Device hash (anonymized) | Security Score details + factors |
| Weekly aggregate numbers (counts only) | Tracker / fingerprinting log |
| Family membership (no content) | Family alert content (E2E AES-256-GCM) |
| Skill level + locale preference | Threat counter for freemium threshold |
| Billing country (for regional pricing) | Recent threats list |

**If our server is breached:** attacker gets emails + subscription status + counts. **No URLs**, no browsing data, no audit results, no decryptable family alerts.

### Cryptography
- **Family alerts:** AES-256-GCM via libsodium; server stores ciphertext blobs only (cannot decrypt)
- **Breach check:** k-anonymity via SHA-1 hash prefix (5 chars sent, 35 chars match locally) — same protocol as HIBP
- **JWT:** HS256 with 256-bit secret rotated quarterly
- **TLS:** 1.2 minimum at edge (Cloudflare/Vercel/Railway enforce)
- **Hash storage:** SHA-256 for device fingerprints (no raw IDs server-side)

---

## Secret Rotation Procedure

### Supabase (anon + service_role + JWT secret)
1. Supabase Dashboard → Settings → API → "Roll JWT secret"
2. Update Railway env vars: `SUPABASE_JWT_SECRET`, `SUPABASE_SERVICE_KEY`, `SUPABASE_ANON_KEY`
3. Trigger Railway redeploy → all sessions invalidated, users re-auth
4. Update local `.env` for any developer machines
5. Rotate Management API token (`SUPABASE_ACCESS_TOKEN`) separately if it was exposed

### Stripe (secret key + webhook secret)
1. Stripe Dashboard → Developers → API keys → "Roll key"
2. Update Railway: `STRIPE_SECRET_KEY`
3. For webhook: Stripe Dashboard → Webhooks → endpoint → "Roll signing secret" → update `STRIPE_WEBHOOK_SECRET`
4. Old webhook secret stays valid for 24h overlap (Stripe gives both)

### Google Safe Browsing API key
1. Google Cloud Console → APIs & Services → Credentials → Regenerate
2. Update Railway: `GOOGLE_SAFE_BROWSING_KEY`

### Redis password
1. Generate new: `openssl rand -base64 32`
2. Update Upstash dashboard or Railway addon
3. Update Railway: `REDIS_URL` and `REDIS_PASSWORD`

### Quarterly schedule (calendar reminder)
- Q1 (Jan): Supabase JWT + Management token
- Q2 (Apr): Stripe + GSB
- Q3 (Jul): Supabase JWT + Management token
- Q4 (Oct): Stripe + GSB
- Redis: every 6 months (Apr, Oct)

### After exposure (immediate, NOT scheduled)
1. Within 1 hour: rotate exposed secret using procedure above
2. Within 4 hours: audit access logs for that secret (Supabase Audit Log, Stripe events, GSB usage stats)
3. Within 24 hours: post-mortem in `.planning/incidents/YYYY-MM-DD-secret-exposure.md`
4. If user data possibly accessed: notify users per GDPR (EU) / CCPA (CA) within 72 hours

---

## Backup & Recovery

### Supabase
- **Daily automatic backups:** retained 7 days on free tier, 30 days on Pro
- **Point-in-time recovery:** Pro plan only ($25/mo); enables sub-second rollback
- **Manual export:** monthly via `pg_dump` to encrypted S3 bucket (separate AWS account)
- **Test restore:** quarterly, into staging project, verify schema + sample row counts

### Redis
- **Treated as ephemeral cache** — no backups needed by design
- All canonical state lives in Supabase
- Cache loss = degraded latency for ~1 hour (cache rewarm), no data loss

### Code & secrets
- **Code:** GitHub is source of truth, mirrored to GitLab as cold backup
- **Secrets:** Railway env vars exported quarterly to encrypted offline storage (1Password vault)

### Disaster scenarios
| Scenario | RPO | RTO | Procedure |
|---|---|---|---|
| Single API container crashes | 0 | 30s | Railway auto-restart |
| Railway region down | 0 | 15min | Failover to backup region (manual) |
| Supabase project deleted | 24h | 1h | Restore from daily backup |
| GitHub account compromised | 0 | 4h | Force-rotate all secrets, restore from GitLab mirror |
| All maintainer accounts lost | 0 | 24h | Recovery codes in 1Password Family vault |

---

## Compliance posture

- **GDPR (EU):** Data minimization by design (we collect what we need to bill, no behavioral data). Right to erasure honored within 30 days. DPA available for B2B customers.
- **CCPA (California):** Same data minimization. Sale of data: never. Disclosure on request.
- **SOC 2:** Not certified yet (Type 1 planned for 2027 once revenue justifies cost). Security controls aligned with framework.
- **PCI DSS:** We never touch card data — Stripe Checkout handles all card capture. Scope = SAQ A.

---

## Honor roll

_Reporters of valid vulnerabilities listed here with their permission._
