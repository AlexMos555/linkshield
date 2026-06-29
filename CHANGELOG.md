# Changelog

## [Unreleased]

### Security
- **Stripe open redirect** — `CheckoutRequest.success_url` / `cancel_url` now allowlist-validated against `cleanway.ai` apex/www. Attackers can no longer pipe Stripe checkout through attacker-controlled landing URLs.
- **Extension host permissions** — Dropped `http://localhost:8000/*` from production manifests (Chrome/Firefox/Safari). Published extensions no longer leak auth to any local service on port 8000.
- **Subscriptions RLS** — Documented intentional default-deny on `subscriptions` writes; all writes go through service_role on the backend.

### Changed
- **Rebrand** — Full migration from LinkShield to Cleanway (cleanway.ai). Infrastructure, extensions, landing, mobile, i18n, and CORS all updated.
- **API host** — Backend URL migrated from Railway to `api.cleanway.ai` across all platform targets (20+ files).
- **Sentry** — Added env-gated Sentry DSN integration for landing (Next.js) and mobile (Expo).

### Fixed
- **Mobile Safari** — Horizontal scroll regression on landing page (`fd99a9e`).
- **Supabase RLS** — Enabled RLS on `families` / `orgs` / `org_members` tables; pinned `search_path` on `get_pricing_tier` and `report_phone` functions.

### Removed
- **Dead i18n** — `welcome_step_label` (`extension.welcome.step_label`) from `packages/i18n-strings/src/` and 50 generated locale files.
- **Unused import** — `get_current_user` from `api/routers/email.py`.

### Tests
- 382 backend tests passing (was 373). Added 9 parameterized tests for `CheckoutRequest` URL validation.

## [0.3.0] - 2026-06-17

### Added — top-20 active-protection strategies (all shipped)
- **#1 Credential-form action-host detector** + active-protection modal
- **#2 Favicon brand-clone gallery** (24 brands seeded, 23 hashes populated)
- **#7 Kids / Regular / Granny / Pro block-page personas**
- **#8 Honeypot Shield** — "Send fake password" decoy (16-byte crypto-random, per-input unique, Shadow DOM toast)
- **#9 Conformal confidence_pct** (50–99) on every DomainResult + popup/block-page chips
- **#10 GH Actions cron** — Tranco daily refresh + favicon weekly refresh
- **#11 Modern-phish guard** — BitB detection, tab-napping rel-patch, overlay credential trap
- **#12 Public transparency endpoint** + landing page (Q2 2026 fixture)
- **#13 Pwned Password** content script — SHA-1 on blur, k-anonymity 5-char prefix, inline banner
- **#14 Tranco top-1M popularity signal** — negative weights for popular domains, atomic Redis refresh
- **#15 Cultural explainer** — 5 categories × 10 locales = 50 hand-curated payloads, Claude Haiku 4.5 with deterministic template fallback
- **#16 Public scorecard** upgraded with FP rate (0.08% Q2 interim)
- **#17 Typosquat Watchtower** — Levenshtein/PSL/crt.sh-driven with cron job
- **#18 Store artifacts ZIP builder** (5 stores) + `docs/STORES.md` runbook
- **#20 URL-param PII leak detection** (JWT/email/long-random, cap 25)
- **#21 LLM Judge** — Claude arbitrates caution-band verdicts; domain-free feature vector via SAFE_KEYS whitelist, sha256 cache, ±20 score-shift cap, 4s timeout, 3-gate firing, crash-safe silent no-op
- **DoH gateway** `/dns-query` (RFC 8484) + iOS `.mobileconfig` generator + landing `/dns` page (iOS/Android/macOS/Win11 paths)
- **Public `/check` full fan-out** — was rule-only, now runs the 18-check analyzer with 24h cache + 5/min IP rate limit + fail-soft fallback
- **Methodology page** (SSR from `docs/benchmarks/latest.json`) + side-by-side vs Cloudflare 1.1.1.1 for Families at `/check/<domain>`
- **Weekly GH Actions benchmark cron** — eval_fresh_urls.py vs URLhaus/PhishTank + Tranco safe sample

### Hardened
- **Watchtower** — subdomain dead code removed, punycode homograph, LIMIT truncation, quota fail-open, RLS shared-row violation, silent PATCH, log scrubbing (7 fixes from adversarial review)
- **Pwned Password** — Referer leak, plaintext-in-WeakMap, prefix-in-logs (3 HIGH fixes)
- **Honeypot Shield** — dropped restore (framework-state leak), per-input unique honeypot, removed fixed watermark, removed fetch (fingerprint), shadow-DOM piercing protection
- **Strategy #20 URL-PII detector** — capped at 25 params to prevent DoS

### Tests
- 619 test functions across 46 files (was 488 in May). Backend coverage held above 90% throughout the strategy push.

## [0.2.0] - 2026-05-13

### Added
- **Family Hub** — end-to-end server-blind family alerts (AES-256-GCM via libsodium), QR-code invite flow + `/family/join` landing, paste-link join
- **Audit log** — migration 014, `audit_log` table wired across account / subscription / family-invite endpoints
- **Stripe pipeline hardening** — checkout dead-on-arrival fix (4 bugs), cancel-bug fix (migration 013 UNIQUE constraint), welcome-email URL typo, past_due dunning grace, business-plan tier mapping
- **Stripe webhook coverage** — trial_will_end, invoice.paid, customer.deleted, idempotency keys
- **GDPR Art. 15/17** — data export + delete + migration 012 + purge cron
- **Voice endpoint** — honest verdict (no false-positive padding)
- **Outlook "Report phishing" add-in** — 3-bug fix, body+org DoS hardening, background LRU + abortable fetch, CheckRequest per-item cap
- **Disposable-email defense-in-depth**
- **Tracking-cleaner perf** improvements
- **Badge layout bug** fix

### Tests
- 488 → 636 test functions. Coverage 84% → 96%.

## [0.1.0] - 2026-04-08

### Added
- **Scoring Engine 3.0** — 42+ detection signals across 6 categories
- **9 blocklist sources** — Google Safe Browsing, PhishTank, URLhaus, PhishStats, ThreatFox, Spamhaus DBL, SURBL, AlienVault OTX, IPQualityScore
- **CatBoost ML model** — AUC 0.9988, 91.1% detection rate, 0% false positives
- **100K domain allowlist** — Tranco top domains with hosting platform bypass protection
- **125 brand targets** — typosquatting detection for tech, banking, shipping, crypto, government
- **Chrome Extension** — Manifest V3, link scanning, badges, block page, Privacy Audit, Security Score, Weekly Report, Breach Check, context menu, keyboard shortcuts
- **Firefox Extension** — Manifest V2 port
- **Safari Extension** — Manifest V3 port
- **iOS App** — 14 screens, QR scanner, breach check, auth, upgrade, VPN tunnel (Swift)
- **Android App** — 14 screens, QR scanner, breach check, auth, upgrade, VPN tunnel (Kotlin)
- **Landing Page** — Hero, features, pricing, FAQ, testimonials, competitor comparison, privacy policy, terms, SEO pages, referral pages, business page
- **API** — 26 endpoints: domain checking, payments (Stripe), user management, breach monitoring, feedback/whitelist, referral system, B2B org management, phishing simulation
- **Security** — JWT validation, SSRF protection, CORS lockdown, rate limiting, circuit breakers, structured logging, Sentry integration
- **ML pipeline** — Feature extraction (39 features), training script, bloom filter compiler
- **94 tests** — 75 unit + 10 integration + 9 feature tests
