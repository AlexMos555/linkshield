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
