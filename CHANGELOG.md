# Changelog

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
