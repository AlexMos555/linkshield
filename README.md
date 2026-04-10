# LinkShield

Privacy-first phishing protection platform. Your browsing data lives only on your device.

## What is LinkShield?

LinkShield automatically checks every link you encounter against 9 threat intelligence sources and a machine learning model. Dangerous sites are blocked before they can harm you.

**Key difference:** Your browsing history never leaves your device. Our servers store only your email and subscription status. Even if breached, attackers learn nothing about your online activity.

## Features

- **42+ detection signals** across 6 categories
- **9 blocklist sources** (Google Safe Browsing, PhishTank, URLhaus, PhishStats, ThreatFox, Spamhaus, SURBL, AlienVault OTX, IPQualityScore)
- **CatBoost ML model** (AUC 0.9988, 91% detection rate)
- **Privacy Audit** — see what trackers, cookies, and data collection any site uses (A-F grade, on-device)
- **Breach Check** — k-anonymity email leak detection (your email never leaves your device)
- **Security Score** — on-device calculation with factor breakdown
- **Weekly Report** — generated on-device, percentile ranking
- **Phishing Simulation** — B2B training campaigns

## Platforms

| Platform | Status |
|----------|--------|
| Chrome Extension (MV3) | Ready |
| Firefox Extension (MV2) | Ready |
| Safari Extension | Ready |
| iOS App (React Native) | Ready |
| Android App (React Native) | Ready |
| Web Landing (Next.js) | Ready |
| REST API (FastAPI) | Ready |

## Quick Start

```bash
# Start everything
./start.sh

# Or manually:
make dev          # API on localhost:8000
cd landing && npm run dev  # Landing on localhost:3000

# Install Chrome extension:
# chrome://extensions/ → Developer mode → Load unpacked → ./extension
```

## Tech Stack

- **Backend:** FastAPI (Python), Redis, Supabase (PostgreSQL)
- **ML:** CatBoost, 27 features, trained on 18K+ domains
- **Extension:** Manifest V3, vanilla JS, MurmurHash3 bloom filter
- **Mobile:** React Native (Expo), SQLite, native VPN (Swift/Kotlin)
- **Landing:** Next.js 15
- **Payments:** Stripe
- **Auth:** Supabase Auth

## Architecture

```
Server stores (boring):          Device stores (private):
  - email, subscription           - full URL history
  - device list                   - Privacy Audit results
  - weekly aggregate numbers      - Security Score breakdown
  - family membership             - Weekly Report data
                                  - Family alert content (E2E)
```

## API Endpoints

See full docs at `/docs` (Swagger UI) when running locally.

- `POST /api/v1/check` — Check domains (authenticated)
- `GET /api/v1/public/check/{domain}` — Public check (no auth)
- `POST /api/v1/payments/*` — Stripe checkout/webhook/portal
- `POST /api/v1/user/*` — Aggregates, score, percentile, devices
- `GET /api/v1/breach/check/{hash_prefix}` — k-anonymity breach check
- `POST /api/v1/feedback/*` — Report false positives, whitelist
- `POST /api/v1/referral/*` — Referral codes
- `POST /api/v1/org/*` — B2B organization management

## Tests

```bash
make test           # 75 unit tests
python3 -m tests.test_api_integration  # 10 integration tests
python3 -m tests.test_features         # 9 feature tests
```

## License

MIT

## Privacy Policy

https://linkshield.io/privacy-policy
