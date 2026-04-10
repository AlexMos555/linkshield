# LinkShield — Installation Guide

## Quick Start (30 seconds)

### 1. Start all services
```bash
cd /Users/aleksandrmoskotin/Desktop/LinkShield/LinkShield
./start.sh
```

This starts:
- **API** at http://localhost:8000 (+ docs at /docs)
- **Landing** at http://localhost:3000

### 2. Install Chrome Extension

1. Open **chrome://extensions/** in Chrome
2. Toggle **Developer mode** ON (top right corner)
3. Click **Load unpacked**
4. Select folder: `/Users/aleksandrmoskotin/Desktop/LinkShield/LinkShield/extension`
5. Done! The shield icon appears in your toolbar

### 3. Use it

- **Browse any page** — green/yellow/red badges appear on links
- **Click the shield icon** — see page safety status + stats
- **Right-click any link** → "Check link with LinkShield"
- **Right-click any page** → "Privacy Audit this page"
- **Visit a phishing site** → full-page block warning

### Test domains
- `google.com` → ✅ Safe (score 0, "Ranked #1 globally")
- `paypa1-verify.tk` → ❌ Dangerous (score 100, 7+ signals)
- `pay-pal.com` → ⚠️ Typosquatting detected
- `evil.netlify.app` → ⚠️ Hosting platform, needs full analysis

### Landing pages
- http://localhost:3000 — Main page (hero, features, pricing)
- http://localhost:3000/check — Search "is X safe?"
- http://localhost:3000/check/paypa1-verify.tk — SEO result page
- http://localhost:3000/privacy-policy — Privacy policy
- http://localhost:3000/terms — Terms of service

### API docs
- http://localhost:8000/docs — Swagger UI (try all 25 endpoints)
- http://localhost:8000/health — Health check + circuit breaker status

### Stop everything
```bash
pkill -f "uvicorn|next"
```
