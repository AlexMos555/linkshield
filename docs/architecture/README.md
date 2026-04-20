# LinkShield Architecture

> Last updated: 2026-04-16

## Monorepo layout

```
linkshield/
├── apps/                      ← Deployable applications (thin wrappers)
│   └── (in migration)
│
├── api/                       ← FastAPI backend (deploys to Railway)
├── landing/                   ← Next.js marketing site (deploys to Vercel)
├── mobile/                    ← React Native app (App Store / Play Store)
├── extension/                 ← Chrome MV3 — thin wrapper over extension-core
├── extension-firefox/         ← Firefox MV2 — thin wrapper over extension-core
├── extension-safari/          ← Safari MV3 — thin wrapper over extension-core
├── ml/                        ← Offline CatBoost training scripts
│
├── packages/                  ← Shared libraries (single source of truth)
│   ├── i18n-strings/          ← ALL UI strings × 10 languages, one source
│   └── extension-core/        ← Popup, block page, welcome, content scripts, styles
│
├── services/                  ← (planned) Edge workers, background jobs
│   └── bloom-cdn/             ← (planned) Cloudflare Worker for bloom filter
│
├── scripts/                   ← Build / deploy / migration scripts
│   ├── build-i18n.py          ← Generate extension _locales/ + landing messages/
│   └── build-extensions.sh    ← Copy extension-core into each browser dir
│
├── infra/                     ← (planned) Terraform for Railway/Vercel/Supabase/CF
│
└── docs/
    ├── architecture/          ← This folder — ADRs, diagrams, invariants
    └── runbooks/              ← Incident response, secret rotation
```

## Core invariants

These are not debatable. Changes that break them are rejected in PR review.

### I1 — Privacy invariant
No full URLs, browsing history, or personal behavioral data EVER leaves the user's device. Server only sees domain names (for checking) and aggregate counts (for percentile).

### I2 — Blocking-is-free invariant
Phishing site blocking works for every free user forever, even after hitting the 50-threat threshold. Paywall only gates DETAILS, not the block itself.

### I3 — Single source of truth
- i18n strings live in `packages/i18n-strings/` — NOT duplicated in extension/ or landing/
- Extension UI (popup, block page, welcome) lives in `packages/extension-core/` — NOT duplicated across chrome/firefox/safari
- Any commit that adds `"scam site"` in an extension/**/_locales/**/messages.json gets flagged in review

### I4 — Contract-driven clients
FastAPI is the source of truth for API shapes. Landing/mobile/extension import generated types from `packages/api-types/` (planned) — no hand-rolled type copies.

### I5 — Defense in depth
Security is layered: pre-commit → CI → build → container → runtime → architecture (boring database). See [SECURITY.md](../../SECURITY.md).

## Build flow

### i18n changes
```
1. Edit packages/i18n-strings/src/en.json        (source of truth)
2. Run: python3 scripts/build-i18n.py
3. Script generates:
   - extension/_locales/{10 langs}/messages.json
   - extension-firefox/_locales/{10 langs}/messages.json
   - extension-safari/_locales/{10 langs}/messages.json
   - landing/messages/{10 langs}.json
4. Commit both the source AND the generated files (reviewers see the diff)
```

### Extension UI changes
```
1. Edit packages/extension-core/src/popup/popup.html (or .css / .js)
2. Run: bash scripts/build-extensions.sh
3. Script copies the file into:
   - extension/src/popup/popup.html
   - extension-firefox/src/popup/popup.html
   - extension-safari/src/popup/popup.html
4. Load the extension in Chrome/Firefox/Safari dev mode to verify.
```

## Why monorepo (and not 7 repos)

- **Atomic changes** — a contract change in API + new consumer in landing in the SAME commit. No cross-repo PR dance.
- **Shared tooling** — one .github/workflows/ dir, one pre-commit config, one gitleaks config.
- **Shared state** — packages/ lets all apps import the same i18n without npm publish.
- **Easier refactor** — rename a field, grep + replace across apps+packages in one commit.

Counter-argument (size/perf) doesn't apply at our scale. Reconsider if repo hits >500MB or >50 devs.

## ADRs

Architecture Decision Records live in this folder:
- (coming soon) ADR-001: Monorepo over polyrepo
- (coming soon) ADR-002: next-intl over react-intl for landing
- (coming soon) ADR-003: chrome.i18n over bundled i18next for extensions
