# Contributing to Cleanway

Cleanway is privacy-first anti-phishing software. The detection engine is open source ([docs/OPEN-SOURCE.md](docs/OPEN-SOURCE.md)). Business surfaces (Stripe, Family Hub crypto, audit log, trained ML weights) stay closed.

PRs welcome. We're a tiny team — be patient, be specific, and we'll get back to you fast.

## Quick start

```bash
git clone https://github.com/cleanway-ai/engine.git cleanway
cd cleanway
cp .env.example .env

# Backend (Python 3.11+)
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 -m uvicorn api.main:app --reload   # http://localhost:8000

# Landing (Node 20+)
cd landing && npm install
npm run dev                                  # http://localhost:3000
```

## Repo layout

```
api/              FastAPI backend (Python 3.11+, 946 tests)
landing/          Next.js 15 marketing site (10 locales, App Router)
extension/        Chrome MV3 extension (vanilla JS)
extension-firefox/  Firefox MV2 extension
extension-safari/   Safari extension (WebKit)
mobile/           React Native / Expo (iOS + Android)
ml/               CatBoost training + 27-feature extractor
data/             Tranco lists, model_meta.json, brand favicons
docs/             Architecture, benchmark methodology, open-source plan
tests/            Unit + integration + feature tests (pytest)
landing/e2e/      Playwright E2E
.github/workflows/  CI: lint + tests + security + weekly benchmark cron
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the detection pipeline (18-check fan-out, circuit breakers, server-blind URL flow, LLM Judge).

## Running tests

```bash
# Backend — 946 tests under py3.11
python3 -m pytest tests/ --timeout=60

# Lint (ruff)
python3 -m ruff check api/ tests/ ml/

# Type-check the landing
cd landing && npx tsc --noEmit

# Landing E2E (Playwright, Chromium + WebKit)
cd landing && npm run e2e
```

CI runs all four on every push (`.github/workflows/ci.yml`). A push that fails any check won't be merged.

## Code style

**Python**: PEP 8, type hints on public functions, ruff for lint.
**TypeScript**: explicit types on exported functions, no `any`, prefer `unknown` for external input + narrow. See `~/.claude/rules/typescript/coding-style.md` for the full rubric we run against.
**Commits**: [Conventional Commits](https://www.conventionalcommits.org/) format. `feat:`, `fix:`, `chore:`, `docs:`, `test:`, `ci:`, `refactor:`. We squash on merge but still want clean PR titles.

## DCO (Developer Certificate of Origin)

We don't require a CLA, but every commit must be signed-off per the [DCO](https://developercertificate.org/):

```bash
git commit -s -m "feat: add new threat source"
```

This certifies you wrote the code (or have rights to submit it) under the project's MIT license.

## Privacy rules (NEVER override)

- Never log full URLs — domain only.
- Never store IP addresses past 24h. Use `_extract_client_ip()` + Redis with TTL.
- Never link account email to scan events. Scans are anonymous.
- Never read page content (extension stays content-script-passive).
- See [SECURITY.md](SECURITY.md) for the full policy.

## i18n

10 locales: en (default), es, hi, pt, ru, ar, fr, de, it, id.

When you add a new UI string:
1. Add it to `landing/messages/en.json` first.
2. The CI i18n parity check (`scripts/check-i18n-parity.py`, runs via `.github/workflows/ci.yml`) will fail if a non-en locale is missing the namespace.
3. Translate into the 9 other locales OR explicitly mark with `// TODO: localize` so future translators see it.

## Pull request process

1. Fork + create a feature branch: `git checkout -b feat/your-feature`.
2. Write tests for new functionality (we aim for ≥80% coverage; CI doesn't gate on it but reviewer will ask).
3. Run the four CI checks locally before pushing (see above).
4. Push and open a PR. Sign off your commits.
5. CI runs automatically. Address any red checks; we won't merge with failing CI.
6. Two-reviewer rule on the first 50 contributions from any new contributor (see [docs/OPEN-SOURCE.md](docs/OPEN-SOURCE.md)).

## Reporting security issues

**Never open a public issue for a vulnerability.** See [SECURITY.md](SECURITY.md) — email `security@cleanway.ai`, 90-day coordinated disclosure.

## Code of Conduct

Be kind. We follow the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md). Report incidents to `conduct@cleanway.ai`.

## Questions

Open a Discussion on GitHub or email `hello@cleanway.ai`. We'll respond within 48 hours.
