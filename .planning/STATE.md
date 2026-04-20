# STATE: LinkShield

> Single source of truth для "где мы сейчас". Обновлено 2026-04-16.

## Current Position

- **Active phase:** E₄ — Mobile native VPN (next)
- **Overall completeness:** ~72% (E₁/E₂/E₃ all done — monorepo, email, 3 environments)
- **Shipped this sprint:** monorepo с 4 packages, security hardening, landing i18n, extension redesign на 10 языках

## Tech stack зафиксирован

**Monorepo root.** npm workspaces: packages/* + landing.
```
apps:     api (Railway), landing (Vercel), extension × 3, mobile (Expo RN)
packages: i18n-strings, extension-core, api-types, api-client
scripts:  build-i18n.py, build-extensions.sh, dump-openapi.py, generate-api-types.sh
infra:    Dockerfile (multi-stage non-root), docker-compose.prod.yml, .github/workflows/
docs:     docs/architecture/, SECURITY.md, .planning/
```

**External services wired:**
- Supabase EU (eu-central-1 Frankfurt): `bpyqgzzclsbfvxthyfsf` — schema 003 применена, 12 таблиц
- Railway API: `web-production-fe08.up.railway.app` — status 200, Redis off (ok degraded mode)
- Vercel: `landing` project linked, 80+ SSG routes build успешен
- GitHub: pre-commit gitleaks + CI security workflows активны

**External pending (user actions):**
- Stripe account + 24 regional price IDs
- Google Safe Browsing API key (console.cloud.google.com)
- Redis provider (Upstash free tier или Railway addon)
- Railway env vars обновление на новый EU Supabase (требуется `railway login`)
- Выбор домена — ребрендинг (linkshield.com/.io недоступны как наши)

## Decisions locked

**i18n — 10 языков.** en/ru native-quality. 8 draft (es/pt/fr/de/it/id/hi/ar) — нужна native review перед Chrome Web Store publish.

**Regional pricing — 4 PPP tier:** T1 $5.99 / T2 $4.99 / T3 $2.49 / T4 $1.49 Personal. Pydantic response models → OpenAPI → TypeScript.

**Pricing v2 — "feel value, then pay":** Free forever для блокировки. 50-threat soft limit на detailed explanations. Paid = Family / Granny Mode / Privacy Audit full / sync.

**4 skill levels:** Kids / Regular / Granny / Pro — schema готова, UI только Regular (Phase D ждёт).

**Security baseline.** Multi-stage Docker, non-root, CSP/HSTS/XFO, gitleaks pre-commit, 6-class threat model, rotation procedure.

## Phases status

| Phase | Title | Status | Notes |
|---|---|---|---|
| A | Strategic foundation | ✅ done | 7 планов + 1 README архитектуры |
| B | Shipping unblock | ⚠️ partial | Env-driven OK, Supabase OK, Vercel OK, pytest OK; ждём Stripe/GSB/Redis/Railway creds |
| C | Regular User UX + i18n | ⚠️ partial | Popup/block/welcome/pricing готовы на 10 языках; landing секции Features/FAQ/Comparison/Testimonials ещё EN only |
| D | Skill Levels | ⏳ schema ready | Всё в БД, UI ещё нет |
| E₁ | Mobile → монорепо | ✅ done | api-client + i18n-strings integrated, 10 langs, RTL |
| E₂ | Transactional Email | ✅ done | 7 templates × 10 langs, 61 tests, HMAC unsubscribe |
| E₃ | dev/staging/prod environments | ✅ done | 3 envs, staging Supabase `dsjkfcllugmlegwymmth`, config guards, runbooks |
| **E₄** | **Mobile native VPN** | 🔨 **СЕЙЧАС** | iOS PacketTunnel + Android VpnService — реализовать DNS interception |
| F | Growth | 📋 planned | Web Store publish + Product Hunt + referral |
| G | B2B | 📋 planned | Email proxy + phishing sim + SSO |
| H | Infra as Code | 📋 planned | Terraform + status page + chaos drills |

## Current work: Phase E₁ — Mobile → монорепо

**Goal:** mobile/ подключён к packages/ так же как landing — убрать дубли типов и i18n.

**Tasks:**
1. Add `mobile/` в root `package.json` workspaces
2. `mobile/src/services/api.ts` → заменить на `@linkshield/api-client`
3. Расширить `scripts/build-i18n.py` чтобы генерировало `mobile/i18n/{locale}.json`
4. Настроить `expo-localization` + `react-i18next` на эти 10 файлов
5. Заменить hardcoded English строки в mobile на `t("key")` calls
6. RTL support (`I18nManager.forceRTL` для ar)
7. Smoke test через Expo Go — запускается, язык переключается

## Architectural invariants (НЕ нарушать)

1. **Privacy.** Никакие браузинг-данные (URL, history, audit результаты) не покидают устройство. Только домен + агрегаты.
2. **Blocking is free forever.** Даже после 50-threat threshold блокировка работает. Paywall только на детали/семью/режимы.
3. **Plain language.** Никакого жаргона в Regular Mode UI. Pro Mode может иметь technical terms.
4. **i18n source of truth.** Все UI строки — в `packages/i18n-strings/src/*.json`. Hardcoded English = bug.
5. **Contract-driven clients.** Все клиенты (landing/mobile/extension) импортируют `@linkshield/api-types` и `@linkshield/api-client`. Hand-rolled interfaces = bug.
6. **Secrets never in git.** gitleaks pre-commit + CI. Все creds через env vars или Railway/Vercel dashboards.

## Open questions (не блокеры)

- Какой домен регать (linkshield.com занят, linkshield.io не наш)? Отложено до ребрендинга.
- Email провайдер: Resend (modern, $20/mo) vs SES (дёшево, сложнее setup)? Решим в Phase E₂.
- Stripe Adaptive Pricing vs ручные price IDs по странам? Ручные для контроля.

## Session log (недавнее)

- **2026-04-14 S10:** Phase A complete (7 планов + competitive-analysis v2 с UX axis). Установили claude-mem, antigravity skills, ultimate-guide MCP.
- **2026-04-15 S11:** Phase B — Supabase EU migration, env-driven URLs в клиентах, pytest. Phase C — popup/block/welcome redesigned на 10 языков.
- **2026-04-16 S12:** Landing i18n (next-intl), security hardening (Dockerfile/compose/headers/gitleaks/CI), monorepo refactor (packages/extension-core, packages/i18n-strings). Phase C partially, architecture principles documented.
- **2026-04-16 S13:** api-types + api-client generated из OpenAPI. Landing pricing page переведена на @linkshield/api-client. Pydantic response models для pricing. Начинаем Phase E₁ (mobile монорепо).
- **2026-04-16 S14 (now):** Phase E₁ + E₂ done. Mobile интегрирован в монорепо (api-client, i18n). Email infra: 7 React Email шаблонов × 10 языков, 600 i18n keys, 61 новых тестов, HMAC unsubscribe + RFC 8058 one-click, docs/runbooks/email.md, packages/email-templates/README.md. Активная фаза — E₃ (environments).
- **2026-04-16 S15 (now):** Phase E₃ done. Staging Supabase project `dsjkfcllugmlegwymmth` created + migrations applied (Sydney удалён). `api/config.py` + `validate_settings()` enforce environment-aware rules: dev permissive, staging strict (Stripe test only), prod ruthless (sk_live_ required, JWT ≥64 chars, Sentry required). 24 новых `test_environment_guards` теста + 3 deploy workflows (staging auto-on-main, prod manual-dispatch with approval). Runbooks: deploy.md (PR → staging → approve → prod) + rollback.md (5-min RTO). Total: 250 pytest pass, 7 shared packages, 10 languages, 3 environments ready.
