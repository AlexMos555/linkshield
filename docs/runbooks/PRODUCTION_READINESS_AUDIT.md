# Cleanway — Production Readiness Audit

**Дата:** 2026-04-20 · **Коммит:** `fe72d42` (main) · **Аудитор:** ccd-agent

Цель: перестать тушить симптомы Railway 502 и увидеть полную картину. Ниже — что сломано, что работает, и конкретный список действий.

---

## 1. Build / deploy chain (Railway backend)

### Current state
- **`railway.json`** → `{"build": {"builder": "NIXPACKS"}}` — только builder, нет `deploy.startCommand`.
- **`Procfile`** → `web: python -m uvicorn api.main:app --host 0.0.0.0 --port $PORT` (последний фикс `a342c24`).
- **`Dockerfile`** → удалён (коммит `208efd2`), но в репо остались: `docker-compose.yml`, `docker-compose.prod.yml`, а в `security.yml` job'ы `trivy-image` / `sbom` всё ещё вызывают `docker build -t cleanway-api:sbom .` — **это сломано** (job `sbom` упадёт с "no Dockerfile").
- **`requirements.txt`** (15 строк): FastAPI 0.115, uvicorn[standard] 0.32, httpx, redis[hiredis], pydantic-settings, PyJWT, python-multipart, dnspython, stripe, sentry-sdk[fastapi], bcrypt. **catboost/numpy убраны** намеренно (OOM на 512 MB starter).
- **`.github/workflows/ci.yml`** job `docker:` тоже делает `docker build -t cleanway-api .` → **упадёт** (нет Dockerfile). Это сломанный pipeline в CI.

### Conflicts / verdict
- **Конфликта Procfile vs Dockerfile больше нет** (Dockerfile удалён). Railway использует Nixpacks + Procfile — корректно.
- **Но два workflow (`ci.yml` docker job + `security.yml` sbom/trivy) ссылаются на удалённый Dockerfile** → Actions красные.

### Required env for startup (из `api/config.py` + `validate_settings`)
Minimum для `ENVIRONMENT=production`:
1. `ENVIRONMENT=production`
2. `DEBUG=false`
3. `SUPABASE_URL` — required
4. `SUPABASE_SERVICE_KEY` — required
5. `SUPABASE_JWT_SECRET` ≥ 64 chars — required
6. `SENTRY_DSN` — required
7. `STRIPE_SECRET_KEY` — если задан, должен начинаться с `sk_live_`
8. `REDIS_URL` — дефолт `redis://localhost:6379` (упадёт в health, но стартанёт)

С `strict_config=false` (текущий дефолт, `api/config.py:31`) любые нарушения **только логируются** — под не упадёт, но `/health` вернёт degraded, и безопасность тоньше.

### Fix
- [ ] Удалить job `docker:` из `.github/workflows/ci.yml` (строки ~66–90) — он гарантированно красный.
- [ ] В `.github/workflows/security.yml` убрать job `sbom` или вернуть Dockerfile. Сейчас `sbom` билдит несуществующий образ.
- [ ] Считать `Procfile` → `python -m uvicorn api.main:app --host 0.0.0.0 --port $PORT` каноническим. Поставить в Railway **Settings → Start Command = (empty)**, чтобы Procfile применялся.

---

## 2. Backend config / env vars (`api/config.py`)

### Все 40+ settings (дефолты)
- `app_name`, `debug=False`, `environment="development"`, `strict_config=False`
- Supabase: `supabase_url/anon_key/service_key/jwt_secret` = `""`
- CORS: `allowed_origins` = `cleanway.ai,www.cleanway.ai,staging.cleanway.ai,mail.google.com,outlook.office.com,outlook.live.com,mail.yahoo.com`
- `redis_url="redis://localhost:6379"`
- Threat intel keys: `google_safe_browsing_key`, `phishtank_api_key`, `ipqualityscore_key`, `hibp_api_key` = `""`
- `sentry_dsn=""`
- Stripe: `stripe_secret_key/webhook_secret/publishable_key=""`
- Rate limits: free 10/день, paid 10000, burst 10/10s, public 60/hour, sensitive 10/hour, unsubscribe 20/hour
- Cache TTLs: safe 3600s, suspicious 900s, dangerous 300s
- Bloom: `./data/bloom_filter.bin`, `bloom_filter_cdn_url=""`
- `extra="ignore"` в `model_config` (line 105) → backend игнорирует `NEXT_PUBLIC_*` / `EXPO_PUBLIC_*`.

### Что ДОЛЖНО быть в Railway для prod
`ENVIRONMENT`, `DEBUG=false`, `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_KEY`, `SUPABASE_JWT_SECRET` (≥64), `SENTRY_DSN`, `REDIS_URL` (настоящий Upstash/Railway Redis), `GOOGLE_SAFE_BROWSING_KEY`, `STRIPE_SECRET_KEY=sk_live_…`, `STRIPE_WEBHOOK_SECRET`, `ALLOWED_ORIGINS` (прод домены + extension IDs).

### Recommended but optional
`PHISHTANK_API_KEY`, `IPQUALITYSCORE_KEY`, `HIBP_API_KEY`, `BLOOM_FILTER_CDN_URL`, `AWS_REGION`/`EMAIL_PROVIDER=ses` (если включена рассылка).

### Hardcoded dev URLs
`web-production-fe08.up.railway.app` захардкожен как **fallback** в:
- `landing/app/[locale]/check/[domain]/page.tsx:25`
- `landing/app/[locale]/pricing/page.tsx:10`
- `mobile/src/services/api.ts` (fallback для `EXPO_PUBLIC_API_URL`)
- `packages/extension-core/src/utils/api.js:9`
- `extension/manifest.json` host_permissions

Это **fine для MVP** (fallback), но когда получите `api.cleanway.ai` custom domain — поменять на него.

### strict_config=false
`api/config.py:31` — **правильный выбор на время роллаута**. Как только в Railway все env выставлены и `/health=ok`, флипнуть в `true` (env `STRICT_CONFIG=true`), чтобы неправильный деплой ронял под сразу, а не тихо.

### Fix
- [ ] В Railway дашборде (`https://railway.com/project/3568c94d-3805-4b66-9972-b63a5d6816e7/service/[API-SERVICE]/variables`) убедиться что стоят 13 обязательных переменных (см. список выше).
- [ ] После успешного `/health=ok` — выставить `STRICT_CONFIG=true`.

---

## 3. Database / Supabase (`supabase/migrations/`)

| # | Файл | Что создаёт | Идемпотентно? |
|---|------|-------------|---------------|
| 001 | initial_schema.sql | `users, subscriptions, devices, weekly_aggregates, families, family_members, family_alerts, user_settings, orgs, org_members, rate_limits` + RLS + indexes | **НЕТ** — `CREATE TABLE` без `IF NOT EXISTS` |
| 002 | feedback_reports | `public.feedback_reports` (user feedback для ML) | **ДА** — `CREATE TABLE IF NOT EXISTS` |
| 003 | intl_pricing_skill_levels | `ALTER TABLE` добавляет `preferred_locale`, `skill_level`, `billing_country`, `pricing_tier`, `currency`, `voice_alerts_enabled`, `font_scale`, `threats_blocked_lifetime` + функция `get_pricing_tier(cc)` | **ДА** — все `ADD COLUMN IF NOT EXISTS` |
| 004 | user_settings | `ALTER TABLE users ADD` воice_alerts_enabled, font_scale, parental_pin_hash | **ДА** |
| 005 | scam_protection | `phone_reports, verified_numbers, sms_reports, scam_analyses` + функция `report_phone` + RLS | **ДА** — `CREATE TABLE IF NOT EXISTS` |

### Статус (по словам оператора): 001–005 применены ✅
### Foreign keys
Все FK ссылаются на `users(id)`. **001 создаёт `public.users` сам**, но 002 ссылается на `auth.users(id)` (строка 4), а 003/004 на `public.users`. Это расхождение: `public.users` живёт параллельно с Supabase встроенной `auth.users`. Приложение использует обе — backend выдаёт JWT с `auth.users.id` → затем читает `public.users.id`. **Риск:** если `public.users.id` ≠ `auth.users.id` → все FK ломаются.

### Fix
- [ ] Проверить в Supabase SQL Editor: `SELECT count(*) FROM public.users u WHERE NOT EXISTS (SELECT 1 FROM auth.users WHERE id=u.id);` — должно быть 0. Если нет — написать триггер `auth.users INSERT → public.users INSERT`.
- [ ] Миграцию 001 переписать с `IF NOT EXISTS` (техдолг, не блокер).

---

## 4. Mobile app (Expo)

### Expected env vars
`EXPO_PUBLIC_API_URL` (с fallback на Railway URL), `EXPO_PUBLIC_SUPABASE_URL`, `EXPO_PUBLIC_SUPABASE_ANON_KEY`. Проверяется в `mobile/src/services/supabase.ts` через `cleanValue()` — отсекает placeholder'ы `YOUR_PROJECT`, `YOUR_ANON_KEY`, `example.supabase.co`.

### API URL
`mobile/src/services/api.ts:21` — приоритет: `process.env.EXPO_PUBLIC_API_URL` → `Constants.expoConfig.extra.apiUrl` → fallback `https://web-production-fe08.up.railway.app`. **Настраиваемо — хорошо.**

### Чего не хватает для prod-билда
- **`eas.json` отсутствует** (`ls mobile/eas.json` → пусто). Без него `eas build` не работает.
- В `app.json`: bundle ID `ai.cleanway.app` (ios+android), есть intent filter для `text/plain` (share) и scheme `cleanway://`. Норм.
- **Expo secrets не настроены** — EAS не знает `EXPO_PUBLIC_*` при билде в облаке.
- Отсутствуют: adaptive-icon на отдельных плотностях, splash в нескольких размерах, `notification.icon`, metadata для App Store / Play Store.

### Fix
- [ ] Создать `mobile/eas.json` с профилями `development`, `preview`, `production`, каждый с `env: { EXPO_PUBLIC_API_URL: …, EXPO_PUBLIC_SUPABASE_URL: …, EXPO_PUBLIC_SUPABASE_ANON_KEY: … }`.
- [ ] `eas secret:create --scope project --name EXPO_PUBLIC_SUPABASE_ANON_KEY --value "…" --type string` — для anon key (остальные можно в `eas.json`).
- [ ] App Store Connect: создать app `ai.cleanway.app`, заполнить screenshots (6.5" iPhone + 12.9" iPad), privacy labels (Data Not Collected ✓ для browsing).
- [ ] Google Play Console: создать app, privacy policy URL = `cleanway.ai/privacy`.

---

## 5. Browser extensions

### API URL
`packages/extension-core/src/utils/api.js:9` — `let API_BASE = "https://web-production-fe08.up.railway.app"` + override через `chrome.storage.local.api_url` (dev). **Хорошо.**

### host_permissions (`extension/manifest.json`)
`railway.app/*`, `*.cleanway.ai/*`, `localhost:8000/*`, `mail.google.com/*`, `outlook.office.com/*`, `outlook.live.com/*`, `mail.yahoo.com/*`. Покрытие webmail соответствует `packages/extension-core/src/content/webmail.js`. OK.

### Статус 3 сборок
- `extension/` — MV3 (Chrome/Edge) ✅
- `extension-firefox/` — MV2 (historical), отличается (`service_worker` → `scripts[]`, нет `host_permissions` как отдельного ключа — в MV2 они в `permissions`). **Важно:** Firefox AMO с 2024 принимает MV3 — стоит мигрировать.
- `extension-safari/` — есть, но надо оборачивать в Xcode project для App Store.

### Publish readiness
- **Icons:** есть 16/32/48/128 в `public/icons/` — ✓
- **Screenshots:** не видно в репо — нужны 1280×800 (Chrome Web Store требует 5 шт)
- **Store listings:** промо-тексты, категория, support email — не в репо
- **_locales:** есть `default_locale=en`, надо проверить 10 языков
- **Privacy disclosures:** Chrome Web Store "Single Purpose + Permission Justification" — не подготовлены

### Fix
- [ ] Создать Chrome Web Store listing (`https://chrome.google.com/webstore/devconsole`): single purpose = "block phishing links in browser + webmail", 5 screenshots, promo tile 440×280.
- [ ] Firefox: мигрировать `extension-firefox/manifest.json` на MV3, либо оставить MV2 до deadline (Firefox поддерживает MV2 дольше).
- [ ] Safari: создать Xcode project через `xcrun safari-web-extension-converter extension-safari/`, подписать Apple Developer cert.

---

## 6. Landing (Next.js / Vercel)

### Env vars
Только два: `NEXT_PUBLIC_API_URL` (fallback на Railway), `API_URL` (server-side alias). В Vercel обычно ставят: `NEXT_PUBLIC_API_URL`, `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`, `NEXT_PUBLIC_STRIPE_PUB_KEY`.

### Next.js 15.1.11 (CVE fixed, `8f38a55`)
`landing/package.json` → `next: 15.1.11`. Соответствует CVE-fixed версии (раньше был 15.1.2).

### i18n
`next-intl@4.9.1` с `i18n/request.ts` + `i18n/routing.ts`. Сообщения в `messages/{en,es,hi,pt,ru,ar,fr,de,it,id}.json` (10 языков — стратегия v2).

### Security concerns
- Fallback API URL `web-production-fe08.up.railway.app` — не секрет, нормально.
- **Vercel incident email сегодня** — отдельный runbook уже есть (`docs/runbooks/vercel-incident-response.md`). **Ротировать**: OAuth tokens, Vercel tokens, любые API keys, которые могли быть в env на Vercel.
- В `next.config.ts` нет `headers()` → CSP/HSTS **не настроены на уровне Next**. Это делает backend middleware, но landing тоже должен.

### SEO
- `sitemap.xml` / `robots.txt` — **не найдены** (надо проверить `landing/app/`).
- `metadata` экспортируется в `[locale]/layout.tsx` (не открывал, надо валидировать).

### Fix
- [ ] Vercel dashboard (https://vercel.com/[team]/cleanway/settings/environment-variables): ротировать все токены (incident response).
- [ ] Добавить `landing/app/sitemap.ts` + `landing/app/robots.ts`.
- [ ] В `next.config.ts` добавить `async headers()` с HSTS/CSP/X-Frame-Options.

---

## 7. Shared packages

- **`packages/api-client/src/index.ts`** (230+ строк) — типизированный fetch wrapper над `@cleanway/api-types`. 4 namespace: check, pricing, health + payments. **Актуален**, отражает backend (`/api/v1/check`, `/api/v1/pricing/*`, `/health`).
- **`packages/api-types/`** — есть `openapi.d.ts` сгенерированный из OpenAPI spec + `schema/` (vendor dump). Последний апдейт 2026-04-20. Выглядит синхронизированным.
- **`packages/i18n-strings/src/`** — 10 json файлов (ar, de, en, es, fr, hi, id, it, pt, ru) = 10 языков стратегии.
- **`packages/extension-core/src/`** — источник правды для 3 extension сборок (extension/, extension-firefox/, extension-safari/ — это синкнутые копии).
- **`packages/email-templates/`** — новый (Apr 20), ещё не проверял use sites.

**Риск:** `api-client` и `api-types` не опубликованы в npm, подключены как workspaces (`"@cleanway/api-client": "*"`). Если кто-то не запустил `npm install` в корне — imports ломаются.

---

## 8. External services inventory

| Сервис | Зачем | Статус | Cost | Блокер |
|---|---|---|---|---|
| **Stripe** | Платежи (subscriptions) | keys в env, но pk/sk не проверены в prod | 2.9% + $0.30 | Нужен live key + webhook secret в Railway, подключение домена в Stripe dashboard |
| **Google Safe Browsing** | Threat DB для проверки доменов | Опциональный, есть код интеграции | Free (до 10K QPD) | Создать key в GCP console, положить в `GOOGLE_SAFE_BROWSING_KEY` |
| **Sentry** | Error tracking | Инициализируется в `main.py:28` если есть `SENTRY_DSN`; `validate_settings` требует в prod | Free (5K events/mo) → $26/mo | Создать project на sentry.io, положить DSN в Railway |
| **Redis** | Rate limit + cache | `REDIS_URL` в config, подключение через `api.services.cache` | Upstash free 10K cmd/day → $10/mo | **Не подключено в Railway** — без Redis rate limiting сломан |
| **SES / Resend** | Транзакционные email (welcome, breach alerts) | Env поля в `.env-examples/.env.production`, но не проверены кодом | SES $0.10/1K, Resend $20/mo | Verify domain `mail.cleanway.ai`, настроить SPF/DKIM/DMARC |
| **Whisper / OpenAI** | Voice transcription (Phase H4) | Код в `api/routers/scam.py` (не открывал) | $0.006/min | Phase H4, не блокер для launch |
| **Anthropic** | LLM scam detection (Phase H4) | Та же история | $0.003/1K input, $0.015/1K output | Phase H4, не блокер |
| **Google Play / Apple Dev** | Mobile distribution | Нет eas.json → ничего не подписывается | Apple $99/год, Google $25 one-time | Зарегистрировать, создать app listings |
| **Chrome Web Store** | Extension distribution | Нет listing | $5 one-time | Developer account, listing |
| **Firefox AMO** | Firefox extension | Нет listing | Free | AMO account |
| **Safari** | Safari extension | Нет Xcode project | Часть Apple Dev | safari-web-extension-converter |

---

## 9. Что блокирует Railway /health=200 прямо сейчас

**Текущее состояние:** commit `fe72d42` на main, Nixpacks + Procfile, Dockerfile удалён, catboost убран, lax mode на config.

### Возможные оставшиеся блокеры (от наиболее вероятного):

1. **Env vars в Railway пустые / неправильные.** Pod стартует, `validate_settings()` ругается но не падает (lax mode), `/health` возвращает `degraded` (redis: down). **Railway health check ждёт 200** — возможно настроен на `/health` и отказывается mark'нуть deploy как healthy. → **Проверить:** `https://railway.com/project/3568c94d-…/service/[api]/settings` → "Health Check Path". Если стоит `/health` — pod в статусе unhealthy и Railway не роутит traffic.

2. **Redis не подключён.** `REDIS_URL=redis://localhost:6379` (default) в prod = нет Redis → `/health` = degraded. Rate limiter через `api.services.cache` выкинет exception на любом rate-limited endpoint → 5xx.

3. **Memory limit.** Без catboost должно быть OK (~150MB resident), но если Starter plan = 512MB и вы запускаете всё через `python -m uvicorn api.main:app` с множеством routers (13 штук) — можно упереться.

4. **CORS / middleware crash.** `api/main.py:71` инициализирует `SecurityHeadersMiddleware` до проверки настроек. Если в `api/services/security_headers.py` есть bug → 500 на каждом запросе. Local pytest зелёный (373 теста), но может не покрывать этот case.

5. **Port binding.** `Procfile` использует `$PORT` — Railway инжектит, должно работать. Если `start.sh` как-то запустился вместо Procfile (custom start cmd) — bound на 127.0.0.1, Railway не дойдёт.

### Как диагностировать
1. Railway logs: `https://railway.com/project/3568c94d-3805-4b66-9972-b63a5d6816e7/service/[api]/deployments/[latest]/logs` → ищите "startup_validation_failed_lax_mode" + сам текст ошибки.
2. `curl https://[railway-prod-url]/` (root, не /health) — если 200 → pod жив, но health endpoint падает на redis.
3. `curl https://[railway-prod-url]/health` — увидите JSON `{"status":"degraded","redis":"down"}` если redis отсутствует.

---

## 10. Production readiness checklist

### MUST DO (blocking launch)

- [ ] **Выставить все обязательные env vars в Railway prod.** *Why:* без них config validation молча падает в lax mode, /health=degraded, Railway health check не пропускает. *How:* https://railway.com/project/3568c94d-3805-4b66-9972-b63a5d6816e7 → Service → Variables → добавить `ENVIRONMENT, DEBUG, SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_KEY, SUPABASE_JWT_SECRET (64+), SENTRY_DSN, REDIS_URL, GOOGLE_SAFE_BROWSING_KEY, STRIPE_SECRET_KEY (sk_live_), STRIPE_WEBHOOK_SECRET, ALLOWED_ORIGINS`.
- [ ] **Подключить Redis.** *Why:* без Redis ломается rate limiting + cache, `/health` навсегда degraded. *How:* Railway → New → Database → Redis → скопировать `REDIS_URL` → добавить в API service variables.
- [ ] **Настроить Railway Healthcheck Path.** *Why:* сейчас либо `/health` (даёт degraded = unhealthy) либо не задано. *How:* Service Settings → Healthcheck Path = `/` (root возвращает всегда 200 если процесс жив), не `/health`. Оставить `/health` для ручного мониторинга.
- [ ] **Убрать сломанные CI jobs.** *Why:* `ci.yml job docker:` и `security.yml job sbom:` билдят удалённый Dockerfile → Actions красные. *How:* удалить job'ы или вернуть минимальный Dockerfile, ссылающийся на `python -m uvicorn`.
- [ ] **Ротировать секреты после Vercel incident.** *Why:* Vercel прислал security email сегодня. *How:* см. `docs/runbooks/vercel-incident-response.md` + ротировать: Supabase service key, Stripe restricted keys, любые токены в Vercel env.
- [ ] **Vercel env vars.** *Why:* landing без `NEXT_PUBLIC_API_URL` работает на fallback Railway URL (некрасиво, CORS проблемы потом). *How:* Vercel → Project → Settings → Environment Variables → `NEXT_PUBLIC_API_URL, NEXT_PUBLIC_SUPABASE_URL, NEXT_PUBLIC_SUPABASE_ANON_KEY, NEXT_PUBLIC_STRIPE_PUB_KEY`.
- [ ] **Stripe webhook endpoint.** *Why:* subscriptions событий не достигают backend. *How:* Stripe Dashboard → Webhooks → Add endpoint → `https://[api-prod]/api/v1/payments/webhook` → copy signing secret → Railway env `STRIPE_WEBHOOK_SECRET`.
- [ ] **Custom domain для API.** *Why:* `web-production-fe08.up.railway.app` захардкожен в 5+ местах; custom domain даёт стабильность если Railway service пересоздастся. *How:* Railway → Settings → Domains → Generate → добавить CNAME `api.cleanway.ai` → обновить fallback'и в landing/mobile/extension.
- [ ] **Supabase: RLS проверить в Supabase SQL Editor**. *Why:* если миграция 001 запустилась без RLS policy на часть таблиц → утечка данных через PostgREST. *How:* `SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname='public';` — все должны быть `t`.

### SHOULD DO (quality)

- [ ] **Создать `mobile/eas.json`** с environment профилями → можно запускать `eas build -p ios --profile production`.
- [ ] **`STRICT_CONFIG=true` после стабилизации.** *Why:* lax mode прячет misconfig; после того как всё стабильно работает — flip to strict.
- [ ] **sitemap.ts + robots.ts + metadata** в `landing/app/` для SEO.
- [ ] **Security headers** в `landing/next.config.ts` (CSP, HSTS, X-Frame-Options).
- [ ] **Backup для Supabase** — PITR уже включён на платных планах, проверить.
- [ ] **Chrome Web Store / Firefox AMO / Safari listings** — screenshots, descriptions, privacy policy.
- [ ] **Миграция 001 → idempotent** (`CREATE TABLE IF NOT EXISTS`) — рисуется когда копируете на новую среду.
- [ ] **Removed `localhost:8000`** из prod `host_permissions` extension manifest (leak info о dev setup).

### NICE TO HAVE (optimization)

- [ ] Upgrade Railway → Pro plan (1GB RAM) → вернуть catboost (см. комментарий в `requirements.txt:12-21`).
- [ ] Mobile: adaptive-icon плотности, app icon в 1024×1024, notification icon.
- [ ] Firefox extension MV2 → MV3 миграция.
- [ ] `/metrics` endpoint для Prometheus/Grafana (observability-monitoring).
- [ ] Load testing (`wrk` / `k6`) против prod — определить real rate limit headroom.
- [ ] Pre-commit hooks проверяются локально (`.pre-commit-config.yaml` есть) — убедиться что каждый разработчик выполнил `pre-commit install`.

---

## Суть, если коротко

1. **Railway 502** = env vars почти наверняка не выставлены + Redis не подключён + Healthcheck Path кривой. Логи Railway покажут точную причину за 30 секунд.
2. **CI красный** = два workflow бьются об удалённый Dockerfile. Две строки удалить.
3. **Vercel incident** = отдельная история, runbook уже есть.
4. **Prod launch блокеры** = ~8 пунктов в MUST DO, остальное — polish.

После MUST DO → `/health` = ok, Railway трафик идёт, landing/mobile/extension работают через Railway URL (захардкоженный fallback), готовы принимать плательщиков.
