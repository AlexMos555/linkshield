# 🚀 LinkShield Launch Roadmap — Master Checklist

**Обновлено:** 2026-04-20 · **Commit:** `fe72d42` · **Статус:** 🟡 Railway 502, остальное работает локально

Этот документ — **единое место** где отмечаем что сделано. Ставь ✅ прямо в файл, коммить. Не забудем ни один сервис.

---

## 📊 Общая картина

| Сервис | Назначение | Где | Статус |
|---|---|---|---|
| **Railway** | Backend API (FastAPI) | `web-production-fe08.up.railway.app` | 🔴 502 |
| **Supabase** | DB + Auth (EU Frankfurt) | `bpyqgzzclsbfvxthyfsf.supabase.co` | 🟢 migrations 001–005 applied |
| **Vercel** | Landing (Next.js) | `linkshield-landing` project | 🟡 Security incident pending response |
| **GitHub** | Repo + CI | `AlexMos555/linkshield` | 🟡 3 workflows red (docker + sbom + deploy-staging) |
| **Redis** | Rate limit + cache | **НЕТ** | 🔴 Не provisioned |
| **Stripe** | Платежи | Keys в `.env-examples` | 🟠 Нет live account |
| **Google Safe Browsing** | Threat DB | `GOOGLE_SAFE_BROWSING_KEY` empty | 🟠 Нет ключа |
| **Sentry** | Error tracking | `SENTRY_DSN` empty | 🟠 Нет project |
| **SES / Resend** | Email sender | `.env-examples` | 🟠 Domain не verified |
| **Apple Developer** | iOS + Safari Ext distrib | — | 🟠 Нет аккаунта |
| **Google Play** | Android distrib | — | 🟠 Нет аккаунта |
| **Chrome Web Store** | Chrome Ext distrib | — | 🟠 Нет листинга |
| **Firefox AMO** | Firefox Ext distrib | — | 🟠 Нет листинга |
| **Домен + DNS** | `linkshield.io` vs бренд | Домен ещё не выбран | 🟠 Pending бренд |

Легенда: 🟢 готово · 🟡 в процессе · 🔴 блокер (критично) · 🟠 внешний сервис (нужен аккаунт)

---

## 🔴 БЛОК 1 — Railway API /health=200 (сегодня, 1-2 часа)

**Цель:** GET https://web-production-fe08.up.railway.app/health → 200 OK.

### Шаг 1.1 — Проверить Railway Healthcheck Path
- [ ] Открыть: https://railway.com/project/3568c94d-3805-4b66-9972-b63a5d6816e7/service/d73d59e3-ae86-49b1-a089-29a2bcdabc89/settings
- [ ] Найти секцию **Deploy → Healthcheck Path**
- [ ] Если стоит `/health` → **изменить на `/`** (root возвращает OpenAPI, всегда 200 если процесс жив)
- [ ] Или убрать поле вообще (пустое → Railway делает TCP ping вместо HTTP)
- [ ] Save

**Почему:** наш `/health` возвращает `degraded` при отсутствии Redis → Railway считает unhealthy → 502.

### Шаг 1.2 — Поставить минимальные env vars в Railway
- [ ] Railway → Variables (рядом с Settings) → **Raw Editor** → paste:

```
ENVIRONMENT=development
DEBUG=false
SUPABASE_URL=https://bpyqgzzclsbfvxthyfsf.supabase.co
SUPABASE_ANON_KEY=<copy from Supabase dashboard → Project Settings → API → anon/public>
SUPABASE_SERVICE_KEY=<copy from Supabase dashboard → Project Settings → API → service_role>
SUPABASE_JWT_SECRET=<copy from Supabase → Settings → API → JWT Secret>
ALLOWED_ORIGINS=https://linkshield.io,https://www.linkshield.io,https://mail.google.com,https://outlook.office.com,https://outlook.live.com,https://mail.yahoo.com
```

**Почему `ENVIRONMENT=development`** временно: в development `validate_settings` лояльнее (не требует Sentry/sk_live/ и т.п.). Переключим на `production` в Блоке 4.

- [ ] Save — Railway сделает auto-redeploy.

### Шаг 1.3 — Дождаться redeploy + проверить
- [ ] Через 3-5 мин открыть https://web-production-fe08.up.railway.app/health
- [ ] Ожидаю: `{"status": "degraded", "redis": "down", ...}` с HTTP 200
- [ ] Если всё ещё 502 → смотрим **Railway → Deployments → топовый → Deploy Logs** → ищем `startup_validation_failed_lax_mode` → фиксим точечно

### Шаг 1.4 — Я убираю сломанные CI jobs
- [ ] CI: удаляю job `docker:` из `.github/workflows/ci.yml` *(делаю я)*
- [ ] Security: удаляю job `sbom:` (или делаю if:false) *(делаю я)*
- [ ] Push — зелёная CI

**✅ После Блока 1** — Gmail banner должен работать (CORS + endpoint оба есть).

---

## 🟡 БЛОК 2 — Redis (завтра, 15 минут)

**Цель:** rate limiting и cache работают = `/health` status = `ok`, не `degraded`.

### Шаг 2.1 — Добавить Redis на Railway
- [ ] Railway project → **+ New** → **Database** → **Add Redis**
- [ ] Railway создаст новый service `redis`
- [ ] В **API service** (web) → Variables → добавить `REDIS_URL=${{Redis.REDIS_URL}}` (reference variable — Railway сам подставит)
- [ ] Save → API service auto-redeploys

### Шаг 2.2 — Проверка
- [ ] https://web-production-fe08.up.railway.app/health → `{"status": "ok", "redis": "ok"}` ✓
- [ ] Rate limit endpoint → 200 (ранее бросал 500 без Redis)

**Альтернатива:** Upstash (https://upstash.com) free tier → 10K commands/day — хватит на старт, `REDIS_URL` тот же формат.

**✅ После Блока 2** — `/health = ok`, backend готов к продакшн нагрузке.

---

## 🟡 БЛОК 3 — Vercel incident response (сегодня, 30 минут)

**Цель:** ротировать всё что было на Vercel, после security incident email.

### Шаг 3.1 — Ротация Vercel
- [ ] https://vercel.com/account/tokens → **удалить ВСЕ tokens**, создать новые только по необходимости
- [ ] https://vercel.com/account → смена пароля (20+ символов, уникальный)
- [ ] https://vercel.com/account/security → включить **2FA (TOTP)**
- [ ] Vercel → Activity Log (30 дней) → просмотреть, нет ли чужих login/deploy
- [ ] https://github.com/settings/security-log → ищем подозрительные Vercel OAuth authorizations

### Шаг 3.2 — Vercel env vars
- [ ] Vercel → linkshield-landing → Settings → Environment Variables → добавить:
  - `NEXT_PUBLIC_API_URL=https://web-production-fe08.up.railway.app` (или custom domain когда будет)
  - `NEXT_PUBLIC_SUPABASE_URL=https://bpyqgzzclsbfvxthyfsf.supabase.co`
  - `NEXT_PUBLIC_SUPABASE_ANON_KEY=<anon key из Supabase>`
- [ ] Каждому toggled **"Sensitive"** (шифрование at-rest)
- [ ] Redeploy landing

### Шаг 3.3 — Проверить deployments
- [ ] Vercel → linkshield-landing → Deployments → проверить что последние 30 дней — только с твоих commit SHA

**Подробности:** `docs/runbooks/vercel-incident-response.md`.

**✅ После Блока 3** — Vercel безопасен, landing с env vars.

---

## 🟡 БЛОК 4 — Harden production (эта неделя, 2-3 часа)

### Шаг 4.1 — Sentry
- [ ] Создать project на https://sentry.io → Platform: Python → FastAPI
- [ ] Скопировать DSN → Railway env `SENTRY_DSN=https://....ingest.sentry.io/...`
- [ ] Redeploy → проверить что первый error (ручной `curl /api/v1/check -X POST -d 'bad json'`) появляется в Sentry dashboard

### Шаг 4.2 — Google Safe Browsing
- [ ] https://console.cloud.google.com → создать project `linkshield-prod` → Enable Safe Browsing API
- [ ] APIs & Services → Credentials → Create API Key
- [ ] Restrict key → API restrictions → Safe Browsing API only
- [ ] Railway env `GOOGLE_SAFE_BROWSING_KEY=AIzaSy...`
- [ ] Проверить: `curl https://[api]/api/v1/check -X POST -d '{"domains":["paypa1-verify.tk"]}' -H "Content-Type: application/json"` → должен вернуть высокий score с GSB signal

### Шаг 4.3 — Flip to strict_config=true
- [ ] После того как все env vars выставлены и `/health = ok`:
- [ ] Railway env `STRICT_CONFIG=true` + `ENVIRONMENT=production`
- [ ] Но! для production нужны ещё: `STRIPE_SECRET_KEY=sk_live_...`, `SENTRY_DSN` (обязательно в prod), JWT_SECRET ≥64 chars
- [ ] Если что-то из этого не готово — оставить `ENVIRONMENT=development` пока

### Шаг 4.4 — Landing security headers + SEO
- [ ] Мне: добавить `async headers()` в `landing/next.config.ts` (HSTS, CSP, X-Frame-Options)
- [ ] Мне: создать `landing/app/sitemap.ts` + `landing/app/robots.ts`
- [ ] Проверить `metadata` в `app/[locale]/layout.tsx` — OpenGraph + Twitter Cards

**✅ После Блока 4** — прод-grade конфиг backend + landing.

---

## 🟠 БЛОК 5 — Внешние сервисы для monetization (пока ты ждёшь аккаунты)

### Шаг 5.1 — Домен
- [ ] **Выбрать бренд** (не linkshield.com — занят, не linkshield.io — тоже не наш)
- [ ] Купить домен (Namecheap / Cloudflare Registrar)
- [ ] Создать CNAME `api.[brand].com` → Railway service URL
- [ ] CNAME `www.[brand].com` → Vercel landing
- [ ] Обновить `ALLOWED_ORIGINS` в Railway + `host_permissions` в extension manifests
- [ ] Обновить fallback URL в landing/mobile/extension (5 мест)

### Шаг 5.2 — Stripe
- [ ] https://dashboard.stripe.com → создать account (или войти)
- [ ] Activate account (нужен российский / EU / US legal entity)
- [ ] Products → создать 3 subscription (Personal $4.99/mo, Family $9.99/mo, Business $49/mo)
- [ ] Для каждого — создать 24 Price (по одному на каждый из 4 PPP tiers × локалей)
- [ ] API keys → Restricted key → `sk_live_...` → Railway env `STRIPE_SECRET_KEY`
- [ ] Webhook → создать endpoint `https://[api]/api/v1/payments/webhook` → signing secret → Railway env `STRIPE_WEBHOOK_SECRET`
- [ ] Customer portal → включить (self-service subscription management)

### Шаг 5.3 — SES / Resend (транзакционный email)
- [ ] **Resend** (проще на старте): https://resend.com → add domain `mail.[brand].com` → DNS records (SPF, DKIM) → verify
- [ ] API key → Railway env `RESEND_API_KEY=re_...`
- [ ] Проверка: welcome email при signup

### Шаг 5.4 — Apple Developer ($99/год)
- [ ] https://developer.apple.com → Enroll (нужен legal entity)
- [ ] App Store Connect → создать app `io.linkshield.app`
- [ ] Screenshots для iPhone 6.5" и iPad 12.9"
- [ ] Privacy Nutrition Labels: Data Not Collected (browsing), минимум
- [ ] Safari Extension: через Xcode `xcrun safari-web-extension-converter extension-safari/`

### Шаг 5.5 — Google Play ($25 one-time)
- [ ] https://play.google.com/console → Enroll
- [ ] Создать app с package `io.linkshield.app`
- [ ] Screenshots (phone + tablet)
- [ ] Privacy policy URL = `https://[brand].com/privacy`
- [ ] Data safety form

### Шаг 5.6 — Chrome Web Store ($5 one-time)
- [ ] https://chrome.google.com/webstore/devconsole → Register
- [ ] Create new item → upload `extension/` directory as ZIP
- [ ] Single purpose: "block phishing links in browser and webmail"
- [ ] Permission Justifications (storage, notifications, activeTab, tabs)
- [ ] 5 screenshots (1280×800)
- [ ] Promo tile 440×280

### Шаг 5.7 — Firefox AMO (бесплатно)
- [ ] https://addons.mozilla.org/developers → Submit New Add-on
- [ ] Upload `extension-firefox/` ZIP
- [ ] Screenshots + описание

### Шаг 5.8 — Safari App Store
- [ ] Создан Xcode project (через converter из 5.4) → upload в App Store Connect

**✅ После Блока 5** — можно принимать плательщиков + публиковать приложения.

---

## 🟠 БЛОК 6 — Mobile build production (еженедельно, пока внешние сервисы)

### Шаг 6.1 — EAS Build config
- [ ] Мне: создать `mobile/eas.json` с профилями development/preview/production
- [ ] Ты: `npm install -g eas-cli && eas login && eas secret:create --scope project --name EXPO_PUBLIC_SUPABASE_ANON_KEY --value "..." --type string`
- [ ] Ты: `cd mobile && eas build -p ios --profile production` — first build

### Шаг 6.2 — Mobile icons + splash
- [ ] Мне: проверить `mobile/assets/` — нужны 1024×1024 app icon, adaptive icon foreground/background, splash
- [ ] Если отсутствуют — генерировать через Figma / AI (иконка уже должна быть)

### Шаг 6.3 — Mobile native VPN config
- [ ] Мне: создать Expo config plugin `mobile/plugins/with-linkshield-vpn/` (iOS Network Extension + Android VpnService)
- [ ] Ты: тест VPN на физическом устройстве (запрашивает permission)

---

## 🟡 БЛОК 7 — Supabase hardening

### Шаг 7.1 — FK sanity check
- [ ] В Supabase SQL Editor:

```sql
SELECT COUNT(*) FROM public.users u
WHERE NOT EXISTS (SELECT 1 FROM auth.users a WHERE a.id = u.id);
```

- [ ] Ожидаем 0. Если нет → создать триггер для sync:

```sql
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.users (id, email) VALUES (NEW.id, NEW.email)
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();
```

### Шаг 7.2 — RLS sanity
- [ ] В Supabase SQL Editor:

```sql
SELECT tablename, rowsecurity FROM pg_tables
WHERE schemaname='public' ORDER BY tablename;
```

- [ ] Все `rowsecurity` колонки должны быть `t` (true). Если где-то `f` — RLS не включён → данные видны всем через PostgREST.

### Шаг 7.3 — Backup
- [ ] Supabase Dashboard → Project Settings → Database → Backup
- [ ] Если free tier — нет автобэкапов. Upgrade to Pro ($25/mo) для PITR + daily backups.

---

## 🟢 БЛОК 8 — Launch gate (финальная проверка перед анонсом)

Все галочки зелёные → запускаем.

- [ ] Railway `/health` = `ok` (не degraded)
- [ ] Landing https://[brand].com → 200, все 10 локалей рендерятся
- [ ] Extension Chrome Web Store → published (live listing)
- [ ] Mobile iOS → TestFlight beta доступен
- [ ] Mobile Android → Internal testing доступен
- [ ] Stripe Checkout → test payment проходит
- [ ] Welcome email — приходит на ручном signup
- [ ] Sentry — видны errors из production
- [ ] Redis rate limiter — блокирует burst запросы
- [ ] Supabase backups включены
- [ ] Privacy Policy + Terms доступны на landing
- [ ] Support email работает

---

## 📅 Timeline (оценка)

| Блок | Время | Тип работы | Кто делает |
|------|-------|-----------|-----------|
| 1. Railway /health | 1-2h | Config + push | Ты + я |
| 2. Redis | 15 min | Railway UI | Ты |
| 3. Vercel incident | 30 min | Vercel UI | Ты |
| 4. Prod config | 2-3h | External keys + code | Ты + я |
| 5. External services | 1-2 недели | Registration + legal | Ты |
| 6. Mobile build | 3-5 days | EAS + stores | Ты + я |
| 7. Supabase hardening | 1h | SQL | Ты |
| 8. Launch gate | 1 day | QA | Ты |

**ETA до MVP публичного запуска:** ~2 недели (если параллелить блок 5).

---

## 📝 Если что-то забыли

Когда найдём пробел — дописываем в этот файл + commit. Живой документ.
