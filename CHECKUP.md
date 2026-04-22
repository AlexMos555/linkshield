# 🎯 Cleanway — CHECKUP (живой перед глазами)

**Этот файл = текущее состояние.** Обновляется на каждом шаге. Ставь ✅/❌ прямо тут.

## 🗺️ Где что ХРАНИТСЯ — карта реальности

Cleanway — многокомпонентная система. Каждый секрет/конфиг живёт в одном конкретном месте:

```
┌──────────────────────────────────────────────────────────────────────┐
│  ТВОЙ КОМП                                                           │
│  /Desktop/Cleanway/Cleanway/.env  ← все 27 секретов СЕЙЧАС тут   │
│  (gitignored, не в git — правильно)                                  │
│                                                                      │
│  ❗ Проблема: когда ты выключаешь комп, Railway/Vercel эти секреты   │
│     НЕ ВИДЯТ. Prod полагается на облачные хранилища.                 │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│  GITHUB (publicly readable repo)                                     │
│  AlexMos555/cleanway                                               │
│                                                                      │
│  ЧТО ХРАНИТ:                                                         │
│   ✓ Исходный код (api/, landing/, mobile/, extension/)               │
│   ✓ Миграции Supabase SQL (supabase/migrations/*.sql)                │
│   ✓ CI workflow'ы (.github/workflows/*.yml)                          │
│   ✓ .env.example (БЕЗ секретов — шаблон)                             │
│                                                                      │
│  НЕ ХРАНИТ (правильно):                                              │
│   ✗ .env с настоящими ключами                                        │
│   ✗ Supabase service_role (дал бы доступ к БД)                       │
│   ✗ Stripe sk_live_                                                  │
│   ✗ JWT secrets                                                      │
│                                                                      │
│  GitHub Settings → Secrets (отдельное место для CI):                 │
│   - RAILWAY_TOKEN_PRODUCTION (для auto-deploy через workflow)        │
│   - (Сейчас не настроено — не критично, Railway auto-deploy без него)│
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│  RAILWAY (backend API runtime)                                       │
│  web-production-fe08.up.railway.app                                  │
│                                                                      │
│  ДОЛЖЕН ХРАНИТЬ (server-side секреты):                               │
│   - SUPABASE_URL, SUPABASE_SERVICE_KEY, SUPABASE_JWT_SECRET          │
│   - REDIS_URL (когда добавим Redis)                                  │
│   - STRIPE_SECRET_KEY (sk_live_)                                     │
│   - GOOGLE_SAFE_BROWSING_KEY                                         │
│   - SENTRY_DSN                                                       │
│   - ALLOWED_ORIGINS, ENVIRONMENT, DEBUG                              │
│                                                                      │
│  СЕЙЧАС:                                                             │
│   ❌ Пусто / недостаточно. Pod 502.                                  │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│  SUPABASE (database + auth)                                          │
│  bpyqgzzclsbfvxthyfsf.supabase.co (EU Frankfurt)                     │
│                                                                      │
│  ХРАНИТ (у Supabase своя консоль для этого):                         │
│   ✓ Таблицы public.* (users, devices, subscriptions, ...)            │
│   ✓ Таблицы auth.* (внутренние Supabase — user accounts)             │
│   ✓ Row-Level Security policies                                      │
│   ✓ Migrations 001–005 уже применены                                 │
│                                                                      │
│  ОТТУДА ТЫ БЕРЁШЬ (копируешь в Railway Variables):                   │
│   → Project URL                                                      │
│   → anon / public key                                                │
│   → service_role key (⚠️ только server-side)                          │
│   → JWT secret                                                       │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│  VERCEL (landing deployment)                                         │
│  cleanway-landing project                                          │
│                                                                      │
│  ДОЛЖЕН ХРАНИТЬ (client-side публичные ключи):                       │
│   - NEXT_PUBLIC_API_URL                                              │
│   - NEXT_PUBLIC_SUPABASE_URL                                         │
│   - NEXT_PUBLIC_SUPABASE_ANON_KEY (безопасно публиковать,            │
│      RLS защищает данные)                                            │
│                                                                      │
│  СЕЙЧАС: не проверено. + Vercel incident → нужна ротация токенов     │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│  EAS / Expo Secrets (mobile build)                                   │
│  Пока не настроено                                                   │
│                                                                      │
│  БУДЕТ ХРАНИТЬ:                                                      │
│   - EXPO_PUBLIC_API_URL                                              │
│   - EXPO_PUBLIC_SUPABASE_URL                                         │
│   - EXPO_PUBLIC_SUPABASE_ANON_KEY                                    │
│   - Apple/Google signing certs                                       │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 📊 Статус сервисов

| Сервис | Где | Статус | Блокер |
|---|---|---|---|
| GitHub repo | AlexMos555/cleanway | 🟢 | — |
| Railway API | web-production-fe08 | 🔴 502 | Env vars не выставлены |
| Supabase DB | bpyqgzzclsbfvxthyfsf | 🟢 migrations 001-005 applied | — |
| Vercel landing | cleanway-landing | 🟡 incident pending | Токены не ротированы |
| Redis | нет | 🔴 не provisioned | Нужен addon |
| CI GitHub Actions | 6 workflows | 🟡 3 красных fix-прямо-сейчас | — |
| Stripe | нет account | ⚪ нет блокера сегодня | Будет нужен для платежей |

---

## 🚦 ПЛАН (один путь, без вариантов)

### Шаг 1. Перенос секретов `.env` → Railway (30 минут)

**ЧТО делаем:** все 27 ключей из твоего локального `.env` копируем в Railway Variables. После этого можно будет .env с компа удалить (с бэкапом в 1Password/Keychain).

**ПОЧЕМУ:** Railway-процесс (pod) при запуске читает environment variables из Railway dashboard, не из твоего компа. Без этого `SUPABASE_URL` пустой → запросы к БД падают → 502.

**КАК:**

**1.1 — Открыть свой `.env` на компе:**

```bash
open -e /Users/aleksandrmoskotin/Desktop/Cleanway/Cleanway/.env
```

Увидишь 27 строк вида `KEY=value`.

**1.2 — Открыть Railway Variables editor:**

🔗 https://railway.com/project/3568c94d-3805-4b66-9972-b63a5d6816e7/service/d73d59e3-ae86-49b1-a089-29a2bcdabc89/variables

В правом верхнем углу кнопка **Raw Editor** (или **RAW**) — нажми.

**1.3 — Скопировать ВСЁ содержимое `.env` и вставить** в Raw Editor.

**⚠️ УБРАТЬ перед вставкой** эти строки — они для landing/mobile, не для backend:
- `EXPO_PUBLIC_*` (все)
- `NEXT_PUBLIC_*` (все)
- `SUPABASE_PUBLISHABLE_KEY` (если есть)

Оставить должно:
```
ENVIRONMENT=development
DEBUG=false
SUPABASE_URL=https://bpyqgzzclsbfvxthyfsf.supabase.co
SUPABASE_ANON_KEY=...
SUPABASE_SERVICE_KEY=...
SUPABASE_JWT_SECRET=...
SUPABASE_ACCESS_TOKEN=... (если есть — не обязательно)
SUPABASE_SECRET_KEY=... (алиас service_key — не обязательно)
REDIS_URL=...
SENTRY_DSN=...
STRIPE_SECRET_KEY=...
STRIPE_WEBHOOK_SECRET=...
STRIPE_PUBLISHABLE_KEY=...
GOOGLE_SAFE_BROWSING_KEY=...
PHISHTANK_API_KEY=...
IPQUALITYSCORE_KEY=...
ALLOWED_ORIGINS=https://cleanway.ai,https://www.cleanway.ai,https://mail.google.com,https://outlook.office.com,https://outlook.live.com,https://mail.yahoo.com
FREE_TIER_DAILY_LIMIT=10
PAID_TIER_DAILY_LIMIT=10000
BURST_LIMIT=10
BURST_WINDOW_SECONDS=10
```

**1.4 — Save / Update.**

Railway автоматически редеплоит через 30-60 сек.

**1.5 — Проверка:**

```bash
curl https://web-production-fe08.up.railway.app/health
```

Должен ответить **200 OK** с JSON `{"status":"degraded","redis":"down",...}`. "degraded" — нормально до Шага 2 (Redis).

**Статус выполнения Шага 1:** ⬜ не начато

---

### Шаг 2. Добавить Redis addon в Railway (15 минут)

**ЧТО:** добавляем Redis на Railway как addon, вплетаем ссылку в API service.

**ПОЧЕМУ:** rate limiter и кеш требуют Redis. Без него `/health` = degraded, частично ломается логика лимитов.

**КАК:**

**2.1 — Railway project → кнопка "+ Create" (обычно справа вверху) → "Database" → "Add Redis"**.

Railway создаст service `Redis` рядом с твоим `web`.

**2.2 — Вернуться в `web` service → Variables → Raw Editor:**

Добавить одну новую строку:

```
REDIS_URL=${{Redis.REDIS_URL}}
```

Это reference variable — Railway сам подставит реальный URL из Redis service.

**⚠️ Если у тебя уже была строка `REDIS_URL=redis://...` из локального .env — УДАЛИ её** и замени на эту reference form.

**2.3 — Save.**

Через 30 сек API service перезапустится с живым Redis.

**2.4 — Проверка:**

```bash
curl https://web-production-fe08.up.railway.app/health
```

Теперь должно быть `{"status":"ok","redis":"ok",...}`.

**Статус выполнения Шага 2:** ⬜ не начато

---

### Шаг 3. Healthcheck Path — что там стоит сейчас?

**Я тебе дал противоречие — давай разберусь конкретно.**

**Как проверить что стоит сейчас:**

🔗 https://railway.com/project/3568c94d-3805-4b66-9972-b63a5d6816e7/service/d73d59e3-ae86-49b1-a089-29a2bcdabc89/settings

Найди секцию **Deploy → Healthcheck Path**. Там одно из трёх:

1. **Пусто** (кнопка `+ Healthcheck Path`) — ничего не делать. Railway пингует TCP-порт, этого достаточно.
2. **`/health`** — теперь правильно. Я зафиксил endpoint чтобы всегда возвращать 200 OK. **Ничего не менять.**
3. **Что-то другое (`/api/v1/...`)** — скажи мне что именно, подскажу конкретно.

**После Шагов 1+2 Railway healthcheck будет проходить в любом из трёх случаев.** Это не блокер.

**Статус:** ⬜ проверить что там стоит, пришли скрин

---

### Шаг 4. Vercel env vars (20 минут)

**ЧТО:** кладём `NEXT_PUBLIC_*` ключи в Vercel (они публичные, но landing без них падёт в fallback Railway URL).

**КАК:**

**4.1 — https://vercel.com/dashboard → cleanway-landing → Settings → Environment Variables**

**4.2 — Добавить три:**

| Key | Value | Environment |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | `https://web-production-fe08.up.railway.app` | Production, Preview |
| `NEXT_PUBLIC_SUPABASE_URL` | `https://bpyqgzzclsbfvxthyfsf.supabase.co` | Production, Preview |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | из твоего `.env` строка `NEXT_PUBLIC_SUPABASE_ANON_KEY=...` | Production, Preview |

**4.3 — Save**, редеплоит landing автоматически.

**Статус:** ⬜ не начато

---

### Шаг 5. Бэкап локального `.env` → и удалить с диска (10 минут)

**ЧТО:** `.env` забирается в 1Password / macOS Keychain, потом удаляем с диска. Если комп украдут — секреты не утекут.

**КАК (выбери ОДИН способ):**

**5.1 — 1Password (если есть):**
1. 1Password → New Item → Secure Note → назови "Cleanway .env production"
2. Скопируй всё содержимое `.env` в поле "Notes"
3. Save
4. `rm /Users/aleksandrmoskotin/Desktop/Cleanway/Cleanway/.env`

**5.2 — macOS Keychain (если нет 1Password):**
1. Открой `Keychain Access.app`
2. File → New Password Item
3. Keychain Item Name: `Cleanway .env`
4. Account Name: `backend`
5. Password: paste содержимое `.env`
6. Add
7. `rm /Users/aleksandrmoskotin/Desktop/Cleanway/Cleanway/.env`

**5.3 — Для разработки локально:**
Теперь когда тебе нужен локальный `.env` — копируешь из 1Password/Keychain, вставляешь, работаешь, перед sleep'ом компа удаляешь. Или просто читаешь env vars напрямую из Railway (`railway run python -m uvicorn ...` использует cloud env).

**Статус:** ⬜ не начато

---

## ✅ После всех шагов

```bash
# /health = 200 с status=ok
curl https://web-production-fe08.up.railway.app/health

# Landing 200
curl -I https://cleanway-landing.vercel.app

# Анонимный email analyze работает (Gmail banner)
curl -X POST https://web-production-fe08.up.railway.app/api/v1/email/analyze \
  -H "Content-Type: application/json" \
  -H "Origin: https://mail.google.com" \
  -d '{"from_address":"test@test.com","body_text":"hello"}'
```

Если все 3 команды зелёные — Блок 1-2 закрыт, идём к внешним сервисам (Stripe, Sentry, и т.д., см. `docs/runbooks/LAUNCH_ROADMAP.md`).

---

## ❓ Твои вопросы ко мне

Если застрянешь на любом шаге:
- Пришли скрин экрана Railway / Vercel / Supabase на том что непонятно
- Или текст ошибки из терминала
- Или "не вижу кнопку X" — я дам точный путь

Я не знаю что в твоём .env (не читал значения) — только имена ключей. Если там чего-то не хватает — напишу какие именно.
