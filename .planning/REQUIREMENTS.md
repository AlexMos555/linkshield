# REQUIREMENTS: LinkShield v2

> Зафиксировано 2026-04-14 после gap-audit. Заменяет старую версию.
> См. также: PROJECT.md, I18N_ARCHITECTURE.md, PRICING_MATRIX.md, SKILL_LEVELS.md.

---

## Cross-cutting invariants (MUST для всего)

**I1 — Privacy invariant**
Никакое поведение пользователя (полные URL, содержимое страниц, audit результаты, score детали, tracker лог) не покидает устройство. Сервер видит домен (для проверки) и агрегаты (для percentile). Никогда не логгировать полные URL.

**I2 — Blocking-is-free invariant**
Блокировка мошеннического сайта работает всегда, даже для free-юзеров после лимита 50 угроз. Никогда не показывать "paywall вместо блока".

**I3 — Plain-language invariant**
Default Regular Mode UI не содержит терминов: phishing, audit, tracker, fingerprinting, breach, score, percentile, bloom filter, ML, heuristic, signal. Замены определены в `SKILL_LEVELS.md` / глоссарии.

**I4 — i18n invariant**
Любая новая UI-строка добавляется во все 10 locales (en, es, hi, pt, ru, ar, fr, de, it, id). Hardcoded English строки в production коде = bug.

**I5 — Regional pricing invariant**
Никаких hardcoded "$4.99" в коде. Цены берутся из Stripe price IDs per country (см. PRICING_MATRIX.md). Detection: billing country, не IP.

**I6 — Accessibility invariant**
Все интерфейсы должны работать в Granny Mode (шрифт 1.5-2×, голосовые алерты, 2 основных цвета). RTL layout для арабского. WCAG AA минимум.

---

## Milestone 1 — Strategic Foundation (Phase A)

### R1.A1 — Доки и решения зафиксированы
- PROJECT.md с intl strategy, pricing v2, skill levels ✅
- REQUIREMENTS.md (этот файл) ✅
- ROADMAP.html с честным baseline ✅
- I18N_ARCHITECTURE.md — выбор библиотек и пайплайн переводов
- PRICING_MATRIX.md — 4 tier + Stripe price IDs + detection
- SKILL_LEVELS.md — UX спеки для Kids/Regular/Granny/Pro + глоссарий замен жаргона
- COMPETITIVE-ANALYSIS.md обновлён (+7 конкурентов, + UX-axis column)

---

## Milestone 2 — Shipping Unblock (Phase B)

### R2.B1 — Env-driven API URL
**Критерий:** во всех клиентах (extension × 3, mobile, landing) URL API задаётся переменной окружения / build-time config, не hardcoded.
- extension/src/utils/api.js: `API_BASE = process.env.LINKSHIELD_API_URL || 'https://api.linkshield.io'`
- extension-firefox, extension-safari: аналогично
- mobile/src/services/api.ts: аналогично через expo env
- landing: через `NEXT_PUBLIC_API_URL`
- Build-time замена для extension (webpack/esbuild define)

### R2.B2 — Railway stable
**Критерий:** API деплоится и отвечает стабильно. Healthcheck проходит. Откачен DEBUG-коммит.
- Procfile: `web: uvicorn api.main:app --host 0.0.0.0 --port $PORT`
- Health check endpoint `/health` (уже есть)
- Env vars заданы в Railway dashboard (см. .env.example)
- Sentry DSN для мониторинга

### R2.B3 — Supabase production
**Критерий:** project создан, миграции запущены, RLS работает.
- Schemas: users, subscriptions, devices, weekly_aggregates, families, family_members, org (B2B)
- Добавленные поля: `users.preferred_locale`, `users.skill_level`, `subscriptions.billing_country`
- RLS policies: пользователь читает/пишет только свои строки; admin Family Hub может читать членов семьи (только membership, не content)
- Applied via migrations/*.sql или Supabase CLI

### R2.B4 — Google Safe Browsing API key
Free tier: 10K lookups/day. Создаётся в console.cloud.google.com. Добавляется в env `GOOGLE_SAFE_BROWSING_KEY`.

### R2.B5 — Stripe regional pricing
**Критерий:** Personal/Family/Business products созданы, price IDs для 4 tier × 3 plan = 12 IDs.
- Test mode сначала, потом prod copy
- Webhook: создан endpoint в API, подписан на events (checkout.session.completed, customer.subscription.*)
- Signature verification в webhook handler (уже есть код, проверить)
- Billing country detection: Stripe автоматически возвращает в session metadata

### R2.B6 — Upstash Redis или Railway Redis addon
Production Redis для rate limiting + domain cache. URL в env `REDIS_URL`.

### R2.B7 — Vercel deploy landing + domain
**Критерий:** `linkshield.io` резолвится на Vercel deployment.
- Deploy landing/ как Next.js app
- Environment vars: NEXT_PUBLIC_API_URL, NEXT_PUBLIC_STRIPE_PUB_KEY
- Custom domain linkshield.io + www.linkshield.io
- SSL (Vercel auto)

### R2.B8 — Pytest migration
**Критерий:** существующие тесты конвертированы в pytest формат с coverage.
- tests/*.py → переписать с `def test_xxx():` функциями и pytest assertions
- Добавить pytest-cov, целевой coverage ≥80%
- CI (.github/workflows/ci.yml) запускает `pytest --cov=api --cov-fail-under=80`

### R2.B9 — E2E smoke test
**Критерий:** chrome extension dev-loaded → запрос к реальному Railway API → real score → badge показывается.
- Документация: docs/E2E_SMOKE.md с шагами проверки

---

## Milestone 3 — Regular User UX + i18n (Phase C)

### R3.C1 — Popup redesign
**Критерий:** popup по умолчанию (Regular Mode) показывает:
- **1 главный статус** большим текстом: "ЭТА СТРАНИЦА БЕЗОПАСНА" / "ВНИМАНИЕ — НА СТРАНИЦЕ НАЙДЕНЫ ОПАСНЫЕ ССЫЛКИ" / "ЭТОТ САЙТ МОШЕННИЧЕСКИЙ"
- **2 secondary действия:** "Посмотреть что собирает этот сайт" + "Моя неделя"
- **"Ещё"** menu с остальным (Breach, Trust, Report, Score, Settings)
- Stats grid убрать с первого экрана, показывать по тапу на главный статус

### R3.C2 — Глоссарий замен жаргона
Централизованный `src/i18n/glossary.json` для всех 10 языков:

| Техническое | Regular Mode |
|---|---|
| Phishing | Мошеннический сайт / Scam site |
| Suspicious | Подозрительный / Suspicious |
| Audit (this page) | Что собирает этот сайт / What this site collects |
| Tracker | Следящий код / Tracking code |
| Fingerprinting | Отпечаток браузера / Browser fingerprint |
| Breach Check | Проверка утечки email / Email leak check |
| Score | Уровень защиты / Protection level |
| Percentile | Безопаснее X% пользователей / Safer than X% |
| Bloom filter / ML | (скрыть от обычного юзера) |

Pro Mode — техническая терминология сохранена.

### R3.C3 — Welcome онбординг (3-4 шага)
- Шаг 1: "Привет! Я буду проверять каждую ссылку за тебя" (auto-on демо)
- Шаг 2: Сканируем Gmail → "Я нашёл 3 подозрительные ссылки которые Chrome пропустил" (aha-moment)
- Шаг 3: "Выбери режим: Я сам / Для родителей / Для ребёнка / Технический" → переход в skill-level selector
- Шаг 4: "Готово! Я буду работать в фоне. Ты заметишь меня только когда найду угрозу."

### R3.C4 — Block page redesign
**Критерий:** когда юзер пытается зайти на мошеннический сайт, видит:
- **Большое "СТОП"** (занимает ~40% экрана, красный)
- **Простое объяснение:** "Этот сайт притворяется <[известным брендом]> чтобы украсть ваш пароль"
- **Схема мошенничества** пример: "Вас попросят ввести данные → Мошенник получит ваш пароль → Украдёт деньги с счёта"
- **Countdown 3 сек** перед тем как можно кликнуть "Всё равно открыть" (для случаев false positive)
- **Кнопки:** "Вернуться назад" (primary, большая, зелёная) / "Я понимаю риск" (secondary, маленькая, серая)
- **Нет жаргона:** никаких "phishing", "malicious URL", "SSL certificate invalid"

### R3.C5 — Лендинг полный комплект
- `/` Hero
- `/pricing` — показывает цены для detected country с переключателем
- `/faq` — 15-20 частых вопросов простым языком
- `/comparison` — таблица vs Guardio / Malwarebytes / Aura (подчёркиваем UX angle)
- `/testimonials` (заглушки ok пока нет реальных)
- `/download` — CTA на Chrome Web Store / App Store / Play Store
- `/family` — отдельный лендинг для Family plan (emotional copy "защитите родителей")
- `/granny` — спец-страница для Granny Mode (для взрослых детей которые устанавливают родителям)

### R3.C6 — i18n инфраструктура
- Landing: **next-intl** (совместим с Next.js 15 App Router)
- Extension: **i18next** + `chrome.i18n.getMessage()` fallback
- Mobile: **expo-localization** + i18next
- Translations/ директория с JSON файлами per language
- DeepL API для первичных переводов (через ключ), ручная вычитка для ru/en обязательна
- Нативная вычитка для остальных 8 языков — позже, при росте

### R3.C7 — RTL support
- Arabic layout: `dir="rtl"` on html/root, зеркальные margins/padding
- Icons: некоторые иконки-стрелки зеркалить (например, "назад" → вправо)
- Text alignment: start/end вместо left/right везде в CSS

### R3.C8 — Pricing v2 реализация
- Счётчик `threatsBlocked` в on-device storage (IndexedDB для extension, SQLite для mobile)
- При достижении 50: показывать nudge UI (не блокирующий, закрываемый)
- Проверить subscription state перед показом нюджа (не показывать paid юзерам)
- Paid check: subscription active + in grace period OK
- Paywall UX для деталей угрозы: "Разблокировать детали — $X/mo" с кнопкой → Stripe Checkout

---

## Milestone 4 — Skill Levels (Phase D)

### R4.D1 — Skill-level selector
- Settings → Skill Level → 4 cards (Kids / Regular / Granny / Pro)
- Preview каждого режима (screenshot превью)
- Сохраняется в user settings (Supabase + локально)
- Sync через Supabase Realtime при изменении

### R4.D2 — Granny Mode
См. SKILL_LEVELS.md для полных спек. Ключевые требования:
- Font size × 1.5-2.0
- 2 доминирующих цвета: ярко-зелёный (безопасно) и ярко-красный (опасно)
- Голосовые алерты (Web Speech API / expo-speech) на блок: "Внимание! Этот сайт хочет украсть ваши деньги. Закройте его."
- Block page: фото мошенника-силуэта, текст как для Regular но крупнее, countdown 5 сек (больше времени понять)
- "Спросить внука" кнопка: отправляет уведомление в Family Hub родственникам
- Скрывает: settings сложные, Privacy Audit детали, советы, статистика

### R4.D3 — Kids Mode
- Gamified: блок = +50 XP, достижения ("Первая ловушка", "10 безопасных дней", "Помог другу")
- Упрощённая лексика: "Плохой сайт" / "Хороший сайт"
- Parental dashboard (родительский аккаунт Family): логи блоков, daily summary
- Safe Search enforcement (если возможно через extension API)
- Время экрана / report для родителей (P2)

### R4.D4 — Pro Mode
- Full signals breakdown (все 42+ signal scores)
- Model predictions (rules + ML probability + confidence)
- Raw data export (JSON, CSV)
- Developer tooling: test any URL manually, inspect bloom filter, see feature vector
- Verbose logs

### R4.D5 — Family Hub backend
- family + family_members tables (уже в схеме)
- E2E encryption library (libsodium / NaCl) для alert content
- Server relays encrypted blob, не может расшифровать
- Invite flow:
  - QR code (для очной встречи)
  - Link + PIN (для удалённой установки бабушке)
- Admin can set skill-level remotely for family members' devices (via Realtime)
- "Спросить внука" → triggers push notification to admin

---

## Milestone 5 — Mobile for Real (Phase E)

### R5.E1 — iOS native VPN
**Критерий:** NEPacketTunnelProvider работает реально:
- DNS query interception
- Bloom filter check on-device
- Safe domain → return result normally
- Dangerous domain → return NXDOMAIN + trigger block screen via IPC
- Fallback на API query для unknown domains (domain only, не full URL)

### R5.E2 — Android native VPN
**Критерий:** VpnService реализован:
- TUN interface, DNS over UDP intercept
- Same bloom filter check + API fallback logic
- Notification channel для block alerts

### R5.E3 — Smart VPN fallback
- Detect при старте: если у юзера уже активен VPN → не можем поднять свой → используем **DNS over HTTPS profile** (iOS) / **Private DNS** (Android) как fallback
- Degraded mode UI: "Работает только для Safari/Chrome, не для всех приложений"

### R5.E4 — App Store submission
- VPN category (требует обоснования для review)
- Screenshots для всех skill levels + 10 languages
- Privacy nutrition labels: "Zero data collected on device usage"
- Age rating: 4+ (с parental controls для Kids)
- Review: 1-3 недели

### R5.E5 — Google Play submission
- Data Safety: честно показать что собираем (email, subscription, aggregates) и что НЕ собираем (browsing)
- App bundle + signed
- Target SDK 34+

### R5.E6 — Mobile Billing
- Apple IAP через expo-in-app-purchases
- Google Play Billing через react-native-iap
- Server-side receipt validation
- Sync subscription state с Supabase

---

## Out-of-Scope (не делаем)

- Антивирус / малварь сканирование файлов
- Password manager
- VPN for traffic encryption (наш VPN только для DNS-based блока)
- Ad blocking как основная фича (но частично делаем в Privacy Audit)
- Server-side URL history (privacy invariant)
- Gmail API integration (extension scanning лучше)
- Chinese market (отдельная инфра, отложено)
- Legacy browsers: IE, Opera Mini, старые Safari (5.x)
