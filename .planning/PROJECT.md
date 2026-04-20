# PROJECT: LinkShield

## Vision

LinkShield — самая удобная защита от мошеннических ссылок для **обычных людей**: родителей, бабушек, детей, не-техспецов по всему миру. Работает автоматически, говорит понятным языком, не требует знаний. Спасает обычных людей от цифрового мошенничества — тысячи, потом миллионы.

## Mission (внутренний компас)

**Grandma test:** если 70-летняя бабушка за 30 секунд без чьей-либо помощи понимает что сайт мошеннический — мы сделали свою работу. Если нет — продукт не готов.

**Этический принцип:** безопасность — право, не услуга. Блокировка мошенничества всегда бесплатна. Платная подписка даёт детали, персонализацию, защиту семьи — но никогда не открывает и не закрывает сам блок.

## One-Liner

"Автоматическая защита от мошеннических ссылок. Для всех, включая тех кто не разбирается в технологиях."

## Problem

- **1M+ фишинговых атак** в Q1 2025 (APWG отчёт). Рост год к году.
- **Aura потеряла 900K записей** (март 2026) — SSN, кредитные данные, адреса. Существующие решения хранят на серверах всё — browsing history, audit, score.
- **Нет "поставил и забыл" решения** для всех устройств
- **Все решения говорят на техническом языке**: "phishing detected", "fingerprinting", "trust score", "trackers". Обычный человек не понимает — значит не пользуется.
- **Бабушки, родители, дети** — основные жертвы фишинга, и именно они НЕ являются целевой аудиторией существующих решений

## Solution

### Три уровня защиты
1. **Browser Extension** — автопроверка ссылок, визуальные бейджи, блок мошеннических сайтов, Privacy Audit
2. **Мобильное приложение** — VPN / DNS, защита ВСЕХ приложений
3. **Email-прокси** (B2B) — проверка ссылок ДО попадания в ящик

### Архитектура "Boring Database"

**Сервер хранит "скучное" (account data):**
Если утечёт — атакующий узнает что человек пользуется LinkShield. И всё.
- user_id, email (для аккаунта и опционального дайджеста)
- Подписка, срок действия, биллинг-страна (для regional pricing)
- Семейная группа (кто в семье, не что они делают)
- Список устройств (для sync)
- Агрегаты: total_checks, total_blocks за неделю (для percentile)
- Skill-level preference per device (Kids / Regular / Granny / Pro)
- Язык интерфейса preference

**Устройство хранит "ценное" (behavior data):**
Никогда не покидает устройство. Персональный security-аналитик.
- Полная история проверок (каждый URL, каждый score)
- Результаты Privacy Audit (трекеры, формы, cookies по каждому сайту)
- Security Score (детали, факторы, история)
- Weekly Report (сырые данные)
- Лог трекеров и fingerprinting-попыток
- Содержание семейных алертов (E2E encrypted)
- Счётчик заблокированных угроз для freemium threshold (локально)

**Правило:** сервер знает КТО ты. Устройство знает ЧТО ты делаешь. Browsing-поведение никогда не покидает устройство.

## Killer Features

- **Automatic по умолчанию** — после установки ничего не надо настраивать, всё работает само
- **Plain-language everything** — никакого жаргона, бабушка понимает с первого взгляда
- **Privacy Audit** — "что собирает сайт" понятным языком (Grade A-F), 100% on-device
- **Aha-moment** — extension сканирует ссылки на открытой Gmail-странице при первом запуске
- **Weekly Report** — on-device генерация + реальный percentile ("безопаснее 89% пользователей")
- **E2E Family Hub** — сервер управляет membership, содержание алертов E2E encrypted
- **Skill Levels** (Kids/Regular/Granny/Pro) — один продукт, разный UX для разных людей
- **Granny Mode** — киллер-фича: огромный шрифт, голос, 2 цвета, "Спросить внука" кнопка
- **B2B Phishing Simulation** — на той же инфраструктуре с org-level данными

## Target Audience

- **Старт (V1):** обычные люди, приоритет — родители / бабушки / пожилые / не-техи
- **Рост (V2):** Family Hub — младшие члены семьи ставят защиту для старших (вирусный механизм)
- **B2B (V3):** SMB (5-100 человек), та же инфраструктура + org-level dashboard

## International Strategy

### Languages (10, без китайского — требует отдельной CIDR-инфры)
`en, es, hi, pt, ru, ar, fr, de, it, id`

Все строки UI + маркетинг + block pages + error messages с дня 1. Арабский требует RTL. Тональности: формальная для Granny Mode (родителям/бабушкам "вы"), gamified для Kids Mode.

### Regional Pricing (4 tier по PPP)

| Tier | Countries | Personal | Family | Business |
|---|---|---|---|---|
| T1 | US, UK, DE, FR, AU, JP, SG, NL, NO, SE, CH | $5.99/mo | $11.99 | $4.99/user |
| T2 (base) | EU east, RU, BR, MX, KR, IL, TR, PL | $4.99 | $9.99 | $3.99 |
| T3 | LATAM mid, SE Asia, MENA | $2.49 | $4.99 | $1.99 |
| T4 | India, Indonesia, VN, EG, PK, BD | $1.49 | $2.99 | $0.99 |

Привязка по **billing country** (не IP) — избегает VPN-обхода. Stripe Checkout автоматически показывает правильную цену для страны пользователя.

## Business Model — Pricing v2 "feel value, then pay"

### 🆓 Free (forever, без карты)
- **Безлимит проверки** всех ссылок с визуальными бейджами (зелёные/жёлтые/красные)
- **Блок-страница для мошеннических сайтов — ВСЕГДА работает**, даже после лимита
- **Первые 50 заблокированных угроз — полный опыт:**
  - Детальное объяснение почему сайт опасный ("Этот сайт притворяется Сбербанком...")
  - История домена (когда появился, сколько раз его жаловали)
  - Схема мошенничества простым языком
  - Снимок страницы с пометками что подозрительно
- **История** последние 30 дней
- **Privacy Audit** оценка A-F (без деталей)
- **1 устройство**, все 10 языков

### 💎 Paid (триггер после 50 угроз или в любой момент)
- Безлимит детальных объяснений + история домена + схемы мошенничества
- **Privacy Audit full** — полный список трекеров, куков, отпечатков, форм
- **Security Score breakdown** + факторы
- **Weekly Report** с percentile
- **Family Hub** до 6 членов
- **Granny Mode / Kids Mode** для родителей/детей
- **5 устройств**, cloud sync
- Приоритетные обновления ML модели
- Приоритетная поддержка

### Ключевой инвариант
Блокировка мошеннических сайтов — бесплатна навсегда. После 50-угрозного лимита у free-юзера:
- Блок всё ещё срабатывает (безопасность)
- Но детали угрозы скрыты: "Опасный сайт. Разблокируй детали."
- История замораживается на 30 днях
- Privacy Audit остаётся grade-only

Upsell **на ценность** (семья, детали, режимы), не на снятие искусственного лимита.

## Skill Levels (4 режима UX)

Ручной выбор в settings. Family Hub admin может настроить удалённо для членов семьи.

| Level | Аудитория | UX |
|---|---|---|
| 🧒 **Kids** | До 14 лет | Gamified (XP за блок, достижения), упрощённый язык, родительский контроль |
| 👤 **Regular** (default) | Обычный взрослый | Понятные слова, 1 главный статус, минимум кнопок |
| 👵 **Granny** | 60+ или слабовидящие | Шрифт 1.5-2×, голосовые алерты, 2 цвета, "Спросить внука" |
| 🛠️ **Pro** | Tech-savvy | Все детали: сигналы, score breakdown, raw data, JSON exports |

## Tech Stack

- **Extension:** TypeScript, Manifest V3 (Chrome), Manifest V2 (Firefox), Manifest V3 (Safari)
- **Mobile:** React Native (Expo) + NEPacketTunnelProvider (iOS) / VpnService (Android)
- **Backend:** FastAPI (Python 3.9+) — URL analysis
- **Edge:** Cloudflare Workers — bloom filter CDN
- **Database:** Supabase (PostgreSQL + Auth + Realtime)
- **Payments:** Stripe (regional price IDs) + Apple IAP + Google Play Billing
- **Family relay:** Supabase Realtime + E2E encryption
- **On-device:** SQLite (mobile), IndexedDB (extension)
- **Sync:** Supabase Realtime (settings, aggregates, skill level — NEVER browsing data)
- **i18n libraries:** next-intl (landing), i18next (extension), expo-localization (mobile)
- **Data Sources:** Google Safe Browsing, PhishTank, URLhaus, PhishStats, ThreatFox, Spamhaus, SURBL, AlienVault OTX, IPQualityScore
- **ML:** CatBoost (27 features, AUC 0.9988), hosted bloom filter

## Privacy Positioning

**Marketing (все 10 языков):** "Ваши данные о безопасности живут только на вашем устройстве. Наши серверы знают ваш аккаунт — не что вы делаете онлайн. Даже если нас взломают, хакеры не узнают ничего о вашей цифровой жизни."

**Сравнение с Aura breach:** их утечка exposed SSN, credit data, addresses. Наша гипотетическая утечка exposes: email + subscription status + billing country. No URLs, no audit results, no browsing history.

## Success Metrics

- **V1** (3 мес после launch): 10,000 установок globally, 300 paying (3% conversion), 50% weekly retention
- **V2** (6 мес): 50,000 пользователей в 10 языках, 2.5 family invite ratio (каждый paid юзер зовёт семью)
- **V3** (12 мес): 20 B2B клиентов (SMB), $25k MRR, granny mode adoption 15% paid users

## Out of Scope (сейчас)

- Антивирус, VPN for encryption, password manager, ad-blocking (not our focus)
- Desktop native app (extension покрывает)
- Server-side URL history или browsing profiles (privacy invariant)
- Gmail API integration (extension scanning лучше)
- Chinese market (требует отдельной инфры: CIDR blocks, WeChat, Alipay)
- iOS 14- / Android 8- (слишком старое для качественного VPN API)
