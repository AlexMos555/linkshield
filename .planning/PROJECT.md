# PROJECT: LinkShield

## Vision

LinkShield — невидимый щит от фишинга, который работает автоматически на всех устройствах. Персональный security-аналитик, который живёт на твоём устройстве и знает всё о твоей безопасности — но никому об этом не рассказывает.

## One-Liner

"Защита от фишинга для обычных людей. Ваши данные о безопасности живут только на вашем устройстве."

## Problem

- 1M+ фишинговых атак в Q1 2025 (APWG)
- Aura потеряла 900K записей с SSN, кредитными данными, адресами (март 2026)
- Существующие решения хранят на серверах всё — browsing history, audit results, score
- Нет "поставил и забыл" решения для всех устройств
- Никто не объясняет понятным языком что опасного в ссылке

## Solution

### Три уровня защиты
1. **Browser Extension** — автопроверка ссылок, Privacy Audit
2. **Мобильное приложение** — VPN / DNS, защита ВСЕХ приложений
3. **Email-прокси** (B2B) — проверка ссылок ДО попадания в ящик

### Архитектура "Boring Database"

**Сервер хранит "скучное" (account data):**
Если утечёт — атакующий узнает что человек пользуется LinkShield. И всё.
- user_id, email (для аккаунта и опционального дайджеста)
- Подписка, срок действия
- Семейная группа (кто в семье, не что они делают)
- Список устройств (для sync)
- Агрегаты: total_checks, total_blocks за неделю (для percentile)

**Устройство хранит "ценное" (behavior data):**
Никогда не покидает устройство. Персональный security-аналитик.
- Полная история проверок (каждый URL, каждый score)
- Результаты Privacy Audit (трекеры, формы, cookies по каждому сайту)
- Security Score (детали, факторы, история)
- Weekly Report (сырые данные)
- Лог трекеров и fingerprinting-попыток
- Содержание семейных алертов (E2E encrypted)

**Правило:** сервер знает КТО ты. Устройство знает ЧТО ты делаешь. Browsing-поведение никогда не покидает устройство.

### Killer Features

- **Privacy Audit** — "что собирает сайт" понятным языком (Grade A-F), 100% on-device
- **Aha-moment** — extension сканирует ссылки на открытой Gmail-странице
- **Weekly Report** — on-device генерация + реальный percentile ("безопаснее 89% пользователей") через серверный агрегат
- **Security Score** — 0-100, расчёт на устройстве, breach check через k-anonymity
- **E2E Family Hub** — сервер управляет membership, содержание алертов E2E encrypted
- **B2B Phishing Simulation** — на той же инфраструктуре с org-level данными

## Target Audience

- **Старт:** обычные люди (B2C)
- **Рост:** Family Hub (вирусный механизм)
- **B2B (V3):** SMB, та же инфраструктура + org-level dashboard

## Business Model

| Tier | Price | Features |
|---|---|---|
| Free | $0 | Extension, server-enforced rate limit, grade-only audit |
| Personal | $4.99/mo | Безлимит, full Privacy Audit, мобильное, Score, Report |
| Family | $9.99/mo | До 6 устройств, Family Hub, E2E алерты |
| Business | $3.99/user/mo | Email-прокси, phishing sim, SSO, API, org dashboard |

## Tech Stack

- **Extension:** TypeScript, Manifest V3
- **Mobile:** React Native + NEPacketTunnelProvider / VpnService
- **Backend:** FastAPI (Python) — URL analysis
- **Edge:** Cloudflare Workers — bloom filter CDN + URL check
- **Database:** Supabase (PostgreSQL + Auth + Realtime)
- **Payments:** Stripe (web + mobile web) + Apple IAP + Google Play Billing
- **Family relay:** Supabase Realtime + E2E encryption
- **On-device:** SQLite (mobile), IndexedDB (extension)
- **Sync:** Supabase Realtime (settings + aggregates only)
- **Data Sources:** Google Safe Browsing, PhishTank, VirusTotal, WHOIS, SSL Labs

## Privacy Positioning

**Marketing:** "Your browsing data lives only on your device. Our servers know your account — not what you do online. Even if we're breached, attackers learn nothing about your online life."

**Comparison with Aura breach:** their leak exposed SSN, credit data, addresses. Our hypothetical leak exposes: email + subscription status. No URLs, no audit results, no browsing history.

## Success Metrics

- V1 (3 мес): 5,000 установок, 200 paying, 50% weekly retention
- V2 (6 мес): 25,000 пользователей, 3.0 family invite ratio
- V3 (12 мес): 10 B2B клиентов, $15k MRR
