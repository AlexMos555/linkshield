# Pricing Matrix — LinkShield v2

> Locked 2026-04-14. См. также PROJECT.md раздел "Business Model".

## Pricing model: "feel value, then pay"

### Основной принцип
1. **Блокировка — всегда бесплатна** (блок мошеннических сайтов работает всегда для всех, даже после free-лимита)
2. **Первые 50 опасных угроз — полный опыт** (детали, история, схемы)
3. **После 50 — soft paywall на детали** (блок продолжает работать, но "почему опасно" скрыто)
4. **Paid unlocks ценность** — не снимает искусственный лимит, а даёт семью, детали, режимы, sync

### Почему 50 (а не 10, не 100)
- Статистика APWG: средний юзер встречает ~5 фишинговых ссылок в год
- 50 — это "активный юзер" или "targeted attack victim" — им реально нужна защита
- 95% нормальных юзеров никогда не достигнут порога → они good free юзеры навсегда
- Можно тюнить: снизить до 20-30 если конверсия слишком низкая

---

## Regional tiers (по PPP — purchasing power parity)

### Tier 1 — Premium markets (цены × 1.2 от базы)
Personal $5.99 / Family $11.99 / Business $4.99/user

**Страны:**
US, CA, UK, DE, FR, AU, JP, SG, NL, NO, SE, CH, DK, FI, AT, BE, IE, NZ, IL (часть), LU, IS

### Tier 2 — Base (цены × 1.0)
Personal $4.99 / Family $9.99 / Business $3.99/user

**Страны:**
EU восточные (PL, CZ, SK, HU, RO, BG, HR, SI, LT, LV, EE, GR, PT — подгруппа), RU, BR (часть), MX, KR, TR, IL (другая часть), CL, UY, AR, CR, PA, ES (часть), IT (часть)

### Tier 3 — Mid-emerging (цены × 0.5)
Personal $2.49 / Family $4.99 / Business $1.99/user

**Страны:**
PE, CO, EC, BO, PY, VE, DO, GT, HN, SV, NI, CU, TH, PH, MY, ZA, UA, BY, KZ, RS, MK, AL, BA, ME, GE, AM, AZ, MD, TN, MA, JO, LB, EG (часть)

### Tier 4 — Affordable (цены × 0.3)
Personal $1.49 / Family $2.99 / Business $0.99/user

**Страны:**
IN, ID, VN, PK, BD, EG, NG, KE, LK, MM, NP, KH, LA, MW, UG, TZ, ZW, ZM, MZ, SN, CI, CM

### Fallback
Любая страна не в списке → Tier 2 (base). Список пересматривается ежеквартально.

---

## Stripe implementation

### Product/Price structure

3 products, каждый с 4 price IDs (по tier) + monthly/yearly → **3 × 4 × 2 = 24 price IDs**

```
Product: "LinkShield Personal"
├── price_personal_t1_monthly  ($5.99)
├── price_personal_t1_yearly   ($59.90 — 2 months off)
├── price_personal_t2_monthly  ($4.99)
├── price_personal_t2_yearly   ($49.90)
├── price_personal_t3_monthly  ($2.49)
├── price_personal_t3_yearly   ($24.90)
├── price_personal_t4_monthly  ($1.49)
└── price_personal_t4_yearly   ($14.90)

Product: "LinkShield Family"
├── (same pattern, $11.99/$9.99/$4.99/$2.99 monthly)

Product: "LinkShield Business"
├── (per-seat pricing, $4.99/$3.99/$1.99/$0.99 per user/month)
```

### Country → tier resolution

```python
TIER_1_COUNTRIES = {"US", "CA", "GB", "DE", "FR", "AU", "JP", ...}
TIER_2_COUNTRIES = {"RU", "BR", "MX", "KR", ...}
TIER_3_COUNTRIES = {"PE", "CO", "TH", "PH", ...}
TIER_4_COUNTRIES = {"IN", "ID", "VN", "PK", ...}

def country_to_tier(country_code: str) -> int:
    if country_code in TIER_1_COUNTRIES: return 1
    if country_code in TIER_3_COUNTRIES: return 3
    if country_code in TIER_4_COUNTRIES: return 4
    return 2  # default
```

Реализация: `api/services/pricing.py` с функцией `get_price_id(plan: str, country: str, interval: Literal['monthly','yearly']) -> str`

### Billing country detection

**Приоритет:**
1. Из Stripe Customer object (`customer.address.country`) — ground truth после первой оплаты
2. Из browser: `navigator.language` + GeoIP (на момент checkout)
3. Из IP (fallback)

**Не привязывать к IP runtime** — юзеры с VPN получат некорректный tier. Привязываемся к billing country на момент подписки; при изменении (переезд) — prorate.

### Checkout flow

```javascript
// Frontend: landing/pricing page
async function selectPlan(plan: 'personal' | 'family' | 'business') {
  const country = await detectCountry() // geoip + browser hint
  const tier = countryToTier(country)
  const priceId = PRICE_MAP[plan][tier]['monthly']
  
  const session = await fetch('/api/v1/payments/create-checkout', {
    method: 'POST',
    body: JSON.stringify({ priceId, country })
  })
  
  window.location = session.checkoutUrl
}
```

### Webhook events для subscription state

- `checkout.session.completed` → create subscription в Supabase + update user tier
- `customer.subscription.updated` → sync status
- `customer.subscription.deleted` → downgrade to free
- `invoice.payment_failed` → grace period (7 days) перед downgrade
- `customer.updated` → update billing country если поменялась

Signature verification обязательна (в api/routers/payments.py).

---

## In-app payments (Mobile)

iOS IAP и Google Play Billing — отдельная вселенная. Apple/Google не поддерживают Stripe-style regional pricing напрямую, но:

### iOS Apple IAP
- Apple имеет свои 175 price tiers
- Map our 4 tiers → Apple's nearest tiers per country
- Products: com.linkshield.personal.monthly, com.linkshield.family.monthly, com.linkshield.business.monthly
- Server-side receipt validation
- Cross-platform: если юзер купил через web (Stripe) — активен на mobile тоже (subscription state через Supabase)

### Android Google Play Billing
- Google тоже имеет pricing templates
- Map наши tiers к их templates per country
- Same: cross-platform через Supabase

### Cross-platform rules
- Юзер платит 1 раз на 1 platform (cheapest for them)
- Subscription state sync via Supabase user_id
- Apple's receipt / Google's purchase token → server validates → updates Supabase → other devices pick up via Realtime

---

## Free tier — подробные правила

### Что всегда бесплатно (навсегда)
- Установка и основная защита
- Auto-scan ссылок на странице
- Визуальные бейджи (green/yellow/red)
- Block page для мошеннических сайтов (полнофункциональный)
- Первые 50 опасных угроз — полные детали (reason, history, scheme explanation)
- История своих проверок за последние 30 дней
- Privacy Audit grade (A-F, без деталей)
- 1 устройство
- 10 языков
- Всегда актуальная ML модель (те же обновления что у paid)

### Что меняется после 50 заблокированных угроз

| До 50 угроз | После 50 угроз |
|---|---|
| "Этот сайт притворяется Сбербанком, домен создан 3 дня назад" | "Опасный сайт. Разблокируй детали подпиской." |
| История угроз 30 дней | История замораживается на текущих 30 днях (новые не добавляются в архив) |
| Schema screenshot с пометками | Только базовый блок |
| Объяснение схемы мошенничества | "Разблокируй объяснение подпиской" |

**Что НЕ меняется:**
- Блок мошеннического сайта (работает всегда)
- Badges (работают)
- Auto-scan (работает)

### Upsell triggers (когда показываем paywall)

1. После 50 угроз — единоразовый nudge "Вы были защищены 50 раз. Поддержите проект и защитите семью"
2. При попытке открыть Privacy Audit детали — "Full audit — $X/mo"
3. При попытке добавить устройство #2 — "Multi-device — Family plan"
4. При попытке включить Granny Mode для члена семьи — "Family Hub required"
5. Weekly digest (opt-in email) — 1 раз в неделю "Вы заблокировали N угроз, upgrade для семьи"

**Не делаем:**
- Постоянных баннеров
- Лимитов на обычные проверки (ненависть пользователей)
- Dark patterns (скрытые галочки, обязательная карта)

---

## Business plan (B2B) — другая модель

### Pricing
- $3.99/user/mo (T2) × regional tier
- Minimum: 1 seat (vs KnowBe4's 25)
- Volume discount: 100+ seats = -10%, 500+ = -20%
- Annual только (monthly тоже доступен но дороже)

### Features разблокируется с B2B (дополнительно к Personal/Family)
- Email proxy (SMTP scan before inbox)
- Org dashboard (aggregate stats, не per-user browsing)
- Phishing simulation (templates, campaigns)
- SSO (SAML / OIDC)
- SCIM provisioning
- API access
- Priority support SLA

### Billing
- Invoice billing для annual (Stripe invoicing)
- Credit card для monthly
- No credit card for demo/trial (14 days free)

---

## Free trials

### Personal/Family free trial
- 14 days full Personal access (все фичи)
- Нет кредитки upfront
- После trial → auto downgrade на Free (не на Personal с билом)
- Только 1 раз per user (anti-abuse)

### Business trial
- 14 days free для up to 10 seats
- Demo call с founder/SDR (для серьёзных SMB)

---

## Refunds / Cancellation

- Monthly: cancel anytime, active до конца billing period
- Yearly: 30-day money-back guarantee (полный refund), после 30 дней prorated refund при cancel
- Business: per contract terms

Через Stripe Customer Portal — не нужно писать саппорту.

---

## Analytics / Metrics to track

- Conversion rate по tier (T4 ожидается выше absolute users, ниже ARPU)
- Threshold hit → payment funnel (% юзеров которые дошли до 50 → % из них заплатили)
- Churn по tier, по plan
- Granny Mode adoption (сколько paid юзеров включили его)
- Family invite ratio (сколько членов добавил Family юзер)

Tracking через PostHog или Plausible (privacy-first analytics, в духе нашего бренда).
