# Cleanway — User Action Playbook

> Что **ты** делаешь руками. В порядке выполнения. Замещает `docs/PLAYBOOK_TONIGHT.md` (был фрагментарный).
>
> 25 items в [`docs/IMPROVEMENT_ROADMAP_2026-06-29.md`](IMPROVEMENT_ROADMAP_2026-06-29.md) — это полная картина. Этот файл — только твоя часть, обрезано до imperative + concrete.

---

## ⚡ TODAY (~1 час всего)

Эти 6 пунктов разблокируют всё остальное. Делай в порядке списка — каждый блокирует следующие.

### 1. DNS CNAME `dns.cleanway.ai` → `api.cleanway.ai`
- **Где:** Cloudflare dashboard → cleanway.ai zone → DNS records → Add record
- **Что:** Type `CNAME`, Name `dns`, Target `api.cleanway.ai`, **Proxy status OFF (серое облако)** — apex/api остаются proxied, dns subdomain — нет
- **Сколько:** 5 минут
- **Проверка:** `curl -v --doh-url https://dns.cleanway.ai/dns-query https://example.com` возвращает DNS answer
- **Зачем:** Strategy #6 (iOS `.mobileconfig` one-tap DoH install) — сейчас profiles устанавливаются, но resolve в NXDOMAIN. Это бьёт "system-wide phishing block без приложения" claim в проде.

### 2. Ротация Anthropic API key
- **Где:** https://console.anthropic.com/settings/keys
- **Что:**
  1. Revoke current key (он светился в transcript дважды — compromised)
  2. Create new key (Name: "Cleanway Prod 2026-06-29")
  3. Открой Railway → web service → Variables → найди `ANTHROPIC_API_KEY` → Edit → вставь новый key → Save
  4. Railway автоматически редеплоит (~3 мин)
- **Сколько:** 5 минут
- **Проверка:** `curl -X POST https://api.cleanway.ai/api/v1/explain -H 'content-type: application/json' -d '{"signals":["paypal_brand","credential_form_mismatch"],"locale":"en"}'` → response содержит `"source": "llm"`
- **Зачем:** Strategy #21 (LLM Judge) + #15 (Cultural Explainer). Без actual ключа Anthropic фичи silently fall back на template. Старый key compromised по security hygiene.

### 3. 5 GitHub Actions secrets
- **Где:** https://github.com/AlexMos555/linkshield/settings/secrets/actions → New repository secret
- **Что добавить:**

| Secret name | Где взять value | Зачем |
|---|---|---|
| `SUPABASE_URL` | Supabase dashboard → Project Settings → API → Project URL | Watchtower cron (Strategy #17) сейчас падает каждый scheduled run |
| `SUPABASE_SERVICE_KEY` | Supabase → Project Settings → API → `service_role` key (НЕ anon) | Watchtower writes the typosquat detection table |
| `GOOGLE_SAFE_BROWSING_KEY` | Google Cloud Console → APIs & Services → Credentials → API key (Restrict to Safe Browsing v4) | Weekly benchmark side-by-side comparison |
| `VT_API_KEY` | https://www.virustotal.com/gui/my-apikey (free, 500 req/day) | Same benchmark — VirusTotal aggregate (70 vendors) |
| `PHISHTANK_API_KEY` | https://www.phishtank.com/api_info.php (free) | Same benchmark — PhishTank column |

- **Сколько:** 15 минут (медленная часть — fetch каждого ключа из его консоли)
- **Проверка:** `gh secret list` показывает все 5
- **Зачем:** 2 криптикal (Watchtower умирает каждый tick без Supabase keys) + 3 high (credibility benchmark не публикует head-to-head без сравнительных ключей)

### 4. Railway deploy tokens (4 secrets)
- **Где:** Railway → Account Settings → Tokens → Create New Token
- **Что добавить в те же GitHub secrets:**

| Secret name | Source |
|---|---|
| `RAILWAY_TOKEN_STAGING` | Create token labeled "GitHub Actions — staging" |
| `RAILWAY_TOKEN_PRODUCTION` | Create token labeled "GitHub Actions — production" |
| `RAILWAY_SERVICE_STAGING` | Railway → Settings → service ID for staging environment |
| `RAILWAY_SERVICE_PRODUCTION` | Railway → service ID for production |
| `STAGING_HEALTH_URL` | `https://<staging-domain>/health` |
| `PROD_HEALTH_URL` | `https://api.cleanway.ai/health` |

- **Сколько:** 10 минут
- **Проверка:** Push на main → `.github/workflows/deploy-production.yml` запускается без "secret missing" errors
- **Зачем:** Без этого каждый push требует manual Railway deploy. До распределения это нормально, но при launch неудобно.

### 5. Тест DNS на real iPhone
- **Где:** Real iPhone (не симулятор)
- **Что:**
  1. Открой Safari → перейди на https://cleanway.ai/dns
  2. Скачай `.mobileconfig` profile
  3. Settings → "Profile Downloaded" → Install (потребует passcode)
  4. Открой Safari incognito tab → вставь любой URL из URLhaus (https://urlhaus.abuse.ch/browse/) — он должен failed с NXDOMAIN или resolution-blocked
- **Сколько:** 15 минут
- **Проверка:** Phishing URL не открывается, любой нормальный сайт (google.com) работает нормально
- **Зачем:** Прежде чем кричать "system-wide phishing protection without an app" в маркетинге — убедись что реально работает на твоём собственном телефоне

### 6. Twitter handle `@cleanwayai` — claim или удали
- **Где:** https://twitter.com/cleanwayai
- **Что:**
  - **Если свободен и хочешь его:** зарегистрируй сейчас (бесплатно, 5 мин), upload avatar + banner
  - **Если уже занят кем-то другим ИЛИ не хочешь:** удали ссылки на него
    - `landing/app/[locale]/layout.tsx` → `twitter.site: "@cleanwayai"` → удалить
    - `landing/app/[locale]/page.tsx` → `twitter.site: "@cleanwayai"` → удалить
    - 8 других page.tsx файлов (pricing/business/terms/privacy-policy/audit/check/transparency/dns) — grep + удалить
- **Сколько:** 10 минут
- **Проверка:** Либо @cleanwayai в твоём ownership, либо `grep -rn cleanwayai landing/` возвращает 0 hits
- **Зачем:** Today Twitter cards не enrich (handle resolves в никуда или к чужому аккаунту), schema.org `sameAs` claim врёт

---

## 🗓️ THIS WEEK (~3-4 часа всего)

### 7. Заблокировать дату CWS submission в календаре
- **Когда:** Прямо сейчас, чтобы не сорвалось
- **Что:** Создай событие в Calendar: "**Cleanway Chrome Web Store submit**", Friday 2026-07-03, 14:00-18:00
- **Сколько:** 1 минута (само событие); 45 мин на самом event дне
- **Зачем:** CWS review takes 1-7 days. Если submit Friday — листинг может быть live к Понедельнику = идеальный launch timing для Show HN.

### 8. Календарное напоминание про 90-day exit gate
- **Когда:** Сейчас
- **Что:** Создай all-day event 2026-09-27: "**Cleanway 90-day go/no-go decision**". В описании:
  - Если MAU ≥ 5,000 + хотя бы одна serious acquihire conversation → close that deal
  - Если MAU ≥ 1,000 но без acquihire → pivot to lifestyle / open-source release / continue solo
  - Если MAU < 1,000 → honest exit, archive project, move on. Без zombie maintenance.
- **Сколько:** 5 минут
- **Зачем:** Solo-проект без deadline становится infinite loop. Без жёсткого gate exit-цель не приближается.

### 9. AV-Comparatives Q3 submission
- **Когда:** Эта неделя, в рабочее время
- **Что:**
  1. Confirm бюджет €4,000-8,000 (Q3 anti-phishing test fee)
  2. Email: `sales@av-comparatives.org`
  3. Subject: "Cleanway Anti-Phishing Engine — Submission for Q3 2026 Anti-Phishing Test"
  4. Body: ссылка на cleanway.ai/transparency/methodology + describe testing endpoint
- **Сколько:** 1 час (включая research + написание email)
- **Realistic timeline:** Lab ack 5-7 дней. Test cycle Q3 (June-Sep). **Badge live end of Q4 2026** when the cycle report publishes — НЕ 8 weeks как я ранее сказал
- **Зачем:** Independent 3rd-party certification на 275-URL externally curated test. Это **единственный** способ объективно валидировать наш recall claim. Без AV-Comparatives badge "93.5% measured" остаётся self-claimed.

### 10. Microsoft Founders Hub signup
- **Где:** https://foundershub.startups.microsoft.com/signup
- **Что:** 15-минутная форма (название, кол-во людей, описание, GitHub link)
- **Сколько:** 15 минут
- **Approval timeline:** 2 недели
- **Зачем:** $150K Azure credits, $500K OpenAI/Anthropic credits, $1K LinkedIn Ads. Free tier — лучшее что есть для соло перед паблик launch. **НЕ обещай AppSource featured placement** в этой заявке — это отдельный multi-month Co-Sell track который требует customer testimonials которых у нас нет.

### 11. Browser walkthrough cleanway.ai
- **Когда:** Любой день этой недели, 20 мин одним блоком
- **Что:**
  1. Chrome incognito → https://cleanway.ai/
  2. Кликни через **все 10 locale switches** в footer — посмотри что переведено корректно
  3. /pricing → переключи on/off monthly/yearly toggle → check что цены отображаются
  4. /check/google.com → должен открыться (если 404 — пиши мне)
  5. /transparency/methodology → /ru, /es, /de — должны быть на нативном языке
  6. /dns → проверь что инструкции для iOS/Android актуальны
  7. /family — есть ли вообще эта страница? Если нет, пометь как gap
  8. Mobile view: открой DevTools → toggle device toolbar → iPhone 14 → пройди тот же flow
- **Что искать:** untranslated strings показывающиеся как English на /de или /ru, layout breaks на mobile, дохлые ссылки, ошибки в console
- **Сколько:** 20 минут
- **Зачем:** Скрипты CI ловят синтаксис, не UX. Реальный glance — единственный способ найти "ой я не заметил".

### 12. Mobile horizontal-overflow E2E локально
- **Когда:** Эта неделя
- **Что:**
  ```bash
  cd /Users/aleksandrmoskotin/Desktop/LinkShield/LinkShield/landing
  npm install
  npx playwright install webkit
  # Открой landing/e2e/mobile.spec.ts — найди test.skip("mobile viewport does not horizontally scroll")
  # Замени test.skip на test (убери .skip)
  npx playwright test e2e/mobile.spec.ts --project=mobile-safari
  ```
- **Если passes:** оставь без `.skip`, закоммить
- **Если fails:** revert на `.skip`, опиши в issue какой именно элемент overflow-ит
- **Сколько:** 30 минут (если first run — playwright installs WebKit ~5 мин)
- **Зачем:** CSS guards я добавил, но без реального WebKit run не подтверждено. Сейчас тест skipped → реальный bug может скрываться.

### 13. **🎯 FRIDAY 2026-07-03: Chrome Web Store submission**
- **Когда:** Запланированный слот 14:00-18:00 этой пятницы
- **Что:**
  1. https://chrome.google.com/webstore/devconsole/ — buy developer account ($5 one-time)
  2. New item → upload `dist/store-artifacts/cleanway-extension.zip`
  3. Open `docs/marketing/chrome-web-store-listing.md` → copy-paste:
     - Extension name (45 chars)
     - Short description (132 chars)
     - Detailed description (470 words)
     - 5 highlight bullets
     - Permission justifications
  4. Upload 5 screenshots @ 1280×800 (если ещё нет — сделай: install extension в своём Chrome, screenshot popup + warning + per-link badge in Gmail + methodology page + family hub)
  5. Submit for review
- **Сколько:** 45 минут (most of it — filling listing copy)
- **Review SLA:** 1-7 days
- **Зачем:** **Без CWS listing live никакой Show HN smysl** — install link ведёт в никуда. Это THE distribution unblock.

---

## 🗓️ WEEK 2 (~2 часа твоего времени)

### 14. n=3 grandparent usability study
- **Когда:** Week 2, после того как CWS approved (~Mon 2026-07-06)
- **Что:**
  1. Найди 3 пользователей: parents/grandparents/teens — кто-то у кого ты можешь сесть в комнате и **молча наблюдать** (или Zoom screen share)
  2. Install extension. Дай задачу: "Открой email, найди ссылку на phishing"
  3. **Не подсказывай.** Записывай где они застревают
  4. Классифицируй каждый bug: `ship-block` / `major` / `minor`
- **Сколько:** 1 час каждый × 3 человека = 3 часа твоего времени (планируй на разные дни)
- **Зачем:** **Это THE critical missing data point.** Сейчас нулевая обратная связь от реальных пользователей. Без неё мы guess-им что хорошо.

### 15. Cold-emails: Bitdefender / NordSecurity / 1Password
- **Когда:** Week 2 (после того как CWS approved → есть proof-of-product)
- **Что:** Используй `docs/marketing/press-pitch.md` как шаблон, но **target BD/partnerships, не CEO**. Конкретные люди:
  - **Bitdefender:** LinkedIn search "Bitdefender business development manager" — найди 1-2 имени. Email format: `firstname.lastname@bitdefender.com`
  - **NordSecurity:** Same approach. NordSecurity team page: https://nordsecurity.com/about
  - **1Password partner program:** https://1password.com/partners — есть форма
- **Сколько:** 30 минут (3 emails)
- **Realistic expectation:** ≥1 substantive reply в 21 день
- **Зачем:** Без personal-touch outreach acquihire conversation не стартует. Forms не работают.

---

## 🗓️ WEEK 3 (~1 час твоего времени, я делаю остальное)

### 16. Approve open-source repo split
- **Что:** Я подготовлю git filter-repo script по [`docs/OPEN-SOURCE.md`](OPEN-SOURCE.md) plan. Тебе нужно:
  1. Решить три open questions в `docs/OPEN-SOURCE.md`: MIT vs Apache 2.0, brand name (cleanway-engine или cleanway-ai/engine), GitHub org (existing AlexMos555 или new cleanway-ai org)
  2. Если new org нужен — создать его на github.com/organizations/new
- **Сколько:** 30 минут
- **Зачем:** Show HN post (Week 3) опирается на live OSS repo. Без принятых решений я не могу скриптовать split.

### 17. Show HN — твоё approval + timing
- **Что:** Я финализирую `docs/marketing/show-hn-post.md` после re-run benchmark (живые числа). Тебе нужно:
  - Прочитать пост целиком, написать "approved" ИЛИ предложить правки
  - Booking слот на Tuesday 9 AM PT (most engaging HN slot)
  - Иметь HN account ≥30 days old (если новый — engagement collapse risk)
- **Сколько:** 30 минут
- **Зачем:** Show HN — самый высокий ceiling на distribution per hour spent у соло-разработчика.

---

## 🗓️ WEEK 4 — Conditional

**Только если** CWS approved + Show HN landed + ≥100 installs к этому моменту.

### 18. Eat your own dog food
- **Что:** Install Cleanway в своём primary Chrome (НЕ test profile). Используй его неделю. **Каждый раз когда срабатывает warning** — note это в `docs/user-journey-notes.md`. Каждый раз когда **должен был сработать но не сработал** — note это тоже.
- **Сколько:** 0 минут запланированно, но constant background observation
- **Зачем:** Founder-grade dogfooding. Если ТЫ не можешь использовать продукт ежедневно, как ожидать что бабушка сможет.

### 19. Set up customer support email
- **Что:** Forward `hello@cleanway.ai` → твой primary email + `support@cleanway.ai` → same. Создай Gmail filter "from CWS reviewer → label: cws-review".
- **Сколько:** 15 минут
- **Зачем:** Первые launch responses требуют немедленной реакции.

---

## 🎯 90-DAY DECISION GATE — 2026-09-27

Календарное событие из пункта 8. Готовь к нему данные:

| Metric | Threshold for "continue" | Threshold for "pivot" | Threshold for "honest exit" |
|---|---|---|---|
| Chrome Web Store installs | ≥5,000 | 1,000-5,000 | <1,000 |
| Weekly active users (extension) | ≥500 | 100-500 | <100 |
| Acquirer responses to outreach | ≥1 substantive reply / 5 emails | =1 / 10 emails | 0 / 15 emails |
| Show HN traction | ≥200 upvotes OR press pickup | 50-200 upvotes | <50 upvotes |
| Paying customers | ≥10 | 1-10 | 0 |

Три pre-committed paths:
1. **Continue (≥3 metrics in "continue" band):** focus on paid conversion + acquirer outreach for next 90 days
2. **Pivot (mostly "pivot" band):** open-source full release, drop paid surfaces, position as portfolio piece + maintainer income via GitHub Sponsors
3. **Honest exit (mostly "honest exit" band):** archive repo, write retrospective post, walk away with code as resume. NO zombie maintenance — это самый дорогой anti-pattern для соло.

---

## ⚠️ Things to NOT do (kill list)

Из roadmap'а explicit — exclude these в ближайшие 4 недели:

- ❌ **Не строить новые detection strategies.** Top-20 + #21 closed. Каждая новая = +X недель maintenance, 0 movement к exit
- ❌ **Не запускать paid ads** до того как analytics покажет funnel
- ❌ **Не делать SOC 2 / GDPR audit** — wrong audience для нашего exit-track
- ❌ **Не пытаться монетизировать агрессивно** до launch — high conversion rate труднее подделать, и acquirers оценивают MAU/engagement, не MRR на этом масштабе
- ❌ **Не "ещё одну фичу до push"** — distribution bottleneck НЕ закрывается через ML улучшения
- ❌ **Не отвечать negative HN commenters** с эмоцией. Calm, specific, link-to-evidence
- ❌ **Не игнорировать 90-day gate** — без deadline продукт зомбифицируется

---

## TLDR — что сделать прямо сейчас (10 минут)

1. **Открой Cloudflare** → добавь `dns` CNAME → `api.cleanway.ai` (proxy OFF). 5 мин.
2. **Открой Calendar** → создай 2 события:
   - Friday 2026-07-03 14:00-18:00: "Chrome Web Store submit"
   - All-day 2026-09-27: "90-day go/no-go decision"
3. **Открой Anthropic Console** → revoke old key → create new → update Railway env var. 5 мин.

Остальное — на этой неделе (~3-4 часа total).
