# Cleanway — User Checklist

> Скажи "сделал 1, 2, 5" → я обновляю `[ ]` → `[x]`. Не задавай мне вопросов которые есть в [`USER_PLAYBOOK.md`](USER_PLAYBOOK.md) — там click-by-click.

---

## 🔴 TODAY (~1 час, выполнять В ПОРЯДКЕ)

- [ ] **1. DNS CNAME `dns.cleanway.ai` → `api.cleanway.ai` (proxy OFF)** · Cloudflare → cleanway.ai zone → DNS → Add record · 5 мин · check: `curl -v --doh-url https://dns.cleanway.ai/dns-query https://example.com` returns DNS answer
- [ ] **2. Calendar event: Fri 2026-07-03 14:00-18:00 "Chrome Web Store submit"** · Calendar app · 1 мин · block все другие звонки
- [ ] **3. Calendar event: All-day 2026-09-27 "Cleanway 90-day go/no-go decision"** · Calendar app · 1 мин · threshold table в [USER_PLAYBOOK.md](USER_PLAYBOOK.md) пункт 90-DAY GATE
- [ ] **4. Rotate Anthropic API key + update Railway env** · console.anthropic.com/settings/keys → Railway dashboard → Variables → ANTHROPIC_API_KEY · 5 мин · check: POST `/api/v1/explain` returns `"source": "llm"`
- [ ] **5. GitHub secret: SUPABASE_URL** · github.com/AlexMos555/linkshield/settings/secrets/actions → New repo secret · 3 мин · value из Supabase → Project Settings → API → Project URL
- [ ] **6. GitHub secret: SUPABASE_SERVICE_KEY** · Same page · 3 мин · value из Supabase → API → `service_role` (НЕ anon)
- [ ] **7. GitHub secret: GOOGLE_SAFE_BROWSING_KEY** · Same page · 5 мин · Google Cloud Console → APIs & Services → Credentials → restrict to "Safe Browsing API v4"
- [ ] **8. GitHub secret: VT_API_KEY** · Same page · 2 мин · https://www.virustotal.com/gui/my-apikey (free, 500 req/day)
- [ ] **9. GitHub secret: PHISHTANK_API_KEY** · Same page · 2 мин · https://www.phishtank.com/api_info.php
- [ ] **10. Railway tokens: RAILWAY_TOKEN_PRODUCTION + RAILWAY_TOKEN_STAGING** · Railway → Account Settings → Tokens → Create New Token · 5 мин · paste в GH secrets с теми же именами
- [ ] **11. Railway service IDs + health URLs (4 secrets)** · Same Railway settings · 5 мин · `RAILWAY_SERVICE_PRODUCTION`, `RAILWAY_SERVICE_STAGING`, `PROD_HEALTH_URL=https://api.cleanway.ai/health`, `STAGING_HEALTH_URL=https://<staging>/health`
- [ ] **12. Test DNS на real iPhone** · Safari → cleanway.ai/dns → download .mobileconfig → install · 15 мин · phishing URL из urlhaus.abuse.ch/browse/ blocked, google.com работает
- [ ] **13. Twitter handle `@cleanwayai` — claim ИЛИ remove refs** · twitter.com/cleanwayai · 10 мин · если занят — grep "cleanwayai" landing/ + удалить из layout/page.tsx files

---

## 🟡 ЭТА НЕДЕЛЯ (по дням)

### Среда (~30 мин)
- [ ] **14. Microsoft Founders Hub signup** · https://foundershub.startups.microsoft.com/signup · 15 мин · approval timeline 2 недели; даёт $150K Azure + $500K OpenAI/Anthropic credits
- [ ] **15. Browser walkthrough cleanway.ai в Chrome incognito** · все 10 locale, /pricing toggle, /check/google.com, /transparency/methodology /ru /es /de, /dns, /family · 20 мин · note bugs в `docs/walkthrough-notes.md`

### Четверг (~1.5 часа)
- [ ] **16. AV-Comparatives Q3 submit** · email `sales@av-comparatives.org` · 1 час · Subject "Cleanway Anti-Phishing Engine — Submission for Q3 2026 Anti-Phishing Test"; **подтверди €4-8K budget ДО email**; realistic timeline: badge live end of Q4 2026
- [ ] **17. Mobile horizontal-overflow E2E локально** · cd landing && npx playwright test e2e/mobile.spec.ts --project=mobile-safari · 30 мин · если passes — убери `.skip` и закоммить; если fails — note в issue

### Пятница 2026-07-03, 14:00-18:00 (~45 мин)
- [ ] **18. 🎯 Chrome Web Store submission** · chrome.google.com/webstore/devconsole · 45 мин · buy $5 dev account → upload `dist/store-artifacts/cleanway-extension.zip` → copy-paste из `docs/marketing/chrome-web-store-listing.md` → 5 screenshots @ 1280×800 → submit · status = "In review" by EOD

---

## 🟢 НЕДЕЛЯ 2 (после CWS approval, ~3-4 часа)

- [ ] **19. n=3 grandparent usability study — пользователь #1** · live или Zoom screen share · 1 час · install extension → дай задачу "найди phishing в email" → молчи и записывай где застревают
- [ ] **20. n=3 grandparent usability study — пользователь #2** · разный день · 1 час · same protocol
- [ ] **21. n=3 grandparent usability study — пользователь #3** · разный день · 1 час · same; затем классифицируй каждый bug: ship-block / major / minor → пиши мне results
- [ ] **22. Cold-email Bitdefender BD/Partnerships** · LinkedIn search "Bitdefender business development" → name → firstname.lastname@bitdefender.com · 10 мин · использовать `docs/marketing/press-pitch.md` template
- [ ] **23. Cold-email NordSecurity partnerships** · nordsecurity.com/about → найти BD person · 10 мин · same template
- [ ] **24. Submit 1Password partner application** · 1password.com/partners · 10 мин · форма

---

## 🟢 НЕДЕЛЯ 3 (~1 час твоего времени)

- [ ] **25. OSS decision #1: License (MIT vs Apache 2.0 vs BSL)** · Read [`docs/OPEN-SOURCE.md`](OPEN-SOURCE.md) section "License recommendation" · 5 мин · default: MIT
- [ ] **26. OSS decision #2: Repo brand (`cleanway-engine` vs `cleanway-ai/engine`)** · same doc · 5 мин · default: `cleanway-ai/engine` org
- [ ] **27. OSS decision #3: GitHub org (existing AlexMos555 vs new `cleanway-ai` org)** · github.com/organizations/new если new · 15 мин
- [ ] **28. Read finalized Show HN post + approve OR edit** · `docs/marketing/show-hn-post.md` · 20 мин · I will update it with the real benchmark numbers first
- [ ] **29. Book Show HN slot: Tuesday 9 AM PT** · news.ycombinator.com/submit · 1 мин · verify HN account ≥30 days old

---

## 🔵 НЕДЕЛЯ 4 — Conditional (только если CWS approved + Show HN landed)

- [ ] **30. Install Cleanway в primary Chrome (НЕ test profile)** · извлеки из CWS → install → use neделю · 0 мин/день · constant observation: note misses/false-positives в `docs/user-journey-notes.md`
- [ ] **31. Set up customer support email forwarding** · Gmail → forward `hello@cleanway.ai` + `support@cleanway.ai` → primary inbox · 15 мин · Filter "from CWS reviewer → label cws-review"

---

## 🎯 90-DAY GATE — 2026-09-27

Календарное событие из пункта 3. Готовь к нему данные:

| Metric | "continue" | "pivot" | "honest exit" |
|---|---|---|---|
| CWS installs | ≥5,000 | 1,000-5,000 | <1,000 |
| Weekly active users | ≥500 | 100-500 | <100 |
| Acquirer replies | ≥1/5 emails | =1/10 | 0/15 |
| Show HN | ≥200 upvotes | 50-200 | <50 |
| Paying customers | ≥10 | 1-10 | 0 |

3 pre-committed paths:
- ≥3 metrics "continue" → focus paid + acquirer outreach next 90 days
- mostly "pivot" → full OSS release, drop paid, portfolio piece + GitHub Sponsors
- mostly "honest exit" → archive repo, retrospective post, walk away. NO zombie maintenance

---

## ❌ Kill list — что НЕ делать эти 4 недели

- ❌ Новые detection strategies (Top-20 + #21 closed)
- ❌ Paid ads до того как analytics покажет funnel
- ❌ SOC 2 / GDPR audit (wrong audience для exit-track)
- ❌ Aggressive monetization до launch
- ❌ "Ещё одна фича до push" (distribution bottleneck не фиксится через ML)
- ❌ Отвечать с эмоцией на негативные HN comments
- ❌ Игнорить 90-day gate

---

**Прогресс: 0/31 done**
