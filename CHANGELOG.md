# Changelog

## [Unreleased]

### Security
- **Stripe open redirect** — `CheckoutRequest.success_url` / `cancel_url` now allowlist-validated against `cleanway.ai` apex/www. Attackers can no longer pipe Stripe checkout through attacker-controlled landing URLs.
- **Extension host permissions** — Dropped `http://localhost:8000/*` from production manifests (Chrome/Firefox/Safari). Published extensions no longer leak auth to any local service on port 8000.
- **Subscriptions RLS** — Documented intentional default-deny on `subscriptions` writes; all writes go through service_role on the backend.

### Changed
- **Rebrand** — Full migration from LinkShield to Cleanway (cleanway.ai). Infrastructure, extensions, landing, mobile, i18n, and CORS all updated.
- **API host** — Backend URL migrated from Railway to `api.cleanway.ai` across all platform targets (20+ files).
- **Sentry** — Added env-gated Sentry DSN integration for landing (Next.js) and mobile (Expo).

### Fixed
- **Mobile Safari** — Horizontal scroll regression on landing page (`fd99a9e`).
- **Supabase RLS** — Enabled RLS on `families` / `orgs` / `org_members` tables; pinned `search_path` on `get_pricing_tier` and `report_phone` functions.

### Removed
- **Dead i18n** — `welcome_step_label` (`extension.welcome.step_label`) from `packages/i18n-strings/src/` and 50 generated locale files.
- **Unused import** — `get_current_user` from `api/routers/email.py`.

### Tests
- 382 backend tests passing (was 373). Added 9 parameterized tests for `CheckoutRequest` URL validation.

## [App 1.0.5] - unreleased

iOS build 4, Android versionCode 106. Ships after 1.0.4 clears App Review.

On Android 1.0.5 is the first release since 1.0.3 (Android 1.0.4 was built but
never published), so it also carries the Android 1.0.4 changes below. Android
files, one per store ([docs/RUSTORE_SUBMISSION.md](docs/RUSTORE_SUBMISSION.md) §2):
`cleanway-1.0.5-106-arm.apk` (site, GitHub release `v1.0.5`),
`cleanway-1.0.5-106-rustore.apk` (RuStore), `cleanway-1.0.5-106-play.aab`
(Google Play).

**Что нового**
- **Приложение больше не «забывает» данные после сна.** Если система закрыла базу на устройстве, приложение открывает её заново, а неудачное чтение больше не считается первым запуском (#184).
- **iOS 26: обновлены шаги включения фильтра SMS** (#187).
- **Android: ссылки открываются только для проверенного адреса, журнал блокировок не попадает в резервную копию**, защита от зацикливания проверки ссылок (#201).
- **Код входа из 6–8 цифр** принимается; вставка всей фразы из письма даёт сам код (#213).
- **Готовность к капче при входе.** Проверка «я не робот» появится, только если сервер её потребует; пока капча выключена, ничего не меняется (#214).
- **Готовность к новому ключу Supabase** (publishable вместо anon JWT) (#215).
- **Доступность.** У всех кнопок есть роли и подписи для VoiceOver и TalkBack; вердикт проверки и загрузка озвучиваются; онбординг говорит «Шаг N из 3». Контраст текста и кнопок — не ниже AA, области нажатия не меньше 44 pt, крупный шрифт больше не обрезается, при «Уменьшить движение» кольцо оценки и окно защиты от звонков не анимируются (#249).
- **Политика конфиденциальности в приложении** перечисляет обработчиков данных после переезда инфраструктуры (#228); для сайтов на динамических DNS результат проверки показывает понятную причину (#224).
- **Android: экран подписки перечисляет только то, что даёт подписка** — без «Автоматической проверки SMS» (её нет ни в одной сборке) и «Защиты во время звонков» (она бесплатна для всех).
- **iOS, не в build 4 (нужна следующая iOS-сборка):** проверка «я не робот» при входе открывается в окне внутри приложения (ASWebAuthenticationSession), а не в Safari; запрос доступа к камере для QR-кодов — на языке телефона.

**What's new**
- Reopens a closed on-device database instead of losing data; a failed read is never treated as a first run (#184).
- SMS-filter setup steps updated for iOS 26 (#187).
- Android: deep links open only for the checked host, block log excluded from backups, link-guard loop brake (#201).
- Sign-in codes of 6–8 digits accepted; pasting the email's sentence yields the code (#213).
- Captcha-ready sign-in: the Turnstile check appears only if Supabase asks for it (#214).
- Supabase publishable-key ready (`*_SUPABASE_PUBLISHABLE_KEY` preferred over the anon JWT) (#215).
- Accessibility: roles and labels on every touchable for VoiceOver and TalkBack; verdicts and loading states are announced; onboarding says "Step N of 3". Text and button contrast meets AA, touch targets are at least 44 pt, large text is no longer clipped, and Reduce Motion stops the score-ring and call-guard animations (#249).
- In-app privacy policy lists the subprocessors after the infrastructure move (#228); sites on dynamic DNS get a plain-language reason in the check result (#224).
- Android: the paywall lists only what the subscription adds — no "Automatic SMS check" (no build has it) and no "Protection during phone calls" (free for everyone).
- iOS, not in build 4 (needs the next iOS build): the on-demand sign-in captcha opens in an in-app sheet (ASWebAuthenticationSession) instead of switching to Safari; the camera prompt for QR codes is in the phone's language.

Enablement order for the server-side switches: [docs/MOBILE_AUTH.md](docs/MOBILE_AUTH.md).

## [Extension 0.2.2] - 2026-10-22

Browser extension for Chrome, Edge, Opera, Firefox and Safari. 0.2.1 never reached the stores; 0.2.2 replaces it in the submission. Permissions are the same as in 0.2.1.

**Что нового**
- **Firefox: окно Cleanway, настройки и страница предупреждения работают.** В Firefox окно по значку застревало на «Проверяю страницу…», а настройки не загружались.
- **Проверка пароля на утечки заработала** в Chrome, Edge и Opera (и, вероятно, в Safari). Браузер отбрасывал ответ сервера, и предупреждение «этот пароль есть в утечках» не появлялось. Теперь запрос отправляет само расширение, без адреса сайта, на котором вы находитесь. Как и раньше, уходят только первые 5 символов хеша пароля.
- **Меньше ложных предупреждений на настоящих страницах входа.** Расширение снова узнаёт настоящие сайты входа банков и сервисов: список с сервера до него не доходил.
- **Проверка ссылок больше не останавливается.** Раньше после нескольких страниц со ссылками сервер переставал отвечать, и на час оставалась только встроенная защита. Теперь расширение отправляет с проверками случайный номер установки (новый каждые 24 часа), и сервер считает лимит для вашего браузера, а не для всех с вашим IP-адресом. Если лимит всё же исчерпан, расширение ждёт столько, сколько просит сервер, и всё равно проверяет страницу, которую вы открыли. Проверки идут по несколько сразу, а ответы не теряются, когда браузер перезапускает расширение.
- **Число на значке — для текущей вкладки** и сбрасывается при переходе на другую страницу, но не тогда, когда страница сама меняет адрес, как YouTube или X. Раньше красная цифра с одной страницы оставалась на всех вкладках.
- **«Сообщить об ошибке» передаёт, в чём ошибка.** Если мы назвали сайт опасным, а вы считаете его безопасным, так и уходит; раньше любое сообщение считалось «пропущенным мошенническим сайтом». На странице предупреждения сообщение относится к заблокированному сайту.
- **Быстрее на больших страницах.** Защита от поддельных окон входа («браузер в браузере») больше не перечитывает весь текст страницы при каждом изменении; на длинных лентах это было заметно.

**What's new**
- **Firefox: the popup, Settings and the warning page work.** In Firefox the popup was stuck on "Checking this page…" and Settings did not load.
- **The password-leak check works** in Chrome, Edge and Opera (and likely Safari). The browser threw away the server's answer, so "this password is in known leaks" never appeared. The extension itself now makes the request, without the address of the site you are on. As before, only the first 5 characters of the password's hash are sent.
- **Fewer false warnings on real sign-in pages.** The extension again learns banks' and services' real sign-in sites: the server's list never reached it.
- **Link checks no longer stop.** After a few link-heavy pages the server used to refuse checks, and for an hour only the built-in protection was left. Now the extension sends a random install number with its checks (a new one every 24 hours), and the server counts the limit for your browser, not for everyone on your IP address. If the limit is reached anyway, the extension waits as long as the server asks and still checks the page you open. Checks run a few at a time, and answers survive the browser restarting the extension.
- **The number on the toolbar icon is for the current tab** and clears when you go to another page, but not when a page changes its own address, as YouTube or X do. A red number from one page used to stay on every tab.
- **"Report wrong result" says which way we were wrong.** If we called a site dangerous and you think it is safe, that is what is sent; before, every report counted as "a scam you missed". On the warning page the report is about the blocked site.
- **Faster on big pages.** The fake sign-in window ("browser in the browser") protection no longer rereads all the page's text on every change, which showed on long feeds.

Server side, same release: the API counts 600 public checks an hour per install number (it was 60; still 60 an hour per IP address without one, and still 5 fresh analyses a minute) and answers a 429 with `Retry-After`. The per-IP ceiling over all install numbers grew with it, from 1,500 to 15,000 checks an hour, so a few browsers behind a carrier's NAT cannot use it up for every phone there; fresh analyses keep their own per-IP ceilings of 60 a minute and 1,500 an hour.

## [Extension 0.2.1] - 2026-10-21

Browser extension for Chrome, Edge, Opera, Firefox and Safari. The first version for the stores: 0.2.0 was built but never submitted. Permissions are the same as in 0.2.0.

**Что нового**
- **Предупреждение об опасном сайте — теперь отдельная страница расширения.** Раньше красный экран «СТОП» рисовался внутри самой мошеннической страницы, и она могла его убрать. Теперь вкладка переходит на страницу Cleanway, до которой сайт не может дотянуться. «Назад» возвращает туда, откуда вы пришли; «Всё равно открыть» пускает на этот сайт в этой вкладке на час, а форма пароля на нём остаётся под строгим присмотром.
- **Окно Cleanway (по нажатию на значок) на странице предупреждения пишет «Это мошеннический сайт»**, а не «Эта страница безопасна», и предлагает закрыть вкладку.
- **Ключ входа надёжнее спрятан.** Короткоживущий ключ входа хранится в памяти браузера, которую не видят скрипты на страницах, и стирается при закрытии браузера; войти заново не придётся — расширение само обновит вход при запуске.
- **Расширение говорит только с сервером Cleanway.** Адрес сервера нельзя подменить на чужой.
- **Ловит больше мошеннических сайтов на бесплатных хостингах** (например, `gmail-support.netlify.app`, `facebook-login0.vercel.app`) и на сервисах бесплатных доменов вроде duckdns.org.
- **Убран неиспользуемый код**, который узнавал почтовые сайты по части адреса (его обманул бы адрес вроде `mail.google.com.evil.example`); на защиту он не влиял.
- **Генератор QR-кода в настройках — официальный файл библиотеки** qrcode-generator 1.4.4 без минификации, байт в байт как в npm-пакете, чтобы проверяющие магазинов могли сверить его с релизом. QR-код выглядит как раньше.

**What's new**
- **The dangerous-site warning is now the extension's own page.** The red STOP screen used to be drawn inside the scam page itself, which could remove it. Now the tab moves to a Cleanway page the site cannot reach. "Go back" returns you to where you came from; "Open anyway" lets you into that site in that tab for an hour, and its password form stays under strict watch.
- **The Cleanway popup on the warning page says "This is a scam site"**, not "This page is safe", and offers to close the tab.
- **Your sign-in key is kept out of reach.** The short-lived sign-in key lives in browser memory that page scripts cannot read and is cleared when the browser closes; you stay signed in — the extension refreshes the sign-in at start-up.
- **The extension talks only to Cleanway's server.** The server address cannot be pointed somewhere else.
- **Catches more scam sites on free hosting** (for example `gmail-support.netlify.app`, `facebook-login0.vercel.app`) and on free dynamic-DNS names such as duckdns.org.
- **Removed unused code** that recognised mail sites by part of the address (an address like `mail.google.com.evil.example` would have fooled it); it never affected protection.
- **The QR code generator in Settings is the library's official file**: qrcode-generator 1.4.4, unminified, byte for byte as in its npm package, so store reviewers can check it against the release. The QR code looks the same.

## [Android 1.0.4] - built 2026-10-08, not published

Android app, versionCode 104 (rebuilt as 105). Never published — no GitHub
release, no store: these changes reach Android phones with App 1.0.5 (106),
the first Android release after 1.0.3.

**Что нового**
- **Проверка SMS стала умнее.** Кроме правил, текст сообщения теперь оценивает небольшая модель прямо на телефоне: она замечает мошеннические сообщения, даже если они написаны своими словами. Текст по-прежнему никуда не отправляется.
- **Новые правила для SMS.** Приложение узнаёт мошеннические схемы, которые раньше пропускало, и общие приметы обмана: просят перевести деньги, назвать код, установить приложение, никому не говорить, перезвонить на личный номер.
- **Ссылки без http://.** Адрес вроде `bonus-sber.online` в тексте сообщения тоже находится и проверяется.
- **«Чтобы защита не выключалась».** На главном экране — шаги, которые не дают телефону усыплять защиту: разрешить работу в фоне и настройки вашего производителя (Samsung, Xiaomi, Huawei и другие). Если система всё же остановила защиту, приложение включает её снова.
- **Аккаунт и устройства.** Новый экран «Аккаунт»: тариф и список устройств, любое можно отвязать. Вход больше не слетает.
- **Удаление аккаунта** прямо в приложении; 30 дней, чтобы передумать.
- **Во время звонка.** Если во время разговора или в течение 30 минут после него вы пытаетесь отключить защиту или открыть опасный сайт, приложение сначала предупреждает: это мошенники, положите трубку. Без доступа к звонкам и номерам.

**What's new**
- **Smarter SMS check:** a small on-phone model reads the message text next to the rules and catches scams written in their own words. The text still never leaves the phone.
- **New SMS rules:** scam schemes the rules used to miss, plus the generic signs — asking for money, a code, an app install, secrecy, a call back to a personal number.
- **Links without http://** in a message (`bonus-sber.online`) are found and checked.
- **Keep protection on:** home-screen steps so the phone does not put protection to sleep (background/battery and your phone maker's settings); protection is turned back on if the system stops it.
- **Account and devices:** a new Account screen with your plan and devices, each can be unlinked; you stay signed in.
- **Delete your account** from the app, with 30 days to change your mind.
- **During a call:** trying to turn protection off or open a dangerous site while on the phone (or within 30 minutes after) first shows a "hang up, it's a scam" screen. No call permissions are asked for.

**For the team:** the server can turn the SMS text model off or make it quieter without a new APK (`SMS_TEXT_MODEL_*` env, see docs/RUSTORE_SUBMISSION.md §2).

## [0.3.0] - 2026-06-17

### Added — top-20 active-protection strategies (all shipped)
- **#1 Credential-form action-host detector** + active-protection modal
- **#2 Favicon brand-clone gallery** (24 brands seeded, 23 hashes populated)
- **#7 Kids / Regular / Granny / Pro block-page personas**
- **#8 Honeypot Shield** — "Send fake password" decoy (16-byte crypto-random, per-input unique, Shadow DOM toast)
- **#9 Conformal confidence_pct** (50–99) on every DomainResult + popup/block-page chips
- **#10 GH Actions cron** — Tranco daily refresh + favicon weekly refresh
- **#11 Modern-phish guard** — BitB detection, tab-napping rel-patch, overlay credential trap
- **#12 Public transparency endpoint** + landing page (Q2 2026 fixture)
- **#13 Pwned Password** content script — SHA-1 on blur, k-anonymity 5-char prefix, inline banner
- **#14 Tranco top-1M popularity signal** — negative weights for popular domains, atomic Redis refresh
- **#15 Cultural explainer** — 5 categories × 10 locales = 50 hand-curated payloads, Claude Haiku 4.5 with deterministic template fallback
- **#16 Public scorecard** upgraded with FP rate (0.08% Q2 interim)
- **#17 Typosquat Watchtower** — Levenshtein/PSL/crt.sh-driven with cron job
- **#18 Store artifacts ZIP builder** (5 stores) + `docs/STORES.md` runbook
- **#20 URL-param PII leak detection** (JWT/email/long-random, cap 25)
- **#21 LLM Judge** — Claude arbitrates caution-band verdicts; domain-free feature vector via SAFE_KEYS whitelist, sha256 cache, ±20 score-shift cap, 4s timeout, 3-gate firing, crash-safe silent no-op
- **DoH gateway** `/dns-query` (RFC 8484) + iOS `.mobileconfig` generator + landing `/dns` page (iOS/Android/macOS/Win11 paths)
- **Public `/check` full fan-out** — was rule-only, now runs the 18-check analyzer with 24h cache + 5/min IP rate limit + fail-soft fallback
- **Methodology page** (SSR from `docs/benchmarks/latest.json`) + side-by-side vs Cloudflare 1.1.1.1 for Families at `/check/<domain>`
- **Weekly GH Actions benchmark cron** — eval_fresh_urls.py vs URLhaus/PhishTank + Tranco safe sample

### Hardened
- **Watchtower** — subdomain dead code removed, punycode homograph, LIMIT truncation, quota fail-open, RLS shared-row violation, silent PATCH, log scrubbing (7 fixes from adversarial review)
- **Pwned Password** — Referer leak, plaintext-in-WeakMap, prefix-in-logs (3 HIGH fixes)
- **Honeypot Shield** — dropped restore (framework-state leak), per-input unique honeypot, removed fixed watermark, removed fetch (fingerprint), shadow-DOM piercing protection
- **Strategy #20 URL-PII detector** — capped at 25 params to prevent DoS

### Tests
- 619 test functions across 46 files (was 488 in May). Backend coverage held above 90% throughout the strategy push.

## [0.2.0] - 2026-05-13

### Added
- **Family Hub** — end-to-end server-blind family alerts (AES-256-GCM via libsodium), QR-code invite flow + `/family/join` landing, paste-link join
- **Audit log** — migration 014, `audit_log` table wired across account / subscription / family-invite endpoints
- **Stripe pipeline hardening** — checkout dead-on-arrival fix (4 bugs), cancel-bug fix (migration 013 UNIQUE constraint), welcome-email URL typo, past_due dunning grace, business-plan tier mapping
- **Stripe webhook coverage** — trial_will_end, invoice.paid, customer.deleted, idempotency keys
- **GDPR Art. 15/17** — data export + delete + migration 012 + purge cron
- **Voice endpoint** — honest verdict (no false-positive padding)
- **Outlook "Report phishing" add-in** — 3-bug fix, body+org DoS hardening, background LRU + abortable fetch, CheckRequest per-item cap
- **Disposable-email defense-in-depth**
- **Tracking-cleaner perf** improvements
- **Badge layout bug** fix

### Tests
- 488 → 636 test functions. Coverage 84% → 96%.

## [0.1.0] - 2026-04-08

### Added
- **Scoring Engine 3.0** — 42+ detection signals across 6 categories
- **9 blocklist sources** — Google Safe Browsing, PhishTank, URLhaus, PhishStats, ThreatFox, Spamhaus DBL, SURBL, AlienVault OTX, IPQualityScore
- **CatBoost ML model** — AUC 0.9983 (test set), 93.5% recall on fresh phishing URLs (measured weekly via `scripts/eval_fresh_urls.py`), 0.08% measured FP rate on Tranco top 1M
- **100K domain allowlist** — Tranco top domains with hosting platform bypass protection
- **125 brand targets** — typosquatting detection for tech, banking, shipping, crypto, government
- **Chrome Extension** — Manifest V3, link scanning, badges, block page, Privacy Audit, Security Score, Weekly Report, Breach Check, context menu, keyboard shortcuts
- **Firefox Extension** — Manifest V2 port
- **Safari Extension** — Manifest V3 port
- **iOS App** — 14 screens, QR scanner, breach check, auth, upgrade, VPN tunnel (Swift)
- **Android App** — 14 screens, QR scanner, breach check, auth, upgrade, VPN tunnel (Kotlin)
- **Landing Page** — Hero, features, pricing, FAQ, testimonials, competitor comparison, privacy policy, terms, SEO pages, referral pages, business page
- **API** — 26 endpoints: domain checking, payments (Stripe), user management, breach monitoring, feedback/whitelist, referral system, B2B org management, phishing simulation
- **Security** — JWT validation, SSRF protection, CORS lockdown, rate limiting, circuit breakers, structured logging, Sentry integration
- **ML pipeline** — Feature extraction (39 features), training script, bloom filter compiler
- **94 tests** — 75 unit + 10 integration + 9 feature tests
