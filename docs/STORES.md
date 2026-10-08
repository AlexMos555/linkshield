# Cleanway extension — store submission runbook

Strategy doc Top-20 **#18**. This is the per-store playbook for
shipping the Cleanway browser extension to every major Chromium-
and Gecko-family store + Safari. Run `bash scripts/build-store-
artifacts.sh` first to produce the upload-ready ZIPs under
`dist/store-artifacts/`.

The Android app's **Google Play** listing draft (EN + RU, Data safety) is in
§6 below; Play submission is currently blocked. The RuStore listing is in
`docs/RUSTORE_SUBMISSION.md` §7.

| Store | Reach | Cost | Manifest | Build artifact |
|---|---|---|---|---|
| Chrome Web Store | ~3 B Chrome + Brave + Vivaldi users | $5 one-time | MV3 | `cleanway-<v>-chrome.zip` |
| Microsoft Edge Add-ons | ~150 M Edge users | Free | MV3 | `cleanway-<v>-edge.zip` |
| Opera add-ons | ~320 M Opera users | Free | MV3 | `cleanway-<v>-opera.zip` |
| Firefox Add-ons (AMO) | ~180 M Firefox + Tor users | Free | MV2 shim | `cleanway-<v>-firefox.zip` |
| Safari App Extensions | ~1 B Safari (Mac + iOS) users | $99/yr (Apple Developer) | MV3 in Xcode wrapper | `cleanway-<v>-safari/` |
| Brave / Vivaldi | (consume CWS) | n/a | n/a — same Chrome upload | n/a |
| Firefox Android | included in AMO listing if `gecko_android` block added | Free | MV2 shim | same firefox.zip |

> **Quick start:** if you only have time for one submission today,
> ship to Chrome Web Store. That single upload reaches Chrome,
> Brave, Vivaldi, Arc (which sideloads CWS items), and Opera GX
> (which can install CWS items via Install Chrome Extensions
> add-on). The other stores compound the reach but don't unlock
> any single new user platform.

---

## Pre-flight (all stores)

```bash
# 1. Run all tests + smoke
pytest tests/ -q --ignore=tests/test_account_lock.py --ignore=tests/test_disposable_email_gate.py

# 2. Rebuild + zip artifacts
bash scripts/build-extensions.sh
bash scripts/build-store-artifacts.sh

# 3. Spot-check the chrome zip (load-unpacked)
#    chrome://extensions → Developer mode ON → Load unpacked → extension/
#    Walk through: badge on safe link, badge on bad link, popup verdict, block page.

# 4. Note the version
grep '"version"' extension/manifest.json
```

---

## 1. Chrome Web Store (chrome.zip)

**Dev account:** https://chrome.google.com/webstore/devconsole/ — $5 one-time fee, Google account required.

**Submission:**
1. Sign in → New item → upload `cleanway-<v>-chrome.zip`
2. Fill listing:
   - **Short description** (≤132 chars) and **Detailed description**: paste from
     `extension/STORE_LISTING.md` (the only extension listing source; the
     `STORE-LISTINGS.md` / `STORE-PRIVACY-JUSTIFICATION.md` files this runbook
     used to name do not exist).
   - **Category:** `Productivity → Tools`
   - **Languages:** all 10 we ship (en/es/hi/pt/ru/ar/fr/de/it/id)
3. Privacy practices tab:
   - Single purpose: "Detect and block phishing/scam URLs to protect the user."
   - Permission justification — paste the "Permissions" section of
     `extension/STORE_LISTING.md`. Chrome treats the `<all_urls>` content
     scripts as access to all sites, so justify that, not just `activeTab`.
   - Data usage — declare what the code sends (`docs/PRIVACY.md`):
     - **Web history** — the host name of pages the user visits and of links on
       them goes to `GET /api/v1/public/check/{host}` (official and
       user-content hosts are answered locally, `trusted-hosts.js`); never the
       path or query.
     - **Personal communications** and **Website content** — on Gmail, Outlook
       and Yahoo Mail the extension sends the open email's subject, sender,
       reply-to and body to `POST /api/v1/email/analyze`
       (`extension/src/content/webmail.js:244-270`). It runs automatically on
       every opened message; there is no setting to turn it off.
     - **Personally identifiable information** — the email address, only if the
       user signs in.
     - Do **not** claim "no data collected", and do not leave the two boxes
       above unticked.
   - Link the privacy policy: https://cleanway.ai/privacy-policy
4. Screenshots (1280×800 or 640×400):
   - 1. Popup with safe verdict
   - 2. Popup with dangerous verdict + reasons
   - 3. Block page with evidence cards
   - 4. Credential-guardian modal (#7) with three buttons
   - 5. Transparency report on cleanway.ai/transparency
5. Promo tile (440×280): **TODO — not made yet** (`marketing/store-assets/` does not exist).
6. Pricing: free
7. **Save draft → Preview → Submit for review.** Reviews typically 1-4 days; expedite by linking the transparency report (proves we publish FP rate).

**After approval:** Brave + Vivaldi pick it up automatically. Arc users can install via the same listing URL.

---

## 2. Microsoft Edge Add-ons (edge.zip)

**Dev account:** https://partner.microsoft.com/en-us/dashboard/microsoftedge/ — free, Microsoft account required.

**Notes:**
- Edge Add-ons accepts the Chrome MV3 build as-is — no manifest changes needed. We still upload `edge.zip` separately so each store can pin its own version history.
- Edge reviews tend to be FAST (24-48h) but pickier on screenshots than Chrome.

**Submission:**
1. Extensions → New → upload `cleanway-<v>-edge.zip`
2. Listing fields are similar to Chrome; reuse `STORE-LISTINGS.md → edge.*`
3. Edge requires a contact email visible in the listing — use `support@cleanway.ai`
4. Privacy: Edge displays each permission inline. The justifications must match the Chrome ones EXACTLY or we get a discrepancy flag.
5. Localisation: Edge accepts the same `_locales/` map Chrome does.

---

## 3. Opera add-ons (opera.zip)

**Dev account:** https://addons.opera.com/developer/ — free, requires GitHub account login.

**Notes:**
- Opera accepts MV3 Chrome zips. Their reviewer is small (1-2 people) so reviews can take 1-2 weeks — submit early.
- Opera will reject extensions that hit `chrome.storage.sync` without `storage` permission — we already declare it.
- Opera GX users (gaming browser) skew young + privacy-conscious. The "honeypot shield" (#8) marketing copy plays well with this audience — highlight it in the long_description for Opera specifically.

**Submission:**
1. Dashboard → Add → upload `cleanway-<v>-opera.zip`
2. Category: `Productivity`
3. Listing: see `STORE-LISTINGS.md → opera.*` — slightly punchier copy than Chrome.

---

## 4. Firefox Add-ons / AMO (firefox.zip)

**Dev account:** https://addons.mozilla.org/developers/ — free, Mozilla account required.

**Notes:**
- We ship MV2 with a module background (`"type": "module"`, so Firefox 112+) and a `chrome → browser` alias in `src/background/browser-compat.js`. Firefox's MV3 transition is still mid-flight; MV2 keeps the broadest compatibility. Chromium can't load MV2, so `scripts/test-extension-sw.mjs` does not cover this build: load it by hand in Firefox (about:debugging) before submitting.
- AMO requires a **source-code submission** for any extension that uses minified or bundled code. Our build is hand-written JS — but AMO's check is heuristic. If they flag, link the GitHub repo: https://github.com/AlexMos555/linkshield.
- Mozilla's review is human-led; expect 3-10 business days. The honest publish-our-FP-rate angle plays VERY well with AMO reviewers.

**Submission:**
1. Submit a new add-on → upload `cleanway-<v>-firefox.zip`
2. Add-on type: `Extension`
3. Listing fields: `STORE-LISTINGS.md → firefox.*`
4. Source code: link the GitHub release tag (e.g. `https://github.com/AlexMos555/linkshield/releases/tag/v<version>`).
5. Add the `gecko_android` block to `manifest.json` before submitting if Firefox Android support is in scope — done already.
6. Privacy policy: AMO requires a public URL. We use https://cleanway.ai/privacy-policy.

---

## 5. Safari App Extensions (safari/)

**Dev account:** https://developer.apple.com/account/ — $99/year (Apple Developer Program), requires Apple ID.

**Notes:**
- Safari extensions can't be uploaded as a zip directly — they must be wrapped in a Mac app bundle via Xcode's `Convert to Safari Web Extension` command. The build-store-artifacts script stages the source for you under `dist/store-artifacts/cleanway-<v>-safari/`.
- The wrapper app needs an App Store Connect listing of its own. Plan for an extra week of round-trips with Apple Review.
- App Sandbox restrictions: Cleanway's content scripts run unchanged, but the popup's `chrome.storage.local` becomes `safari.storage.local` — handled by our existing alias.

**Submission flow:**
1. Open Xcode → `xcrun safari-web-extension-converter dist/store-artifacts/cleanway-<v>-safari/`
2. Choose project name `Cleanway` and bundle id `ai.cleanway.safari`
3. Build → Archive → Distribute → Upload to App Store Connect
4. In App Store Connect, fill the macOS listing per `STORE-LISTINGS.md → safari.*`
5. Submit for review. **Safari review can take 7-14 days** — start the clock first.

---

## 6. Google Play (Android app) — DRAFT, submission BLOCKED

> **Status (re-checked 2026-10-08): do not submit.** Google Play requires
> targetSdk 36 for new apps and updates since 31 Aug 2026; our APK targets 34
> because the app is on Expo SDK 52 (`mobile/package.json`: `expo ~52.0.0`).
> Details: `docs/RUSTORE_SUBMISSION.md` (top) and `docs/GO_LIVE_CHECKLIST.md`.
> `landing/lib/install-urls.ts` has no Google Play entry — the Android button
> leads to `/android` (direct APK). The copy below is ready so the listing is not
> the bottleneck once the SDK upgrade ships.

Package `ai.cleanway.app`. Build, signing, permissions and the VpnService /
battery / camera justifications are shared with RuStore:
`docs/RUSTORE_SUBMISSION.md` §2–4.

### 6.0 TODO before any Play submission (founder)

- [ ] **Remove or replace the old upgrade screen.** In every language except
      Russian, Settings → Plan opens `mobile/app/upgrade.tsx`: hard-coded "$4.99
      Personal / $9.99 Family", "10 checks/day", and a button that opens
      `cleanway.ai/pricing` in the browser. That breaks Play's Payments policy
      (digital subscriptions must use Play Billing) and contradicts the new
      prices (`docs/ACCOUNTS_BILLING_PLAN.md` §5). Hide it like in Russian
      (`mobile/src/config/market.ts`) or wire Play Billing (§7 item 4 of the
      plan) first.
- [ ] **Pricing line.** Play Billing is not wired, the 3-checks-a-day limit and
      the 7-day trial are not in the app, so the copy says only "Basic protection
      is free." When paid is live, add (confirm numbers first): "Blocking known
      scam sites is free with no limit. 3 detailed checks a day are free, and
      everything is unlimited for the first 7 days. Optional subscription:
      $0.99 a month or $9.99 a year for 3 devices (phone, tablet, or browser with
      the extension); each extra device $0.49 a month." Russian: see
      `docs/RUSTORE_SUBMISSION.md` §7.0 (99 ₽ / +29 ₽).
- [ ] **Data safety "shared" answer** for the threat-intelligence lookups (below).
- [ ] **Screenshots in English** — none exist; capture on the signed build in
      the `en` locale.

### 6.1 English

**Title** (Play limit 30) — 25 characters:

```text
Cleanway: Scam Protection
```

**Short description** (limit 80) — 78 characters:

```text
Blocks known scam sites in every app and checks texts and links before you tap
```

**Full description** (limit 4000):

<!-- count: play_en_full max=4000 -->
```text
Cleanway protects your phone from scams. It stops known scam sites from opening and helps you check a suspicious text message or link before you tap it. Turn it on once and it keeps working, even with the app closed. Simple to set up for yourself or for your parents.

WHAT IT PROTECTS YOU FROM
• Scam websites. Cleanway blocks known scam and phishing sites in every app and browser. The page simply won't open, and Cleanway lets you know with a notification.
• Suspicious texts. Got a message about a "parcel", a "blocked card" or a "prize"? Share it to Cleanway or paste the text. The app tells you whether it looks like a scam and explains why, in plain words.
• Dangerous links and QR codes. Paste a link or point the camera at a QR code, and Cleanway checks the site before you open it.
• Phone scams. If you try to switch protection off or open a blocked site during a call or right after it, Cleanway shows a warning: this is what scammers ask for. The "I'm being called" button explains what to do when "the bank" or "the police" calls, and lets you call a loved one with one tap. Cleanway does not listen to calls, see phone numbers or block calls.

SIMPLE FOR EVERYONE
• Clear warnings without technical words.
• Tips on the home screen show what to change on your phone so battery saving doesn't switch protection off.
• If protection was on, it turns itself back on after the phone restarts.
• No account needed. Signing in with email is optional; it shows all your devices in one place, and you can unlink the ones you no longer use.

HOW IT WORKS, HONESTLY
• The list of known scam sites is stored on your phone and matched there. To do this, Cleanway uses Android's built-in VPN feature. It is not a privacy VPN: your IP address does not change, and your pages, messages and calls do not pass through Cleanway.
• Your phone finds all other sites as usual, through your mobile operator or Wi-Fi, and if they do not answer, through the public services Cloudflare or Quad9.
• Android runs only one VPN at a time. If you already use another VPN, you will have to choose between it and Cleanway's protection.
• Message text is checked on your phone and is never sent anywhere. Only the site names from links in a message can go to our server, three at most.
• When you check a link, only the site name (for example, example.com) goes to Cleanway's server, never the rest of the address. The server checks it against sources that include outside lists of dangerous sites such as Google Safe Browsing.
• No ads, and we don't sell data.

WHAT CLEANWAY DOESN'T PROMISE
New scam sites and messages appear every day, and no app catches them all. If in doubt, don't open the link, never share codes from text messages, and call your bank on the number printed on your card.

PRICE
Basic protection is free.

Help: support@cleanway.ai
Privacy policy: cleanway.ai/privacy-policy
```

### 6.2 Русский

**Название** (лимит 30) — 30 characters:

```text
Cleanway: защита от мошенников
```

**Краткое описание** (лимит 80) — 69 characters:

```text
Защита от мошенников: блокирует опасные сайты, проверяет СМС и ссылки
```

**Полное описание** (лимит 4000). Same text as the RuStore listing on purpose —
one Russian description, two stores. If you edit one, edit both.

<!-- count: play_ru_full max=4000 -->
```text
Cleanway — защита от мошенников в телефоне. Не даёт открыть известные мошеннические сайты и помогает проверить подозрительное СМС или ссылку, прежде чем вы по ней перейдёте. Включили один раз — защита работает сама, даже когда приложение закрыто. Можно поставить себе и родителям.

ОТ ЧЕГО ЗАЩИЩАЕТ
• Сайты мошенников. Cleanway блокирует известные мошеннические и фишинговые сайты во всех приложениях и браузерах. Такая страница просто не откроется, а Cleanway сообщит об этом уведомлением.
• Подозрительные СМС. Пришло сообщение про «посылку», «блокировку карты» или «выигрыш»? Перешлите его в Cleanway кнопкой «Поделиться» или вставьте текст. Приложение скажет, похоже ли это на мошенников, и объяснит почему — простыми словами.
• Опасные ссылки и QR-коды. Вставьте ссылку или наведите камеру на QR-код — Cleanway проверит сайт, прежде чем вы его откроете.
• Обман по телефону. Если во время звонка или сразу после него вы пытаетесь отключить защиту или открыть заблокированный сайт, Cleanway покажет предупреждение: так действуют мошенники. Кнопка «Мне звонят» подскажет, что делать, если звонят «из банка» или «из полиции», и поможет одним нажатием позвонить близкому. Cleanway не слушает разговоры, не видит номера и не блокирует звонки.

ПРОСТО ДЛЯ ВСЕХ
• Понятные предупреждения на русском, без технических слов.
• Подсказки на главном экране: что настроить в телефоне, чтобы экономия батареи не выключала защиту.
• Если защита была включена, после перезагрузки телефона она включится сама.
• Аккаунт не нужен. Войти по email можно по желанию — тогда в одном месте видны все ваши устройства, и лишнее можно отвязать.

КАК ЭТО УСТРОЕНО — ЧЕСТНО
• Список известных мошеннических сайтов хранится на телефоне, и сверка идёт там же. Для этого Cleanway использует встроенный в Android механизм VPN. Это не VPN для анонимности: ваш IP-адрес не меняется, а страницы, сообщения и звонки через Cleanway не проходят.
• Остальные сайты телефон находит как обычно — через вашего оператора или Wi-Fi, а если они не отвечают — через общедоступные сервисы Cloudflare или Quad9.
• На Android одновременно может работать только один VPN. Если у вас уже включён другой VPN, придётся выбрать: он или защита Cleanway.
• Текст СМС проверяется на телефоне и никуда не отправляется. На наш сервер могут уйти только имена сайтов из ссылок в сообщении — не больше трёх.
• Когда вы проверяете ссылку, на сервер Cleanway уходит только имя сайта (например, example.ru), без остальной части адреса. Сервер сверяет его в том числе с внешними базами опасных сайтов, например Google Safe Browsing.
• Мы не показываем рекламу и не продаём данные.

ЧЕГО CLEANWAY НЕ ОБЕЩАЕТ
Новые мошеннические сайты и сообщения появляются каждый день, и ни одна программа не ловит их все. Если сомневаетесь — не переходите по ссылке, никому не называйте коды из СМС и перезвоните в банк по номеру на обратной стороне карты.

СКОЛЬКО СТОИТ
Основная защита — бесплатно.

Вопросы и помощь: support@cleanway.ai
Политика конфиденциальности: cleanway.ai/privacy-policy
```

Count check for both full descriptions (same snippet as the RuStore doc):

```bash
python3 - <<'EOF'
import re, pathlib
t = pathlib.Path("docs/STORES.md").read_text(encoding="utf-8")
for name, mx, body in re.findall(r"<!-- count: (\S+) max=(\d+) -->\n```text\n(.*?)\n```", t, re.S):
    print(name, len(body), "/", mx, "OK" if len(body) <= int(mx) else "TOO LONG")
EOF
```

### 6.3 Data safety — answers that match the code

Full table with evidence: `docs/RUSTORE_SUBMISSION.md` §3; the source of truth
is `docs/PRIVACY.md` → "The Android app". In Play's terms:

| Play category | Answer | Why |
|---|---|---|
| Web browsing → **Web browsing history** | **Collected**, not optional, purpose *App functionality* + *Fraud prevention, security* | The host name of every link the person checks (typed, pasted, QR, shared, link guard, max 3 per message) goes to `api.cleanway.ai`; the server caches host + verdict up to 24 h, so do **not** tick "processed ephemerally". Never the full URL. |
| Messages → **SMS or MMS** | **Not collected** | The text is analysed on the phone and never leaves it (Play counts only data sent off the device). |
| Personal info → **Email address** | Collected, **optional**, *Account management* | Only when the person signs in. |
| App info and performance → **Crash logs**, **Diagnostics** | Collected, *Analytics* (stability) | Sentry; a processor, so not "shared". |
| Device or other IDs | Collected, *Fraud prevention, security* + *Account management* | The random install number (rate limiting, replaced every 24 h) and the device ID of a signed-in account. Neither is derived from hardware. |
| Location, contacts, photos, calendar, files, audio, health, financial info, app activity | **Not collected** | No such permission or code path. No purchases in the app yet. |
| Data shared with third parties | **TODO (founder):** the server sends the bare host, with no user identity, to threat-intelligence services (Google Safe Browsing and the others in `docs/PRIVACY.md`). Play's "service provider" exemption may cover it; the conservative answer is *Shared: Web browsing history — Fraud prevention, security*. Pick one and keep it in step with the privacy policy. | |
| Encrypted in transit | **Yes** | HTTPS to our API. |
| Deletion | **Yes** — in the app (Settings → Delete account, Account screen) and on the web: `https://cleanway.ai/account` (use as the "delete account URL") | Required for apps with accounts. |

---

## After submission

- Pin store URLs in [README.md](../README.md) install badges.
- Update [landing/app/[locale]/page.tsx](../landing/app/[locale]/page.tsx) hero CTA to use the live Chrome Web Store URL once approved.
- Bump the Q3 2026 transparency report's `intel_sources_active` list if we add any new sources between submissions.
- Watch the Chrome Web Store dashboard for "Possible policy violation" notices — a common trigger is host-permission scope. The manifest asks for neither `webRequest` nor `declarativeNetRequest`; the broad scope comes from the `<all_urls>` content scripts, which reviewers will see as "read and change all your data on all websites".

## Submission status (update on each release)

| Store | Submitted | Approved | Listing URL |
|---|---|---|---|
| Chrome Web Store | TBD | TBD | TBD |
| Edge Add-ons | TBD | TBD | TBD |
| Opera add-ons | TBD | TBD | TBD |
| Firefox AMO | TBD | TBD | TBD |
| Safari Mac App Store | TBD | TBD | TBD |
