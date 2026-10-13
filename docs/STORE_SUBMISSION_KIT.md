# Набор для публикации: Google Play, Chrome Web Store, Edge, Firefox

Один файл, из которого вставляется всё: тексты, ответы на анкеты, картинки. Порядок — как в консоли каждого магазина: «где нажать → что вставить». App Store — отдельно, `docs/APP_STORE_LISTING.md`; RuStore — `docs/RUSTORE_SUBMISSION.md` §7.

Как пользоваться:
- вставляйте **только текст внутри серых блоков** — пометки вокруг для нас;
- тексты для покупателей — на языке листинга (английский / русский), ответы проверяющим — по-английски;
- длины, полнота полей, совпадение русского описания с RuStore, обоснования для каждого разрешения из манифеста и размеры картинок проверяет `python3 scripts/check_store_submission_kit.py` (тест — `tests/test_store_submission_kit.py`);
- почему ответы именно такие (код, файлы) — `docs/STORES.md` §6.3–6.9 (Android), `docs/CWS_SUBMISSION.md` §3–5 и `extension/STORE_LISTING.md` (расширение), `docs/PRIVACY.md`.

Проверено 2026-10-13: `https://cleanway.ai/privacy-policy`, `/delete-account`, `/account`, `/support`, `/terms` и `/ru/…` отвечают 200; `aapt2 dump permissions` сборки 1.0.4 (104) — без SMS, журнала звонков и `AD_ID`; манифесты `dist/store-artifacts/cleanway-0.2.0-{chrome,edge,firefox}.zip` (Edge = Chrome).

---

## 0. Только вы (до открытия консолей)

| Что | Где | Зачем |
|---|---|---|
| Аккаунт разработчика Google Play **организации**: $25, номер D-U-N-S компании, подтверждение телефона, почты и сайта `cleanway.ai` (через Search Console) | play.google.com/console/signup | Аккаунт организации не попадает под правило «12 тестировщиков 14 дней» для личных аккаунтов |
| Ящик `support@cleanway.ai` принимает письма | почтовый хостинг | Play требует рабочий контактный email; страница `/delete-account` пока пишет, что ящик не настроен |
| Собрать AAB для Play с `EXPO_PUBLIC_DISTRIBUTION=play` и `EXPO_PUBLIC_REVENUECAT_ANDROID_KEY=goog_…` | `docs/STORES.md` §6.0 | Без этого в сборке нет Google Play Billing, и Play её отклонит |
| Записать видео для деклараций VPN и foreground service (§1.6) и выложить на YouTube «доступ по ссылке» | телефон + YouTube | Play требует ссылку на видео |
| Аккаунт Chrome Web Store: $5, двухэтапная проверка Google, подтвердить почту; статус «trader» (продавец) для ЕС — указать адрес, телефон и email компании | chrome.google.com/webstore/devconsole | Без оплаты и 2SV загрузка недоступна |
| Аккаунт Microsoft Partner Center (бесплатно, тип — компания) | partner.microsoft.com/dashboard/microsoftedge | — |
| Аккаунт Mozilla с двухфакторной защитой | addons.mozilla.org/developers | AMO не принимает загрузки без 2FA |

---

## 1. Google Play (Android-приложение `ai.cleanway.app`)

Консоль: play.google.com/console. Сначала всё из этого раздела, потом загрузка AAB во **Внутреннее тестирование** (§1.7).

### 1.1 Создать приложение — «Create app»

| Поле | Значение |
|---|---|
| App name | `Cleanway: Scam Protection` |
| Default language | English (United States) – en-US |
| App or game | App |
| Free or paid | Free (подписка внутри — через Google Play Billing) |
| Declarations | отметить обе (Developer Program Policies, US export laws) |

### 1.2 Store presence → Main store listing (английский)

<!-- field: play.en.title max=30 -->
```text
Cleanway: Scam Protection
```

<!-- field: play.en.short max=80 -->
```text
Blocks known scam sites in every app and checks texts and links before you tap
```

<!-- field: play.en.full max=4000 -->
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

Графика (Graphics):

| Поле | Файл |
|---|---|
| App icon (512 × 512) | `mobile/assets/store/icon-512.png` |
| Feature graphic (1024 × 500) | `mobile/assets/store/google-play/en/feature-graphic.png` |
| Phone screenshots (порядок загрузки) | `mobile/assets/store/google-play/en/01-home.png`, `02-message-scam.png`, `03-link-dangerous.png`, `04-call-guard.png`, `05-history.png` |
| Video, tablet / Chromebook / Wear screenshots | пусто (не обязательно) |

<!-- asset: mobile/assets/store/icon-512.png 512x512 -->
<!-- asset: mobile/assets/store/google-play/en/feature-graphic.png 1024x500 opaque -->
<!-- asset: mobile/assets/store/google-play/en/01-home.png 1080x1920 opaque -->
<!-- asset: mobile/assets/store/google-play/en/02-message-scam.png 1080x1920 opaque -->
<!-- asset: mobile/assets/store/google-play/en/03-link-dangerous.png 1080x1920 opaque -->
<!-- asset: mobile/assets/store/google-play/en/04-call-guard.png 1080x1920 opaque -->
<!-- asset: mobile/assets/store/google-play/en/05-history.png 1080x1920 opaque -->

Скриншоты — настоящие кадры сборки 1.0.4 (104), что в них и как переснять: `mobile/assets/store/google-play/README.md`.

### 1.3 Перевод на русский — Main store listing → «Manage translations» → Add → Russian – ru-RU

<!-- field: play.ru.title max=30 -->
```text
Cleanway: защита от мошенников
```

<!-- field: play.ru.short max=80 -->
```text
Защита от мошенников: блокирует опасные сайты, проверяет СМС и ссылки
```

Полное описание — тот же текст, что в RuStore (`docs/RUSTORE_SUBMISSION.md` §7.3); проверка сверяет их побуквенно.

<!-- field: play.ru.full max=4000 -->
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

Графика для ru-RU: Feature graphic `mobile/assets/store/google-play/ru/feature-graphic.png`; скриншоты `mobile/assets/store/google-play/ru/01-home.png` … `05-history.png` (тот же порядок). Иконка общая.

<!-- asset: mobile/assets/store/google-play/ru/feature-graphic.png 1024x500 opaque -->
<!-- asset: mobile/assets/store/google-play/ru/01-home.png 1080x1920 opaque -->
<!-- asset: mobile/assets/store/google-play/ru/02-message-scam.png 1080x1920 opaque -->
<!-- asset: mobile/assets/store/google-play/ru/03-link-dangerous.png 1080x1920 opaque -->
<!-- asset: mobile/assets/store/google-play/ru/04-call-guard.png 1080x1920 opaque -->
<!-- asset: mobile/assets/store/google-play/ru/05-history.png 1080x1920 opaque -->

**Строка о цене.** Сейчас в обоих описаниях «Basic protection is free.» / «Основная защита — бесплатно.» Когда подписки заработают в Play Console, допишите строку из `docs/STORES.md` §6.0 («Pricing line») — и поменяйте её в RuStore тоже.

### 1.4 Store presence → Store settings

| Поле | Значение |
|---|---|
| App category | Application → **Tools** |
| Tags | до 5 из списка Play, ближайшие к: Security, Privacy, Safety |
| Email address | `support@cleanway.ai` |
| Phone number | номер компании (необязательно, для организации Play может показать его в листинге) |
| Website | `https://cleanway.ai` |
| External marketing | оставить включённым |

### 1.5 Policy and programs → App content (по порядку списка)

**Privacy policy**

```text
https://cleanway.ai/privacy-policy
```

**App access** → «All functionality in my app is available without any access restrictions». Вход по почте необязателен: вся защита работает без аккаунта.

**Ads** → «No, my app does not contain ads».

**Content rating** → Start questionnaire:

| Вопрос | Ответ |
|---|---|
| Email for IARC | `support@cleanway.ai` |
| Category | «All Other App Types» (в старой анкете — «Utility, Productivity, Communication, or Other») |
| Violence, fear, sexuality, gambling, language, controlled substances, crude humour | No — на всё |
| Users can interact or exchange content (chat, posts, photos) | No (семейные предупреждения — автоматические, зашифрованные, без свободного текста) |
| Shares the user's current physical location with other users | No |
| Allows users to purchase digital goods | Yes (подписка через Google Play Billing) |
| Unrestricted internet access / web browser or search engine | No (ссылки открываются в браузере пользователя) |
| NFT / blockchain, gambling-like content | No |
| Ожидаемый результат | Everyone / PEGI 3 / 0+ |

**Target audience and content** → Target age: только **18 and over**. «Could your store listing unintentionally appeal to children?» → No. (Младшие группы включают правила Families — не отмечать.)

**News apps** → «My app is not a news app».

**Government apps** → No.

**Financial features** → «My app doesn't provide any financial features» (подписка — это покупка в Google Play, не финансовая функция).

**Health apps** → «My app does not have any health features».

**Advertising ID** → «No». В сборке 1.0.4 нет разрешения `com.google.android.gms.permission.AD_ID`; перед загрузкой нового AAB проверьте: `aapt2 dump permissions app-release.apk | grep AD_ID` — должно быть пусто.

**SMS and Call Log permissions** — декларация не нужна: приложение не запрашивает ни SMS, ни журнал звонков, ни состояние телефона (`app.json` → `blockedPermissions`, страж `mobile/scripts/check-android-permissions.mjs`). Если Play всё же покажет эту форму — значит, разрешение попало в AAB через библиотеку: не заполнять, а убрать его и пересобрать.

**Data safety** → Start:

Шаг «Data collection and security»:

| Вопрос | Ответ |
|---|---|
| Does your app collect or share any of the required user data types? | Yes |
| Is all of the user data collected by your app encrypted in transit? | Yes |
| Which methods of account creation does your app support? | «Username and other authentication» (email + одноразовый код). Вход необязателен |
| Delete account URL | `https://cleanway.ai/delete-account` |
| Do you provide a way for users to request that some or all of their data is deleted, without requiring them to delete their account? | No |

Шаг «Data types» — отметить ровно эти:

| Категория → тип | Collected | Shared | Processed ephemerally | Required / optional | Purposes |
|---|---|---|---|---|---|
| Personal info → **Email address** | Yes | No | No | Optional | App functionality, Account management |
| Personal info → **User IDs** | Yes | No | No | Optional | App functionality, Account management |
| Financial info → **Purchase history** | Yes | No | No | Optional | App functionality, Account management |
| Web browsing → **Web browsing history** | Yes | **Yes** | No | Required | Collected: App functionality, Fraud prevention, security, and compliance. Shared: Fraud prevention, security, and compliance |
| App info and performance → **Crash logs** | Yes | No | No | Required | App functionality, Analytics |
| App info and performance → **Diagnostics** | Yes | No | No | Required | App functionality, Analytics |
| Device or other IDs → **Device or other IDs** | Yes | No | No | Required | App functionality, Fraud prevention, security, and compliance, Account management |

Всё остальное (местоположение, контакты, сообщения SMS/MMS, фото, аудио, файлы, календарь, здоровье, активность в приложении, установленные приложения, рекламный ID) — **не отмечать**: текст сообщений проверяется на телефоне и никуда не уходит, камера читает QR-код на устройстве.

Как это сходится с iOS (App Privacy, `docs/IOS.md` §3.5): email, ID пользователя, ID устройства и история покупок — «связаны с пользователем, для работы приложения»; имена проверенных сайтов и отчёты о сбоях — «не связаны»; отслеживания и рекламы нет. В Play нет понятия «связано», поэтому там это выражено целями. «Shared» у истории браузинга — осторожный ответ: сервер отправляет голое имя сайта, без пользователя, сервисам проверки угроз (Google Safe Browsing и др., политика §5). Обоснование — `docs/STORES.md` §6.3.

**VPN service** (появится, потому что в манифесте есть `BIND_VPN_SERVICE`):

| Вопрос | Ответ |
|---|---|
| Does your app use VpnService? | Yes |
| Core functionality | Device security — on-device anti-phishing DNS filter (не «VPN-клиент», не прокси) |
| Is VPN usage disclosed in the store listing? | Yes — раздел «HOW IT WORKS, HONESTLY» полного описания |
| Video link | ссылка из §1.6 |

Описание (если поле ограничено 500 символами):

<!-- field: play.vpn.short max=500 -->
```text
Cleanway uses VpnService only for an on-device DNS filter. The tunnel carries DNS lookups only (one /32 route to an on-device address); web, app, message and call traffic never enter it, and there is no remote VPN server. Names on a list of known scam sites stored on the phone get "not found", so those sites don't open; other lookups go to the network's own DNS. The user's IP is not changed or hidden; traffic is not logged, sold or sent to us.
```

Описание (если поле длиннее):

<!-- field: play.vpn.full max=2000 -->
```text
Cleanway uses Android's VpnService only to run a DNS filter on the device itself. The VPN interface routes nothing but DNS lookups to the app (a single /32 route to the on-device DNS address); web pages, app traffic, messages and calls never enter the tunnel. The app compares each looked-up name with a list of known scam and phishing sites stored on the phone and answers names on the list with "not found", so those sites do not open. Every other lookup is forwarded to the DNS server of the network the phone is on (the user's mobile operator or Wi-Fi router), and only if that fails to Cloudflare (1.1.1.1) or Quad9 (9.9.9.9) — the lookups the phone makes without Cleanway. There is no remote VPN server: the app does not route, proxy, inspect, log or monetise the user's traffic, and does not change or hide the user's IP address. The DNS answers are not sent to us. The VPN starts only after the user turns protection on and accepts Android's VPN consent dialog, and the store listing says that Cleanway uses the built-in VPN feature.
```

Риск, о котором стоит знать: политика Play говорит о шифровании «до конечной точки VPN-туннеля». У Cleanway конечная точка — на самом телефоне, наружу через туннель ничего не уходит; пересылаемые DNS-запросы идут к резолверу сети так же, как без приложения. Если проверяющий спросит — ответ именно такой.

**Foreground service permissions** → `FOREGROUND_SERVICE_SPECIAL_USE`:

| Вопрос | Ответ |
|---|---|
| Foreground service type | Special use (subtype в манифесте: `vpn`) |
| User impact if deferred or interrupted | Пользователь остаётся без защиты, не зная об этом: мошеннические сайты открываются |
| Video link | та же ссылка из §1.6 |

<!-- field: play.fgs.short max=500 -->
```text
The foreground service is Cleanway's on-device DNS filter (VpnService) that blocks known scam and phishing sites in every app. It must keep running while the user has protection on, including with the app closed: if Android stopped it, scam links opened from messages or other apps would load unprotected. It starts only when the user turns protection on, shows a persistent "Protection is on" notification, and stops when the user turns protection off.
```

`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` отдельной формы не имеет; если проверяющий спросит — текст в `docs/STORES.md` §6.7.

### 1.6 Видео для деклараций VPN и foreground service (записываете вы)

Один ролик на оба поля. Телефон с Play-сборкой из внутреннего тестирования, встроенная запись экрана, 30–90 секунд, вертикально, режим «Не беспокоить» (никаких личных уведомлений), английский язык интерфейса. Что должно быть видно, по порядку:

1. Главный экран Cleanway с выключенной защитой.
2. Нажатие «включить» и объяснение в приложении, что используется встроенный механизм VPN Android и только для DNS.
3. Системный диалог Android «Connection request» → OK.
4. Значок ключа в строке состояния; шторка уведомлений с постоянным уведомлением «Protection is on» (это и есть foreground service).
5. Chrome → адрес `list-canary.cleanway.ai` (тестовое имя, которое всегда есть в списке Cleanway) — страница не открывается, Cleanway показывает уведомление о блокировке.
6. Обычный сайт (`example.com`) открывается — блокируются только имена из списка.
7. Выключение защиты в приложении — ключ и уведомление исчезают.

YouTube → «Доступ по ссылке» (Unlisted). Ссылку вставить в обе декларации.

### 1.7 Release → Testing → Internal testing → Create new release

AAB с `EXPO_PUBLIC_DISTRIBUTION=play` (§0). Release notes:

<!-- field: play.release_notes max=1000 -->
```text
<en-US>
First release on Google Play: blocks known scam sites in every app, checks a suspicious text or link you share, and explains what to do when "the bank" calls.
</en-US>
<ru-RU>
Первая версия в Google Play: блокирует известные мошеннические сайты во всех приложениях, проверяет подозрительные СМС и ссылки и подсказывает, что делать, если звонят «из банка».
</ru-RU>
```

Дальше — `docs/STORES.md` §6.10, пункты 10–13 (проверка на телефоне из Play, подписки в RevenueCat, страны: все доступные; в России Play Billing не работает — приложение там просто бесплатное).

---

## 2. Расширение: общие тексты для Chrome, Edge и Firefox

Название и краткое описание Chrome и Edge берут **из манифеста** (`_locales/*/messages.json`): «Cleanway — Protection from scam links» / «Cleanway — Защита от мошенников». Менять — только в `packages/extension-core` и пересобирать ZIP.

### 2.1 Подробное описание — английский

<!-- field: ext.en.description max=10000 -->
```text
Cleanway warns you about scam and phishing websites before you type a password or card number. Everything is in plain language, for you and for your parents.

WHAT IT DOES
- Marks links on the pages you visit: a green tick, a yellow warning or a red cross, with the reason when you hover.
- Stops you on a dangerous page with a full-screen warning that explains why, in your language.
- Warns you on login forms that send your password to a different site than the one you see, and on fake "browser windows" drawn inside a page.
- Tells you if a password you type has appeared in known data leaks.
- Optional, off until you switch it on in Settings: checks emails you open in Gmail, Outlook and Yahoo Mail and shows a short banner: looks safe, suspicious, or likely a scam.
- Right-click any link to check it. Right-click a page for a Privacy Audit: trackers, cookies and forms that ask for personal data. The audit runs in your browser.
- Removes common tracking tags such as utm_ and fbclid from web addresses.
- Family: with an account, family members can send each other end-to-end encrypted warnings about dangerous sites.

WHAT LEAVES YOUR BROWSER, HONESTLY
- Site names. To check a site, Cleanway sends only its name (for example, example.com) to our server, never the full address, the page content or your history. This happens for the page you open and for links on it, except well-known official sites the extension recognises on its own. The server checks the name, including with outside lists of dangerous sites such as Google Safe Browsing.
- Emails, only if you switch the email check on. It is off until you turn on "Scan emails I open in Gmail, Outlook and Yahoo for phishing" in Settings. While it is on, for each email you open in Gmail, Outlook or Yahoo Mail, Cleanway sends its subject, the sender's name and address, the reply-to address, the text, and the address and text of each link (not the email's HTML) to our server to check it for scams. The email is checked and not stored. Switch it off any time and the checks stop at once.
- Password leak check. When you leave a password field, Cleanway sends only a short scrambled piece of it (the first 5 characters of its SHA-1 hash), never the password itself. The match is made in your browser.
- Your check history and counters stay in your browser; history is deleted after 30 days.
- Signing in is optional. If you sign in through cleanway.ai, the extension keeps its sign-in keys in the browser's extension storage, this browser appears as a device in your Cleanway account (you can unlink it there), and your settings are saved to the account. "Sign out" in Settings deletes the keys.
- No ads, no analytics inside the extension, and we don't sell data.

WHAT CLEANWAY DOESN'T PROMISE
New scam sites appear every day, and no tool catches them all. If something feels wrong, don't enter your details.

PRICE
Free.

PERMISSIONS EXPLAINED
- "Read and change all your data on all websites": Chrome shows this because Cleanway's scripts run on every page. They are needed to mark links, show the warning page and watch password forms where they appear. They read the page inside your browser; only what is listed above leaves it.
- Gmail, Outlook and Yahoo Mail sites (optional): asked for only when you switch the email check on, and given back when you switch it off.
- Scripting: turns the email check on and off; it runs on those mail sites only while it is switched on.
- cleanway.ai: our checking server (api.cleanway.ai) and the sign-in page that hands your session to the extension.
- Active tab: check the page you are on when you click the icon or press Ctrl+Shift+K.
- Storage: settings, counters and (if you sign in) sign-in keys, on your device.
- Context menus: "Check this link" and "Privacy Audit" in the right-click menu.
- Alarms: housekeeping on a timer: refresh sign-in, delete history older than 30 days, look for family warnings.
- Notifications: show family warnings.

Source code: github.com/AlexMos555/linkshield
Privacy policy: https://cleanway.ai/privacy-policy
```

### 2.2 Подробное описание — русский

<!-- field: ext.ru.description max=10000 -->
```text
Cleanway предупреждает о мошеннических и фишинговых сайтах до того, как вы введёте пароль или номер карты. Всё простыми словами — для вас и для ваших родителей.

ЧТО ДЕЛАЕТ
- Отмечает ссылки на страницах, которые вы открываете: зелёная галочка, жёлтое предупреждение или красный крестик, а при наведении — причина.
- Останавливает вас на опасной странице предупреждением во весь экран и объясняет почему — на вашем языке.
- Предупреждает о формах входа, которые отправляют пароль не на тот сайт, который вы видите, и о поддельных «окнах браузера», нарисованных внутри страницы.
- Сообщает, если пароль, который вы вводите, встречался в известных утечках данных.
- По желанию, выключено, пока вы не включите в настройках: проверяет письма, которые вы открываете в Gmail, Outlook и Yahoo Mail, и показывает короткую плашку: выглядит безопасно, подозрительно или похоже на мошенников.
- Проверка любой ссылки правой кнопкой мыши. Правой кнопкой по странице — «Проверка приватности»: трекеры, cookie и формы, которые просят личные данные. Проверка идёт в вашем браузере.
- Убирает из адресов распространённые метки слежки, например utm_ и fbclid.
- Семья: с аккаунтом члены семьи могут присылать друг другу зашифрованные сквозным шифрованием предупреждения об опасных сайтах.

ЧТО УХОДИТ ИЗ БРАУЗЕРА — ЧЕСТНО
- Имена сайтов. Чтобы проверить сайт, Cleanway отправляет на наш сервер только его имя (например, example.com) — не полный адрес, не содержимое страницы и не вашу историю. Так проверяются открытая страница и ссылки на ней, кроме известных официальных сайтов, которые расширение узнаёт само. Сервер проверяет имя, в том числе по внешним спискам опасных сайтов, например Google Safe Browsing.
- Письма — только если вы включили проверку почты. Она выключена, пока вы не включите в настройках «Проверять на фишинг письма, которые я открываю в Gmail, Outlook и Yahoo». Пока она включена, для каждого письма, которое вы открываете в Gmail, Outlook или Yahoo Mail, Cleanway отправляет на наш сервер тему, имя и адрес отправителя, адрес для ответа, текст, а также адрес и текст каждой ссылки (не HTML письма), чтобы проверить его на мошенничество. Письмо проверяется и не сохраняется. Выключите проверку в любой момент — и она сразу прекратится.
- Проверка пароля на утечки. Когда вы уходите из поля пароля, Cleanway отправляет только короткий фрагмент его хеша (первые 5 символов SHA-1), а не сам пароль. Сравнение идёт в вашем браузере.
- История проверок и счётчики остаются в браузере; история удаляется через 30 дней.
- Вход необязателен. Если вы войдёте через cleanway.ai, расширение хранит ключи входа в хранилище расширений браузера, этот браузер появляется как устройство в вашем аккаунте Cleanway (его можно там отвязать), а настройки сохраняются в аккаунт. «Выйти» в настройках удаляет ключи.
- Без рекламы и аналитики внутри расширения, и мы не продаём данные.

ЧЕГО CLEANWAY НЕ ОБЕЩАЕТ
Новые мошеннические сайты появляются каждый день, и ни один инструмент не ловит их все. Если что-то кажется странным — не вводите свои данные.

ЦЕНА
Бесплатно.

ЗАЧЕМ РАЗРЕШЕНИЯ
- «Просмотр и изменение всех ваших данных на всех сайтах»: Chrome пишет так, потому что скрипты Cleanway работают на каждой странице. Они нужны, чтобы отмечать ссылки, показывать предупреждение и следить за формами паролей там, где они есть. Они читают страницу внутри браузера; наружу уходит только то, что перечислено выше.
- Сайты Gmail, Outlook и Yahoo Mail (по желанию): запрашиваются, только когда вы включаете проверку почты, и возвращаются, когда вы её выключаете.
- Scripting: включает и выключает проверку почты; на почтовых сайтах она работает, только пока включена.
- cleanway.ai: наш сервер проверки (api.cleanway.ai) и страница входа, которая передаёт ваш вход расширению.
- Активная вкладка: проверить открытую страницу, когда вы нажимаете на значок или Ctrl+Shift+K.
- Хранилище: настройки, счётчики и (если вы вошли) ключи входа — на вашем устройстве.
- Контекстное меню: «Проверить ссылку в Cleanway» и «Проверка приватности» в меню правой кнопки.
- Будильники (alarms): служебные задачи по таймеру — обновить вход, удалить историю старше 30 дней, проверить семейные предупреждения.
- Уведомления: показывать семейные предупреждения.

Исходный код: github.com/AlexMos555/linkshield
Политика конфиденциальности: https://cleanway.ai/privacy-policy
```

### 2.3 Картинки (общие для всех трёх магазинов)

| Что | Файл |
|---|---|
| Иконка 128 × 128 | `extension/public/icons/icon128.png` |
| Малая промо-плитка 440 × 280 | `store-assets/browser-extension/en/promo-small-440x280.png` (ru: `…/ru/promo-small-440x280.png`) |
| Большая (marquee) 1400 × 560 | `store-assets/browser-extension/en/promo-marquee-1400x560.png` (ru: `…/ru/…`) |
| Логотип Edge 300 × 300 | `store-assets/browser-extension/edge-store-logo-300.png` |
| Скриншоты 1280 × 800 | TODO — не сняты; список кадров: `docs/CWS_SUBMISSION.md` §6 |

<!-- asset: extension/public/icons/icon128.png 128x128 -->
<!-- asset: store-assets/browser-extension/en/promo-small-440x280.png 440x280 opaque -->
<!-- asset: store-assets/browser-extension/ru/promo-small-440x280.png 440x280 opaque -->
<!-- asset: store-assets/browser-extension/en/promo-marquee-1400x560.png 1400x560 opaque -->
<!-- asset: store-assets/browser-extension/ru/promo-marquee-1400x560.png 1400x560 opaque -->
<!-- asset: store-assets/browser-extension/edge-store-logo-300.png 300x300 -->

Промо-плитки и картинка для Play нарисованы из иконки и названия скриптом `store-assets/render-graphics.mjs` (без элементов интерфейса); скриншоты — настоящие кадры, см. README рядом с ними.

---

## 3. Chrome Web Store — `dist/store-artifacts/cleanway-0.2.0-chrome.zip`

Консоль: chrome.google.com/webstore/devconsole → Items → **New item** → загрузить ZIP.

### 3.1 Store listing

| Поле | Значение |
|---|---|
| Description | §2.1 (английский) |
| Category | Productivity → Tools |
| Language | English; затем в выпадающем списке языков листинга — Russian, описание §2.2 и русские картинки |
| Store icon | `extension/public/icons/icon128.png` |
| Screenshots | §2.3 (до 5) |
| Small promo tile / Marquee | §2.3 |
| Official URL | `https://cleanway.ai` — только после подтверждения домена в Search Console (иначе пропустить) |
| Homepage URL | `https://cleanway.ai` |
| Support URL | `https://cleanway.ai/support` |
| Mature content | No |

### 3.2 Privacy

Single purpose:

<!-- field: cws.single_purpose max=1000 -->
```text
Cleanway warns users when a website or an open webmail message is a phishing or scam attempt, by scoring the page's domain (and, if the user opts in, the open message's content) with a local engine and the Cleanway backend.
```

Permission justification — по одному полю на разрешение:

<!-- field: cws.perm.activeTab max=1000 -->
```text
Reads the active tab's URL only when the user runs the "Check page" command or a context-menu action, to score that page.
```

<!-- field: cws.perm.storage max=1000 -->
```text
Stores user settings, local protection statistics, the opt-in webmail switch, sign-in tokens (if the user signs in), the random install ID and Family Hub key material in chrome.storage.local.
```

<!-- field: cws.perm.alarms max=1000 -->
```text
Runs periodic background jobs that must survive MV3 service-worker suspension: local history pruning (30 days), refreshing the sign-in before it expires, and the Family Hub notification poll.
```

<!-- field: cws.perm.contextMenus max=1000 -->
```text
Adds right-click items "Check this link with Cleanway" (links) and "Privacy Audit" (pages) so users can trigger a check on demand.
```

<!-- field: cws.perm.notifications max=1000 -->
```text
Shows OS notifications for Family Hub alerts (a family member's device blocked a dangerous site), with a click handler that opens the relevant page.
```

<!-- field: cws.perm.scripting max=1000 -->
```text
Registers the opt-in webmail scanner on Gmail, Outlook and Yahoo Mail only after the user switches it on in Settings and grants those sites, and unregisters it when they switch it off (scripting.registerContentScripts / unregisterContentScripts, plus executeScript into mail tabs already open). Nothing else is injected this way.
```

Host permission justification (одно поле на все хосты):

<!-- field: cws.host_permissions max=1000 -->
```text
Content scripts run on <all_urls> to mark links on the page, show the full-page warning on a dangerous site and watch password forms where they appear; they read the page inside the browser and send only host names for checks. https://api.cleanway.ai/* is the checking backend. https://*.cleanway.ai/* covers the sign-in page cleanway.ai/extension/connect that hands the user's session to the extension. https://mail.google.com/*, https://outlook.office.com/*, https://outlook.live.com/* and https://mail.yahoo.com/* are optional, requested only when the user switches on the webmail phishing scan in Settings, and released when it is switched off.
```

| Вопрос | Ответ |
|---|---|
| Are you using remote code? | **No** — фоновый service worker-модуль грузит только свои файлы через статические `import`; нет `eval`, `new Function`, внешних скриптов |

Data usage — отметить:

| Тип данных CWS | Отметить | Что именно |
|---|---|---|
| Personally identifiable information | Yes | email и ID аккаунта, если человек вошёл |
| Health information | No | — |
| Financial and payment information | No | оплата на сайте, не в расширении |
| Authentication information | Yes | первые 5 символов SHA-1 пароля (проверка утечек); токен входа |
| Personal communications | Yes | письма — только при включённой проверке почты |
| Location | No | — |
| Web history | Yes | имена сайтов (без пути и параметров) для проверки |
| User activity | Yes | счётчик заблокированных угроз (число), сайт из «Wrong result?» |
| Website content | Yes | текст и ссылки открытого письма — только при включённой проверке почты |

Отметить все три подтверждения: не продаём данные третьим лицам; не используем для целей вне единственного назначения; не используем для кредитоспособности.

Privacy policy URL:

```text
https://cleanway.ai/privacy-policy
```

### 3.3 Distribution

Payments: **Free**. Visibility: **Public**. Regions: **All regions**.

### 3.4 Test instructions (для проверяющего)

<!-- field: cws.test_instructions max=2000 -->
```text
No account is needed: every protection feature works signed out. After install, open any website: links get green, yellow or red marks, and the toolbar popup shows the verdict for the current page (Ctrl+Shift+K checks the page too). Right-click a link and choose "Check this link with Cleanway" to check it on demand. The webmail scan is off by default; to see it, open Settings, switch on "Scan emails I open in Gmail, Outlook and Yahoo for phishing" and grant the mail site Chrome asks for. Sign-in is optional, through a one-time code sent to an email address on cleanway.ai.
```

Потом **Submit for review**. Edge берёт те же ответы (§4), они должны совпадать слово в слово.

---

## 4. Microsoft Edge Add-ons — `dist/store-artifacts/cleanway-0.2.0-edge.zip`

Консоль: partner.microsoft.com/dashboard/microsoftedge → **Create new extension** → загрузить ZIP.

| Раздел → поле | Значение |
|---|---|
| Availability → Visibility | Public |
| Availability → Markets | All markets |
| Properties → Category | Productivity |
| Properties → Privacy policy requirements | Yes — `https://cleanway.ai/privacy-policy` |
| Properties → Website URL | `https://cleanway.ai` |
| Properties → Support contact details | `support@cleanway.ai` |
| Properties → Mature content | No |
| Store listings → English → Description | §2.1 |
| Store listings → English → Extension Store logo | `store-assets/browser-extension/edge-store-logo-300.png` |
| Store listings → English → Small / large promotional tile | §2.3 |
| Store listings → English → Screenshots | §2.3 |
| Store listings → English → Short description (если поле есть) | берётся из манифеста; иначе — первое предложение §2.1 |
| Store listings → Russian | Description §2.2, русские картинки §2.3 |

Search terms (до 7 штук на язык):

<!-- field: edge.search_terms.en max=200 -->
```text
phishing; scam protection; anti-phishing; safe browsing; link checker; password leak; fraud
```

<!-- field: edge.search_terms.ru max=200 -->
```text
фишинг; мошенники; защита от мошенников; проверка ссылок; безопасность; утечка паролей; обман
```

Submission options → **Notes for certification**:

<!-- field: edge.cert_notes max=2000 -->
```text
Same build and same permission justifications as our Chrome Web Store item. No account is needed to test: open any website and links get green, yellow or red marks; the toolbar popup shows the verdict for the current page. Permissions: activeTab (check the current page on request), storage (settings, counters, optional sign-in keys), alarms (history pruning, sign-in refresh, family alert poll), contextMenus ("Check this link with Cleanway", "Privacy Audit"), notifications (family alerts), scripting (registers the opt-in webmail scanner only while the user keeps it on). Content scripts on all sites mark links and show warnings; only host names are sent to api.cleanway.ai. Gmail, Outlook and Yahoo Mail hosts are optional and requested only from the webmail switch in Settings (off by default). Privacy policy: https://cleanway.ai/privacy-policy
```

Потом **Publish**.

---

## 5. Firefox Add-ons (AMO) — `dist/store-artifacts/cleanway-0.2.0-firefox.zip`

Консоль: addons.mozilla.org/developers → **Submit a New Add-on** → «On this site».

1. Загрузить ZIP. Платформы: **Firefox** — да, **Firefox for Android** — снять галочку (в манифесте нет `gecko_android`, на Android не проверено).
2. «Do you need to submit source code?» → **Yes** и загрузить `dist/store-artifacts/cleanway-0.2.0-firefox-source.zip`. Наш код не минифицирован, но в пакете две минифицированные сторонние библиотеки и один сгенерированный файл данных — проверяющие просят исходники в таких случаях.
3. Описание дополнения:

| Поле | Значение |
|---|---|
| Name | `Cleanway — Protection from scam links` (из манифеста) |
| Add-on URL | `cleanway` (если занято — `cleanway-scam-protection`) |
| Summary | ниже |
| Description | §2.1 |
| Categories | Privacy & Security |
| Support email / website | `support@cleanway.ai` / `https://cleanway.ai/support` |
| License | MIT License (как `LICENSE` в репозитории) |
| Privacy policy | «This add-on has a privacy policy» → текст ниже |

<!-- field: amo.en.summary max=250 -->
```text
Warns you about scam and phishing sites before you type a password or card number. Marks dangerous links, explains why in plain language, and sends only site names for checks, never full addresses.
```

Политика конфиденциальности для AMO (поле принимает текст):

<!-- field: amo.privacy_policy max=2000 -->
```text
Cleanway's full privacy policy: https://cleanway.ai/privacy-policy

In short: to check a site, the add-on sends only its host name (for example, example.com) to api.cleanway.ai — never the full address, the page content or your history. When you leave a password field, it sends the first 5 characters of the password's SHA-1 hash for a leak check; the match is made in the browser. Only if you switch on the webmail scan in Settings (off by default), it sends the subject, sender, reply-to, text and links of each email you open in Gmail, Outlook or Yahoo Mail for a phishing check; emails are not stored. Signing in is optional. No ads, no analytics, and we don't sell data.
```

4. Русская страница: Edit Product Page → сменить язык на «Русский» → Summary и Description:

<!-- field: amo.ru.summary max=250 -->
```text
Предупреждает о мошеннических и фишинговых сайтах до того, как вы введёте пароль или номер карты. Отмечает опасные ссылки, объясняет почему простыми словами и отправляет на проверку только имена сайтов, а не полные адреса.
```

5. Картинки: Edit Product Page → Images → Screenshots (§2.3, 1280 × 800); иконка берётся из пакета.
6. Notes to Reviewer:

<!-- field: amo.reviewer_notes max=3000 -->
```text
No account is needed to test: open any website and links get green, yellow or red marks; the toolbar popup shows the verdict for the current page. Webmail scanning is off by default and asks for the mail sites and Firefox's data-collection consent when switched on in Settings ("Scan emails I open in Gmail, Outlook and Yahoo for phishing").

Build: there is no bundler, minifier or transpiler. The add-on is the extension-firefox/ folder of the attached source archive, zipped as is by scripts/build-store-artifacts.sh; extension-firefox/src is a copy of packages/extension-core/src made by scripts/build-extensions.sh (rsync). To verify: unzip the uploaded package and run `diff -r <unzipped> extension-firefox` (only .DS_Store and overrides/ are excluded). Public repository: https://github.com/AlexMos555/linkshield

Generated file: src/utils/scorer-data.js is readable data written by scripts/build_extension_scorer_data.py from the repository's data files (comment at its top).

Third-party libraries, unmodified:
- src/utils/vendor/tweetnacl.min.js = tweetnacl 1.0.3, nacl-fast.min.js from the npm package (https://cdn.jsdelivr.net/npm/tweetnacl@1.0.3/nacl-fast.min.js), SHA-256 3ec535c004aeeb225785d8e93fb33bf99f52e399bd7dfc01969b5629baea5131.
- src/utils/vendor/qrcode-generator.min.js = qrcode-generator 1.4.4 as minified by jsDelivr (https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js; original source https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.js), SHA-256 bb2365e4902f4f84852cf4025e6f6a60325a682aeafa43fb63b7fc8f098d1ef2.
```

7. **Submit Version**. Проверка у Mozilla — люди, обычно 3–10 рабочих дней.

Архив исходников пересобирается одной командой (после изменения расширения и `build-store-artifacts.sh`):

```bash
git archive --format=zip -o dist/store-artifacts/cleanway-0.2.0-firefox-source.zip HEAD \
  extension-firefox packages/extension-core scripts/build-extensions.sh \
  scripts/build-store-artifacts.sh scripts/build_extension_scorer_data.py LICENSE
```

---

## 6. Opera add-ons (по желанию)

addons.opera.com/developer → Add → `dist/store-artifacts/cleanway-0.2.0-opera.zip`; Category: Productivity; описание §2.1/§2.2; скриншоты §2.3; Privacy policy URL — как выше. Отдельной анкеты нет.

---

## 7. Что остаётся только за вами — сводка

- [ ] Аккаунты и оплаты: Play (организация, $25, D-U-N-S), Chrome ($5, 2SV, статус trader), Partner Center, Mozilla (2FA).
- [ ] Рабочий ящик `support@cleanway.ai`.
- [ ] Play AAB с `EXPO_PUBLIC_DISTRIBUTION=play` + ключ RevenueCat; проверка `aapt2` на `BILLING` и отсутствие `AD_ID`.
- [ ] Видео для деклараций VPN и foreground service (§1.6) → YouTube Unlisted.
- [ ] Нажать «Submit» в каждой консоли; принять условия магазинов.
- [ ] Строка о цене в описаниях — когда подписки заработают в Play.
- [ ] После одобрения: ссылки магазинов в `landing/lib/install-urls.ts` и таблица статусов в `docs/STORES.md`.
