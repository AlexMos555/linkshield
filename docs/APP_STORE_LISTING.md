# App Store — тексты для «Cleanway: Scam Protection» (iOS)

Источник для App Store Connect → App Information и страницы версии. Тексты Google Play и RuStore живут в `docs/STORES.md` §6 и `docs/RUSTORE_SUBMISSION.md` §7: там Android, у iPhone защита устроена иначе.

Правила (`docs/IOS.md` §3.7, App Review 5.4):
- слова «VPN» в текстах и на скриншотах нет — только «DNS protection» / «защита DNS»;
- про SMS — «фильтрует мошеннические SMS от незнакомых номеров»; никогда «все» и ничего про iMessage;
- каждое утверждение соответствует коду: в DNS-защите имена сайтов уходят на наш сервер `dns.cleanway.ai`, текст SMS не покидает телефон, при проверке ссылки уходит только имя сайта.

Длины проверяет `scripts/check_app_store_listing.py` (лимиты Apple: название 30, подзаголовок 30, рекламный текст 170, описание 4000, ключевые слова 100 байт).

## English (U.S.) — основной язык

<!-- field: en.name max=30 -->
```text
Cleanway: Scam Protection
```

<!-- field: en.subtitle max=30 -->
```text
Block scam sites, check texts
```

<!-- field: en.promo max=170 -->
```text
Stops known scam sites from opening in every app, filters scam texts from unknown senders and checks a suspicious link before you tap it.
```

<!-- field: en.keywords max=100 -->
```text
phishing,scam,fraud,spam,sms filter,link checker,safe browsing,dns,security,qr,parents,safari
```

<!-- field: en.description max=4000 -->
```text
Cleanway protects your iPhone from scams. It stops known scam sites from opening, moves scam texts from unknown numbers to Junk and helps you check a suspicious link before you tap it. Simple to set up for yourself or for your parents.

WHAT IT PROTECTS YOU FROM
• Scam websites in every app. Turn on DNS protection once, and known scam and phishing sites won't open in Safari, in messengers or in any other app.
• Scam texts. The SMS filter checks texts from numbers that are not in your contacts and moves the ones that look like a scam to the Junk folder. The check happens on your iPhone and works without internet.
• Scam sites in Safari. The Safari extension warns you before a known scam page opens.
• Suspicious links. Paste a link or share it to Cleanway from any app, and Cleanway checks the site before you open it and explains the result in plain words.

SIMPLE FOR EVERYONE
• Step-by-step setup with clear explanations, no technical words.
• No account needed. Signing in with email is optional; it shows all your devices in one place.

HOW IT WORKS, HONESTLY
• DNS protection uses iPhone's built-in encrypted DNS setting. While it is on, your iPhone asks our server, dns.cleanway.ai, for the address of every site it opens. Known scam sites get no address, so they don't open; every other name is passed on to Cloudflare's DNS. We keep no record of who looked up what. You can switch it off in the app or in Settings at any time.
• It is not a VPN: your IP address does not change, and your pages and messages do not pass through Cleanway.
• The SMS filter sees only texts from unknown numbers, as iOS allows. It never sends a message anywhere. iMessage is not available to any filter app.
• When you check a link, only the site name (for example, example.com) goes to our server, never the rest of the address. The server checks it against sources that include outside lists of dangerous sites such as Google Safe Browsing.
• No ads, and we don't sell data.

WHAT CLEANWAY DOESN'T PROMISE
New scam sites and messages appear every day, and no app catches them all. If in doubt, don't open the link, never share codes from text messages, and call your bank on the number printed on your card.

Help: support@cleanway.ai
Privacy policy: cleanway.ai/privacy-policy
Terms: cleanway.ai/terms
```

<!-- field: en.whats_new max=4000 -->
```text
First release for iPhone: DNS protection against scam sites, a scam-text filter, a Safari extension and link checks.
```

## Русский

<!-- field: ru.name max=30 -->
```text
Cleanway: защита от мошенников
```

<!-- field: ru.subtitle max=30 -->
```text
Блокирует сайты и SMS-обман
```

<!-- field: ru.promo max=170 -->
```text
Не даёт открыть известные мошеннические сайты в любом приложении, убирает мошеннические SMS от незнакомых номеров и проверяет ссылку до того, как вы её откроете.
```

<!-- field: ru.keywords max=100 -->
```text
мошенники,фишинг,спам,смс,ссылка,обман,dns,scam,sms
```

<!-- field: ru.description max=4000 -->
```text
Cleanway защищает iPhone от мошенников. Не даёт открыть известные мошеннические сайты, убирает мошеннические SMS от незнакомых номеров в папку «Спам» и помогает проверить подозрительную ссылку до того, как вы её откроете. Легко настроить себе или родителям.

ОТ ЧЕГО ЗАЩИЩАЕТ
• Мошеннические сайты в любом приложении. Включите защиту DNS один раз — и известные мошеннические и фишинговые сайты не откроются ни в Safari, ни в мессенджерах, ни в других приложениях.
• Мошеннические SMS. Фильтр проверяет сообщения с номеров, которых нет в контактах, и переносит похожие на обман в папку «Спам». Проверка идёт на самом iPhone и работает без интернета.
• Мошеннические сайты в Safari. Расширение для Safari предупреждает до того, как откроется известная мошенническая страница.
• Подозрительные ссылки. Вставьте ссылку или поделитесь ею с Cleanway из любого приложения — Cleanway проверит сайт и простыми словами объяснит результат.

ПРОСТО ДЛЯ ВСЕХ
• Пошаговая настройка с понятными объяснениями, без технических слов.
• Аккаунт не нужен. Вход по почте — по желанию: он показывает все ваши устройства в одном месте.

КАК ЭТО РАБОТАЕТ — ЧЕСТНО
• Защита DNS использует встроенную в iPhone настройку зашифрованного DNS. Пока она включена, iPhone спрашивает у нашего сервера dns.cleanway.ai адрес каждого открываемого сайта. Известные мошеннические сайты адреса не получают и не открываются, остальные имена передаются в DNS Cloudflare. Мы не храним, кто какие сайты открывал. Выключить защиту можно в приложении или в Настройках в любой момент.
• Это не VPN: ваш IP-адрес не меняется, страницы и сообщения не проходят через Cleanway.
• Фильтр SMS видит только сообщения с незнакомых номеров — так устроен iOS. Он никуда не отправляет сообщения. iMessage недоступен ни одному приложению-фильтру.
• При проверке ссылки на наш сервер уходит только имя сайта (например, example.com), а не весь адрес. Сервер сверяет его с источниками, среди которых внешние списки опасных сайтов, например Google Safe Browsing.
• Без рекламы, мы не продаём данные.

ЧЕГО CLEANWAY НЕ ОБЕЩАЕТ
Новые мошеннические сайты и сообщения появляются каждый день, и ни одно приложение не ловит их все. Если сомневаетесь — не открывайте ссылку, никому не сообщайте коды из SMS и звоните в банк по номеру на карте.

Помощь: support@cleanway.ai
Политика конфиденциальности: cleanway.ai/privacy-policy
Условия: cleanway.ai/terms
```

<!-- field: ru.whats_new max=4000 -->
```text
Первая версия для iPhone: защита DNS от мошеннических сайтов, фильтр мошеннических SMS, расширение для Safari и проверка ссылок.
```

## Прочие поля App Store Connect

| Поле | Значение |
|---|---|
| Категория | Utilities (вторая — Productivity) |
| Возрастной рейтинг | 4+ (анкета: ничего из списка) |
| Privacy Policy URL | https://cleanway.ai/privacy-policy |
| Support URL | https://cleanway.ai/support |
| Marketing URL | https://cleanway.ai |
| Copyright | 2026 [юридическое название компании] — после перевода аккаунта (`docs/runbooks/company-accounts.md`) |
| Скриншоты (6,9″) | `mobile/assets/store/app-store/{en,ru}/01…05.png`, порядок и правила — README там же |
| App Privacy | `docs/IOS.md` §3.5 |
| Заметки для проверки | `docs/IOS.md` §3.6; демо-аккаунт нужен рабочий вход по почте (ключ Resend) |
