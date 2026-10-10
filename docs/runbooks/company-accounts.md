# Аккаунты магазинов на компанию

Решение основателя 2026-10-10: приложения в магазинах публикуются от имени компании, а не от личного имени.

- **Apple:** весь аккаунт разработчика (Team ID `29LQWL23VQ`) переводится с частного лица на организацию. Вместе с ним переходят Aevum, Easy — Meditate и Cleanway: Scam Protection. Приложения, отзывы, покупки, TestFlight, App ID и App Group остаются на месте; меняется продавец на странице App Store.
- **Google Play:** аккаунт сразу создаётся на организацию. Тип аккаунта потом не меняется; у организации нет требования о закрытом тесте «12 тестировщиков × 14 дней», которое есть у новых личных аккаунтов. Если у основателя есть личный аккаунт Play с приложениями, они переносятся в новый через запрос на перенос в Play Console.
- **Расширения:** в Chrome Web Store, Firefox и Edge издателем указывается компания; Chrome Web Store и Edge просят подтвердить юридические данные.

Аккаунт организации у Apple ещё и разрешает настоящий VPN (`NEPacketTunnelProvider`, App Review 5.4); частному лицу он запрещён. Текущему плану для iPhone VPN не нужен (`docs/IOS.md` §3.1).

## 1. Реквизиты (основатель, 2026-10-12)

Точно как в лицензии компании:

| Поле | Значение |
|---|---|
| Полное юридическое название и форма | _ждём_ |
| Страна, свободная зона или эмират | _ждём_ |
| Регистрационный номер или номер лицензии | _ждём_ |
| Юридический адрес | _ждём_ |
| D-U-N-S | _ждём; если нет — шаг 2_ |
| Должность основателя (директор или владелец) | _ждём_ |
| Рабочая почта на домене компании и телефон | _ждём_ |
| Сайт | `https://cleanway.ai` |

Паспортные данные и банковские реквизиты в чат и в репозиторий не попадают: основатель вводит их сам в формах Apple и Google.

ИП, торговая марка или филиал организацией не считаются: Apple и Google их не принимают.

## 2. D-U-N-S

1. developer.apple.com/enroll/duns-lookup — поиск компании в базе Dun & Bradstreet.
2. Если компании нет, там же подать заявку. Номер бесплатный, обычно около 5 рабочих дней; ещё около 2 рабочих дней, пока Apple его увидит.
3. Название и адрес в D-U-N-S должны совпадать с лицензией: Apple сверяет их при переводе.

## 3. Apple: перевод аккаунта на организацию

Пишет основатель, войдя тем Apple ID, на котором аккаунт:
developer.apple.com/contact → **Membership and Account** → **Program Enrollment** → описать запрос.

Текст (английский; поля в скобках заполнить):

> Hello,
>
> I would like to convert my Apple Developer Program membership (Team ID 29LQWL23VQ) from an individual to an organization membership, keeping the same team, apps and App Store Connect records.
>
> Organization legal name: [LEGAL NAME]
> D-U-N-S Number: [D-U-N-S]
> Registered address: [ADDRESS]
> Website: https://cleanway.ai
> My role: [Director / Owner], with legal authority to bind the organization to Apple's agreements.
> Work email: [name@company-domain]
> Phone: [PHONE]
>
> Thank you.

Дальше Apple присылает письмо или звонит для проверки полномочий, иногда просит документы компании. Обычно это занимает от нескольких дней до двух недель. TestFlight всё это время работает.

После перевода:
- основатель принимает соглашения в App Store Connect → Business: Paid Apps, банк и налоги уже на компанию;
- Claude создаёт подписки `cleanway.devices.monthly` и `.yearly` (`docs/IOS.md` §3.4), ключ In-App Purchase для RevenueCat и подключает App Store в RevenueCat (`docs/runbooks/revenuecat.md`).

## 4. Google Play: аккаунт организации

1. play.google.com/console/signup → тип **Organization**.
2. Данные компании, D-U-N-S, сайт, почта и телефон разработчика (покажутся на странице приложения). Регистрационный сбор $25.
3. Google проверяет организацию по D-U-N-S: обычно от нескольких дней до пары недель.
4. После проверки — шаги из `docs/PLAN.md` «От основателя для публикации»: загрузить наш ключ подписи как ключ приложения, создать подписки `cleanway.devices` и `cleanway.extra_device`, подключить RevenueCat. Закрытый тест на 12 человек × 14 дней не нужен.

## 5. Что не ждёт реквизитов

TestFlight, проверка на iPhone, скриншоты и тексты для App Store, App Privacy, заметки для проверки Apple. Всё это от продавца не зависит.
