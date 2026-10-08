# Runbook: покупки в Google Play и App Store через RevenueCat

Что настроить, чтобы приложение продавало тариф по устройствам через магазин,
а сервер видел покупку в аккаунте. Как это устроено в коде — раздел 11
`docs/ACCOUNTS_BILLING_PLAN.md`.

Источники (проверено 2026-10-08):
- SDK для приложения — https://www.revenuecat.com/docs/getting-started/installation/expo и
  https://github.com/RevenueCat/react-native-purchases/blob/main/CHANGELOG.md (10.x: Play Billing
  Library 8, minSdk 23, RN ≥ 0.73)
- события и поля вебхука — https://www.revenuecat.com/docs/integrations/webhooks/event-types-and-fields
- доставка и повторы вебхука — https://www.revenuecat.com/docs/integrations/webhooks
- REST API `GET /v1/subscribers/{app_user_id}` — https://www.revenuecat.com/docs/api-v1/customers
- ключ сервисного аккаунта Play — https://www.revenuecat.com/docs/service-credentials/creating-play-service-credentials
- уведомления Google в реальном времени — https://www.revenuecat.com/docs/platform-resources/server-notifications/google-server-notifications

## Коротко: как идут деньги и данные

```
Приложение (вошли в аккаунт) ──покупка──▶ Google Play ──▶ RevenueCat
                                                         │
                                    вебхук POST /api/v1/webhooks/revenuecat
                                                         ▼
                                    API Cleanway → таблица entitlements
                                    (source=google_play, plan, period_end, device_limit)
```

- В RevenueCat приложение входит **id аккаунта Supabase** (`Purchases.logIn(user.id)`),
  поэтому каждое событие сразу привязано к аккаунту.
- «Восстановить покупки»: приложение вызывает `Purchases.restorePurchases()`, затем
  `POST /api/v1/me/entitlement/refresh` — сервер сам перечитывает подписки из RevenueCat.
- Двойная оплата: оплата на сайте (Stripe) отказывает, если у аккаунта уже есть
  действующий тариф из Google Play; `GET /api/v1/me/entitlement` отдаёт `source` и
  `manage_url` («вы платите через Google Play — управлять там»).

## 1. Google Play Console

Нужен хотя бы один загруженный билд с библиотекой оплаты (react-native-purchases
добавляет её сама) — до этого Play не даёт создавать подписки. Достаточно
внутреннего тестирования.

**Монетизация → Товары → Подписки → Создать подписку.** Создайте две подписки:

| ID подписки | Базовые планы (ID → период) | Что продаёт |
|---|---|---|
| `cleanway.devices` | `monthly` → 1 месяц, `yearly` → 1 год | тариф: без ограничений на 3 устройствах |
| `cleanway.extra_device` | `monthly` → 1 месяц, `yearly` → 1 год | +1 устройство к тарифу |

В RevenueCat они придут как `cleanway.devices:monthly`, `cleanway.devices:yearly`,
`cleanway.extra_device:monthly`, `cleanway.extra_device:yearly` — сервер их уже знает
(`api/services/store_products.py`), отдельной настройки не нужно.

- Цены — как в разделе 10 плана: месяц $0,99, год $9,99; доп. устройство $0,49 / $4,99.
  Play сам пересчитает в местные валюты; для стран уровней 3–4 поправьте годовую цену
  вручную ($6,99 / $4,99 и $3,49 / $2,49 за доп. устройство).
- Пробный период: предложение (offer) к базовому плану, «Бесплатный пробный период 7 дней»,
  только для новых подписчиков.
- Активируйте базовые планы — неактивный план купить нельзя.
- Одну подписку Play нельзя купить дважды одновременно, поэтому «+1 устройство»
  покупается один раз. Если понадобится «+2», «+3» — создайте отдельные подписки
  (например `cleanway.extra_devices_2`) и добавьте их в `REVENUECAT_PRODUCTS`
  (см. «Переменные окружения»).

**Тестировщики:** Настройки → Лицензионное тестирование → добавьте свои Google-аккаунты.
Их покупки бесплатные, приходят как `environment: SANDBOX`, месячная подписка
продлевается каждые несколько минут.

## 2. Ключ сервисного аккаунта (чтобы RevenueCat проверял покупки)

1. Google Cloud Console → проект (можно новый) → включить **Google Play Android
   Developer API**, **Google Play Developer Reporting API** и **Cloud Pub/Sub**
   (для уведомлений в реальном времени).
2. IAM → Сервисные аккаунты → Создать (например `revenuecat`) → Ключи → Добавить ключ → JSON.
3. Play Console → Пользователи и разрешения → Пригласить пользователя → email сервисного
   аккаунта → разрешения аккаунта: «Просмотр информации о приложении и скачивание
   массовых отчётов (только чтение)», «Просмотр финансовых данных, заказов и ответов на
   опрос об отмене», «Управление заказами и подписками», «Управление присутствием в магазине».
4. JSON загрузить в RevenueCat: приложение Play Store → Service account credentials JSON.
   Google активирует ключ до 36 часов — статус «Valid credentials» в RevenueCat.

**Уведомления в реальном времени** (без них окончание подписки доходит с опозданием
около часа): RevenueCat → настройки приложения Google Play → «Connect to Google» →
скопировать id топика Pub/Sub → Play Console → Монетизация → Настройка монетизации →
Уведомления разработчика в реальном времени → вставить id топика, содержимое: подписки,
отменённые покупки и все разовые товары → сохранить → «Отправить тестовое уведомление».
В RevenueCat появится «Last received». Если тест не проходит — дать
`google-play-developer-notifications@system.gserviceaccount.com` роль Pub/Sub Publisher
на этот топик.

## 3. RevenueCat

1. Проект `Cleanway` → добавить приложение **Play Store**, package `ai.cleanway.app`.
2. **Products** → импортировать подписки из Play (4 продукта выше).
3. **Entitlements** → `unlimited`, прикрепить `cleanway.devices:monthly` и
   `cleanway.devices:yearly`. Отдельно `extra_device` с двумя продуктами
   `cleanway.extra_device:*`. Сервер на id entitlement не смотрит — они нужны
   приложению, чтобы мгновенно показать «оплачено».
4. **Offerings** → `default` (текущий): пакет `$rc_monthly` → `cleanway.devices:monthly`,
   `$rc_annual` → `cleanway.devices:yearly`. По желанию offering `extra_device` для
   кнопки «добавить устройство».
5. **Project settings → General → Transfer behavior**: оставить «Transfer to new App
   User ID» (по умолчанию). Тогда «Восстановить покупки» под другим email переносит
   подписку на этот аккаунт (сервер обрабатывает событие `TRANSFER`).
6. **API keys**:
   - публичный ключ Play (`goog_…`) — в приложение (`EXPO_PUBLIC_REVENUECAT_ANDROID_KEY`),
     не на сервер;
   - **секретный ключ** (`sk_…`, API v1) — на сервер, `REVENUECAT_SECRET_API_KEY`.
7. **Integrations → Webhooks → Add**:
   - URL: `https://<домен API>/api/v1/webhooks/revenuecat`
   - Authorization header value: длинная случайная строка (`openssl rand -hex 32`),
     та же — в `REVENUECAT_WEBHOOK_AUTH`. Сервер сравнивает заголовок целиком
     (принимает и вариант с `Bearer ` спереди).
   - Environment: Production (для стенда — отдельный вебхук на стенд с Sandbox).
   - Events: все.
   - «Send test event» → в логах `revenuecat_webhook_received`, ответ 200
     `{"result": "ignored"}`.

## 4. Сервер (Railway)

1. **Применить миграцию** `supabase/migrations/024_store_purchases_revenuecat.sql`
   (после 022 и 023). Без неё вебхук отвечает 500/503 и RevenueCat повторит позже —
   до 5 раз за ~2,5 часа, потом событие можно переотправить кнопкой Retry в RevenueCat.
2. Переменные окружения:

| Переменная | Значение | Зачем |
|---|---|---|
| `REVENUECAT_WEBHOOK_AUTH` | случайная строка ≥ 32 символов | проверка вебхука; пусто → вебхук 503, ничего не выдаётся |
| `REVENUECAT_SECRET_API_KEY` | `sk_…` | «Восстановить покупки», синхронизация после `TRANSFER`; пусто → `/refresh` отвечает 503 `store_sync_unavailable` |
| `REVENUECAT_PRODUCTS` | пусто (или JSON) | дополнительные продукты: `{"cleanway.extra_devices_2": {"extra_devices": 2}}`; с `"plan": "personal"` — тариф, без `plan` — добавка устройств |
| `REVENUECAT_ACCEPT_SANDBOX` | `false` | `true` — тестовые покупки дают тариф (стенд или пока тестируете сами) |
| `GOOGLE_PLAY_PACKAGE_NAME` | `ai.cleanway.app` | ссылка «управлять подпиской» в Google Play |

## 5. Приложение (сборка Google Play)

Сделано в `feat/play-billing-app`: `react-native-purchases` 10.11 (RevenueCat SDK; RN ≥ 0.73,
Kotlin ≥ 1.8, Play Billing Library 8; работает в dev/prebuild-сборках, не в Expo Go).
Код: `mobile/src/services/store-billing.ts` (вызовы SDK), `mobile/src/utils/store-billing.ts`
(чистая логика, тест `mobile/scripts/test-store-billing.mjs` в CI), экран
`mobile/app/paywall.tsx` + `mobile/src/components/paywall/StorePlans.tsx`.

### 5.1 Переменные сборки

| Переменная | Значение | Что делает |
|---|---|---|
| `EXPO_PUBLIC_DISTRIBUTION` | `play` | Сборка для Google Play: платить можно только через Google Play, нигде нет ссылки на оплату на сайте, нет баннера «скачайте новую версию». **Задать на всю сборку** (prebuild, gradle и JS-бандл — `mobile/.env` или профиль EAS): по ней же `mobile/react-native.config.js` решает, подключать ли нативную часть SDK. В сборке `site` (APK с сайта) и `rustore` SDK нет ни в JS-бандле, ни в APK, и нет разрешения `com.android.vending.BILLING`. |
| `EXPO_PUBLIC_REVENUECAT_ANDROID_KEY` | `goog_…` | Публичный ключ приложения Play Store в RevenueCat (Project settings → API keys). Нет ключа → экран оплаты пишет «Оплата в приложении скоро появится», ничего не падает. Секретный `sk_…` или ключ App Store (`appl_…`) приложение не принимает — тоже «скоро». |
| `EXPO_PUBLIC_FREEMIUM_ENABLED` | как раньше | Дневной лимит проверок. С покупкой не связан: экран оплаты открывается и из «Настройки → Тариф». |

Проверить готовую сборку: `aapt2 dump permissions app-release.apk | grep BILLING` — есть в
`play`, нет в `site` / `rustore`.

⚠️ **Сменили `EXPO_PUBLIC_DISTRIBUTION` — пересоздайте `android/`** (`CI=1 npx expo prebuild -p
android --clean`, как в `docs/RUSTORE_SUBMISSION.md` §2). Gradle кеширует список нативных
модулей (`android/build/generated/autolinking/autolinking.json`) и пересчитывает его только при
изменении `package.json` / `package-lock.json` / `react-native.config.js`, но не переменных
окружения. Иначе получится, например, APK для сайта с разрешением BILLING или сборка Play без
нативной части SDK (тогда экран оплаты честно пишет «скоро», но продавать не будет).

### 5.2 Как это работает в приложении

- **Вход.** Платить можно только с аккаунтом. Без входа кнопка «Войдите, чтобы оформить» ведёт
  на вход, после входа покупка продолжается сама (Google Play всё равно показывает своё окно
  подтверждения). Если аккаунт уже оплачен (любым способом) — экран пишет «подписка активна» и
  где оплачено, продавать второй раз не предлагает.
- **RevenueCat знает человека по id аккаунта Supabase** (`sub` из токена). SDK конфигурируется
  с этим id (`appUserID`) или переходит на него через `Purchases.logIn(id)`; при любом выходе из
  аккаунта (Настройки, экран аккаунта, удаление аккаунта, отвязка устройства, отказ в
  обновлении токена) — `Purchases.logOut()`. Покупка без id аккаунта не начинается.
- **Когда SDK обращается к RevenueCat:** когда открыт экран оплаты (загрузка цен; до входа — под
  анонимным id), при покупке и «Восстановить покупки», и при запуске приложения — только если на
  этом телефоне уже начинали покупку (чтобы завершилась отложенная оплата). Остальным — ни
  одного запроса.
- **Цены** — только из Google Play: offering `default`, пакеты месяц / год продукта
  `cleanway.devices` (`$rc_monthly` / `$rc_annual`, иначе по типу пакета или id базового плана).
  «+1 устройство» как тариф не продаётся, даже если его по ошибке прикрепили к `$rc_monthly`.
  У годового плана — «выгода N %» относительно 12 месяцев (если ≥ 5 % и валюта та же).
- **После покупки:** `POST /api/v1/me/entitlement/refresh`, ответ сохраняется в кеш тарифа
  (счётчики сразу видят «оплачено»). Если сервер ещё не видит покупку — «Оплата прошла, тариф
  включится в течение минуты — если нет, нажмите „Восстановить“».
- **Ошибки (10 языков):** отмена — молча; медленная оплата (`PAYMENT_PENDING`) — «платёж ждёт
  подтверждения»; уже куплено (`PRODUCT_ALREADY_PURCHASED`, `RECEIPT_ALREADY_IN_USE`) —
  приложение само делает «Восстановить покупки», иначе подсказывает нажать его; нет сети,
  покупки запрещены (родительский контроль), товар недоступен, сбой Google Play, другая покупка
  ещё идёт — каждое своей фразой.
- **«Восстановить покупки»** — на экране оплаты и на экране аккаунта: `Purchases.restorePurchases()`
  → `POST …/refresh`. Если Google Play видит подписку, а сервер ещё нет — «тариф включится в
  течение минуты».
- **«Управлять подпиской»** (экран аккаунта и экран оплаты, когда оплачено) открывает
  `manage_url` из `GET /api/v1/me/entitlement`. Сборка магазина открывает только страницу
  магазина (`play.google.com`, `apps.apple.com`); для оплаты на сайте пишет «Оплачено на
  cleanway.ai» без ссылки.
- **Удаление аккаунта** (§8): если тариф оплачен через Google Play, перед подтверждением —
  «Сначала отмените подписку в Google Play» с кнопками «Открыть Google Play» / «Всё равно
  удалить» / «Отмена». Google не даёт приложению отменить подписку за человека.

### 5.3 Тестирование: лицензионные тестировщики и внутреннее тестирование

1. **Play Console → Настройки → Лицензионное тестирование:** добавить Google-аккаунты
   тестировщиков (список адресов), ответ лицензии `RESPOND_NORMALLY`. Покупки этих аккаунтов
   бесплатные (тестовые карты), месячная подписка продлевается каждые 5 минут, годовая — каждые
   30 минут, после 6 продлений отменяется сама.
2. Собрать AAB с `EXPO_PUBLIC_DISTRIBUTION=play` и ключом `goog_…`, подписать ключом загрузки
   (`docs/RUSTORE_SUBMISSION.md` §1–2), загрузить в **Тестирование → Внутреннее тестирование**,
   добавить туда тот же список тестировщиков. До первой загрузки сборки с библиотекой оплаты
   Play не даёт создать подписки (§1) — значит, порядок: загрузить сборку → создать подписки →
   активировать базовые планы → настроить RevenueCat (§3).
3. На телефоне тестировщика: открыть ссылку-приглашение внутреннего теста, установить
   приложение **из Google Play** (на телефоне должен быть вход в Play именно под аккаунтом
   тестировщика). Сборку, поставленную мимо Play, для покупок не используйте — Play
   проверяет, что приложение установлено из магазина и подписано тем же ключом.
4. Сервер: `REVENUECAT_ACCEPT_SANDBOX=true` на время тестов (или стенд с отдельным вебхуком),
   иначе тестовые покупки записываются, но тариф не дают. В RevenueCat — переключатель
   «Sandbox data», чтобы видеть тестовых покупателей.
5. Что пройти:
   - без входа открыть экран оплаты → видны цены из Play в местной валюте; «Войдите» → вход →
     сразу окно Google Play;
   - месячная покупка картой «Test card, always approves» → «подписка активна», в Аккаунте
     «Оплачено в Google Play», «Управлять подпиской» открывает страницу Play;
   - «Slow test card, approves after a few minutes» → «платёж ждёт подтверждения»; через
     несколько минут перезапустить приложение — тариф включился (SDK стартует сам, потому что
     покупку начинали);
   - «Slow test card, declines after a few minutes» → тариф не включается;
   - закрыть окно Play → без сообщения;
   - второй телефон / переустановка, тот же аккаунт → «Восстановить покупки»;
   - другой аккаунт Cleanway на том же Google-аккаунте → покупка отвечает «уже куплено» и
     переносит подписку (событие `TRANSFER` в логах сервера);
   - отмена в Play → тариф действует до конца периода; удаление аккаунта → вопрос про Play;
   - выход из аккаунта → следующая покупка уже под другим id (в RevenueCat видно `logOut`).

## 6. Проверка после настройки

1. Тестировщик входит в приложение, покупает месячный тариф.
2. В логах: `revenuecat_webhook_received` (type `INITIAL_PURCHASE`), без ошибок.
3. `GET /api/v1/me/entitlement` → `source: google_play`, `device_limit: 3`,
   `manage_url` на Google Play.
4. Отмена подписки в Play → событие `CANCELLATION`, тариф действует до конца периода;
   после окончания — `EXPIRATION`, тариф `free`.
5. Покупка «+1 устройство» → `device_limit: 4`.

## 7. Что смотреть в логах и Sentry

| Событие в логе | Что значит | Что делать |
|---|---|---|
| `revenuecat_webhook_unauthorized` | заголовок не совпал | сверить `REVENUECAT_WEBHOOK_AUTH` и значение в RevenueCat |
| `revenuecat_webhook_failed` | запись в базу не прошла, ответ 500 | RevenueCat повторит; если повторы кончились — Retry в RevenueCat |
| `revenuecat_purchase_without_account` | покупка с анонимным id | человек должен войти и нажать «Восстановить покупки» |
| `revenuecat_unknown_product` | продукт не из списка | добавить его в `REVENUECAT_PRODUCTS`, затем Retry события в RevenueCat (оно не помечено обработанным) или «Восстановить покупки» |
| `subscription_duplicate_detected` | купил в Play, уже платя иначе | вернуть деньги за одну из подписок |
| `revenuecat_event_stale` | старое событие пришло после нового | ничего, так и задумано |

Журнал аудита: `subscription.store_event`, `subscription.store_transferred`,
`subscription.store_unknown_product`, `subscription.duplicate_detected`.

## 8. Возвраты и удаление аккаунта

- Возврат лучше делать в RevenueCat (карточка клиента → Refund): придёт `CANCELLATION`
  с причиной `CUSTOMER_SUPPORT`, доступ закрывается сразу.
- Удаление аккаунта Cleanway **не отменяет** подписку в Google Play — её отменяет только
  сам человек, в Play (Google не даёт приложению отменить подписку за него). Поэтому
  приложение перед удалением спрашивает: если тариф оплачен через Google Play (или App
  Store), показывает «Сначала отмените подписку в Google Play» с кнопкой, открывающей
  страницу подписок Play (`manage_url`, иначе
  `https://play.google.com/store/account/subscriptions?package=ai.cleanway.app`), и
  «Всё равно удалить». Код: `mobile/src/services/account-actions.ts`.
- Сервер сам отмену через RevenueCat не вызывает. Если человек удалил аккаунт, не отменив
  подписку, и пишет в поддержку — вернуть деньги в RevenueCat (Refund), это закрывает и
  подписку.

## 9. App Store (позже)

- App Store Connect → группа подписок `Cleanway`: `cleanway.devices.monthly`,
  `cleanway.devices.yearly`; отдельная группа `Cleanway devices`:
  `cleanway.extra_device.monthly`, `.yearly` (иначе Apple считает добавку заменой тарифа).
  Эти id сервер уже знает.
- Ключ In-App Purchase (`.p8`) → RevenueCat; App Store Server Notifications V2 → URL из RevenueCat.
- Публичный ключ `appl_…` — в приложение. Вебхук и переменные сервера те же.
