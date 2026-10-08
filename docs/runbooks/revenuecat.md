# Runbook: покупки в Google Play и App Store через RevenueCat

Что настроить, чтобы приложение продавало тариф по устройствам через магазин,
а сервер видел покупку в аккаунте. Как это устроено в коде — раздел 11
`docs/ACCOUNTS_BILLING_PLAN.md`.

Источники (проверено 2026-10-08):
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

## 5. Приложение (для того, кто делает мобильную часть)

- Покупать только после входа: `Purchases.configure({ apiKey })` при старте,
  `Purchases.logIn(supabaseUserId)` после входа, `Purchases.logOut()` при выходе.
  Покупка без входа приходит с анонимным id — сервер её не выдаёт
  (лог `revenuecat_purchase_without_account`), пока человек не войдёт и не нажмёт
  «Восстановить покупки».
- Перед экраном оплаты: `GET /api/v1/me/entitlement`. Если `source` уже есть
  (`stripe`, `operator_ru` …) — не продавать, показать «у вас уже оплачено через …»
  и кнопку на `manage_url`.
- После покупки: `POST /api/v1/me/entitlement/refresh` (вебхук обычно успевает раньше,
  refresh просто гарантирует) и перерисовать экран по ответу.
- Кнопка «Управлять подпиской»: открыть `manage_url` из ответа.
- «Восстановить покупки»: `Purchases.restorePurchases()` → `POST /api/v1/me/entitlement/refresh`.
  Не чаще 10 раз в час на аккаунт (дальше 429).

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
- Удаление аккаунта Cleanway **не отменяет** подписку в Google Play — её отменяют в
  Play. Сервер пока не вызывает отмену через RevenueCat (не сделано).

## 9. App Store (позже)

- App Store Connect → группа подписок `Cleanway`: `cleanway.devices.monthly`,
  `cleanway.devices.yearly`; отдельная группа `Cleanway devices`:
  `cleanway.extra_device.monthly`, `.yearly` (иначе Apple считает добавку заменой тарифа).
  Эти id сервер уже знает.
- Ключ In-App Purchase (`.p8`) → RevenueCat; App Store Server Notifications V2 → URL из RevenueCat.
- Публичный ключ `appl_…` — в приложение. Вебхук и переменные сервера те же.
