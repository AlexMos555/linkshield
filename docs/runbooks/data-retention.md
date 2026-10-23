# Сроки хранения данных: что обещано и что это обеспечивает

Политика конфиденциальности (`docs/PRIVACY.md`, раздел «What we store, and
for how long»; публичная версия — раздел 16 `landing.privacy_policy` в
`packages/i18n-strings/src/`, 10 языков) обещает сроки хранения. Ниже — кто
каждый срок исполняет. Проверено 2026-10-21 по коду и по каталогу
production-базы (только чтение).

## Таблица

| Обещание | Чем обеспечено | Состояние до PR fix/data-retention |
|---|---|---|
| Аккаунт удаляется через 30 дней после запроса | `api/services/account_purge.py` (вызывается из `api/services/retention.py`) | **Не работало**: функция была, но её ничто не запускало (нет `api/routers/admin.py`, нет задачи в GitHub, нет pg_cron). Хуже: флаг `deleted:{id}` в Redis живёт 30 дней, после чего «удалённый» пользователь снова получал доступ |
| Журнал безопасности (`audit_log`) — 2 года | правило `audit_log_2y` | **Не работало**: SQL-функции `purge_old_audit_log` (миграция 017) в production **нет** — миграция 017 не применена; вызова тоже не было |
| Журнал входов Supabase Auth (`auth.audit_log_entries`: номер аккаунта, почта или телефон, действие, IP **как есть**, время — пишется при каждом входе, обновлении токена, выходе и действии через Admin API). Отдельного срока политика не называет (раздел 9: Supabase «может записывать IP входа в свой журнал безопасности»), поэтому — срок нашего журнала безопасности, 2 года (раздел 16) | правило `auth_audit_log_2y` — функция `purge_auth_audit_log` (миграция 027); при удалении аккаунта строки о нём удаляются сразу — `delete_auth_audit_log_for_users` из `account_purge.py` | **Не работало до PR fix/auth-log-retention**: строки не удалялись ни по сроку, ни при удалении аккаунта (схема `auth` недоступна через PostgREST), а удаление учётной записи через Admin API ещё и добавляло строку `user_deleted` с почтой. До применения миграции 027 — так и остаётся (см. шаги) |
| Недельные счётчики (`weekly_aggregates`) — 1 год | правило `weekly_aggregates_1y` | **Не работало** — удаления не было нигде |
| Семейные оповещения — до 30 дней | правила `family_alerts_expired`, `family_alerts_legacy_30d`; список оповещений больше не отдаёт просроченные (`api/routers/family.py`) | **Не работало**: `expires_at` записывался, но строки не удалялись и продолжали выдаваться |
| Приглашения в семью — до использования или 7 дней | правила `family_invites_expired`, `family_invites_redeemed` | **Не работало**: просроченное приглашение отклонялось, но строка (хэш кода + bcrypt PIN) оставалась навсегда |
| Жалобы «ошибка проверки» / «фишинговое письмо» (`feedback_reports`: домен сайта или отправителя, тип жалобы, номер аккаунта, если вошли) — 1 год | правило `feedback_reports_1y` (с 2026-10-22) | **Срока не было**: строки копились навсегда, а жалобы из дополнения Outlook ещё и несли в `comment` полный адрес отправителя и тему письма (теперь — только домен) |
| Белый список сайтов пользователя (Redis) — 1 год | TTL 365 дней (`api/routers/feedback.py`); при удалении аккаунта теперь стирается сразу | Работало (TTL); после удаления аккаунта оставался до года |
| Кэш проверок — до 24 ч; счётчики лимитов (IP, номер установки) — до часа; кэш DNS — до часа | TTL в Redis / в памяти | Работает |
| Флаг удаления — до удаления аккаунта | `users.deletion_requested_at` в базе; Redis только кэширует ответ (`deleted:{id}` — 30 дней, `notdeleted:{id}` — 5 минут), `api/services/auth.py::_deletion_requested`. Пока база недоступна, запрос без флага в Redis пропускается (в логах `deleted_check_failed_open`) — как и до этого PR; если недоступен и Redis — 503 | **Не работало до PR fix/account-lifecycle-and-data-rights**: через 30 дней флаг в Redis истекал, отсутствие флага читалось как «не удалён», и удалённый аккаунт снова получал доступ к API |
| Ночные резервные копии — 35 дней | правило жизненного цикла бакета R2 `cleanway-db-backups` (`ops/backup-sink/README.md`) | Настраивается в Cloudflare, из кода не проверить — сверить в дашборде R2 → бакет → Settings → Object lifecycle rules |
| Sentry — до 90 дней | настройки Sentry | Вне кода |
| История проверок в расширении — 30 дней | расширение, на устройстве | Вне сервера |
| Биллинг (РФ): номер телефона удаляется после 5 лет | `billing_purge_msisdn()` в `api/billing/migrations/002_…` | Биллинг выключен; запуска функции тоже нет — подключить, когда биллинг включат |

Не описаны в политике сроками (хранятся до удаления аккаунта, стираются
каскадом): `scam_analyses`, `user_settings`, `devices`, `entitlements`,
`brand_watchlist`. В `feedback_reports` при удалении аккаунта номер
аккаунта обнуляется (ON DELETE SET NULL), сама жалоба живёт до своего
срока в 1 год. `phone_reports` и `typosquat_alerts` не привязаны к
пользователю.

Удаление аккаунта (`api/services/account_purge.py`) кроме строк в базе и
учётной записи Supabase Auth удаляет клиента Stripe, клиента RevenueCat (если
задан `REVENUECAT_SECRET_API_KEY`) и ключи пользователя в Redis (белый список,
реферальный код и отметка, кэши); флаг удаления ставится ещё на час — пока
не истечёт токен, выданный до удаления. Организации, где человек —
администратор, удаляются перед ним: у `orgs.admin_user_id` нет ON DELETE
(миграция 026 добавляет каскад), и раньше один такой человек срывал удаление
всей пачки. После учётных записей Supabase Auth одним вызовом
`delete_auth_audit_log_for_users` удаляются строки журнала входов о всей
пачке — по `payload.actor_id` (действия самого человека) и по
`payload.traits.user_id` (действия над ним через Admin API, в том числе
строка `user_deleted` с почтой, которую пишет само удаление). Если на вызов
нет ответа (таймаут, 502/503/504) — пачка ждёт следующего прохода; любой
другой отказ (404 — миграция 027 не применена, 403, 500) повторился бы
каждый проход, поэтому удаление аккаунтов идёт дальше, в логе
`account_purge.auth_audit_delete_failed` (с номерами аккаунтов), в итоге —
`auth_audit_log_error`, а проход считается неуспешным (`accounts` в
`last_pass_failed`). Такие строки потом уйдут по сроку в 2 года; удалить
сразу — SQL Editor:
`select public.delete_auth_audit_log_for_users(array['<id>', '<id>']::uuid[]);`
Выгрузка данных по запросу — `docs/runbooks/data-requests.md`.

**`auth_audit_log_error: status_500`** (в логе
`account_purge.auth_audit_delete_failed` — `status: 500`) почти наверняка
значит, что журнал входов разросся: вызов просматривает его целиком, и
база отменила его по лимиту времени (код Postgres 57014, «canceling statement
due to statement timeout»). Миграция 027 даёт обеим функциям по 50 секунд
(без этого вызов через API получил бы 8 секунд — лимит Supabase для
`service_role`), а `account_purge.py` и `retention.py` ждут ответа 70 секунд,
поэтому слишком долгий вызов заканчивается именно этой ошибкой: аккаунты всё
равно удаляются, а строки журнала о них остаются. Это будет повторяться при
каждом удалении — прислать в чат, а пока удалить строки вручную: взять
номера из `user_ids` строки `account_purge.auth_audit_delete_failed` и
выполнить SQL выше в SQL Editor (у редактора свой лимит, до 60 секунд, а не
50 секунд функции). Если и там «canceling statement due to statement
timeout» — тот же запрос через прямое подключение к базе (Supabase →
Connect → Direct connection, `psql`), первой командой
`set statement_timeout = '10min';`. Та же причина у
`auth_audit_log_2y: status_500` в итоге прохода очистки; вручную —
`select public.purge_auth_audit_log(730, false);` тем же способом.

## Как работает очистка

`api/services/retention.py` — один проход по правилам: каждое — запрос
PostgREST `DELETE` с фильтром (без фильтра не отправляется никогда), под
серверным ключом. Повторный запуск безопасен. Режим задаёт переменная
`RETENTION_PURGE`:

- `off` — по умолчанию, ничего не запускается;
- `dry_run` — только считает, сколько строк удалилось бы, и пишет в лог
  `retention.pass_complete` (поля `tables`, `accounts_would_delete`);
- `on` — удаляет.

Журнал входов Supabase Auth лежит в схеме `auth`, которую PostgREST не
отдаёт, поэтому правило `auth_audit_log_2y` вызывает функцию миграции 027
(`/rest/v1/rpc/purge_auth_audit_log`, только `service_role`): в `on` —
`POST` с `p_dry_run: false` (удаляет), в `dry_run` — `GET` (PostgREST
выполняет GET в транзакции «только чтение», так что пробный проход ничего не
удалит, даже если бы попросил). Пока миграция 027 не применена, PostgREST
отвечает 404, и в итоге прохода — `auth_audit_log_2y: {"error":
"not_installed"}`; остальные правила работают как раньше.

Планировщик — сам процесс API (pg_cron в проекте не установлен, а workflow
GitHub менять в этом PR нельзя). Если режим не `off`, при старте API
запускается цикл: первый проход через 15 минут после старта, дальше каждые
6 часов. Замок в Redis (`retention:lock`, 30 мин) не даёт двум репликам
сделать один проход дважды.

Ручной запуск (Railway → сервис API → Shell):
`python -m api.services.retention --dry-run` (без `--dry-run` — удаляет).

## Шаги для основателя

1. **Supabase → SQL Editor** (роль `postgres`, как по умолчанию): выполнить
   целиком `supabase/migrations/027_auth_audit_log_retention.sql`. Миграция
   сначала проверяет, что `auth.audit_log_entries` есть и что роль может из
   неё читать и удалять; если нет — останавливается с понятной ошибкой и
   ничего не создаёт (прислать её в чат). Повторный запуск безопасен.
   Проверка — ожидается одно число, сколько строк старше 2 лет (сейчас
   обычно `0`):
   `select public.purge_auth_audit_log(730);` (без второго аргумента функция
   только считает). Затем один раз — строки журнала входов об аккаунтах,
   удалённых до этой миграции (ответ — сколько строк удалено; `0`, если
   таких не было):
   ```sql
   select public.delete_auth_audit_log_for_users(array(
     select distinct target_id::uuid from public.audit_log
     where action = 'account.hard_deleted' and target_kind = 'user'));
   ```
2. **Railway → сервис API → Variables**: `RETENTION_PURGE=dry_run`. Railway
   перезапустит сервис.
3. Через ~20 минут открыть логи Railway и найти `retention.pass_complete`.
   Посмотреть числа `would_delete` по таблицам (в том числе
   `auth_audit_log_2y`) и `accounts_would_delete` (сколько аккаунтов ждут
   удаления дольше 30 дней). Ошибки (`error`) — прислать в чат;
   `auth_audit_log_2y: not_installed` — шаг 1 не выполнен.
4. Если числа ожидаемые — `RETENTION_PURGE=on`. Первый проход через 15
   минут удалит всё накопившееся; в логе будут `retention.pass_complete` с
   полями `deleted` и `account_purge.complete` (поле `auth_audit_deleted` —
   сколько строк журнала входов ушло вместе с аккаунтами) — или
   `account_purge.no_candidates`, если ни один аккаунт не ждёт дольше 30 дней
   (это нормально). Признак успеха — `/health/deep` → `components.retention`:
   `mode: "on"`, `ok: true`.
5. По желанию — применить миграцию `supabase/migrations/017_audit_log_retention.sql`
   (индекс по `audit_log.created_at` ускоряет очистку журнала; функция из
   неё больше не нужна). Только версию после 2026-10-22: в прежней функция
   `purge_old_audit_log` оставалась доступной анонимам через `/rest/v1/rpc`
   (любой мог очистить журнал). Если 017 уже применяли раньше — выполнить в
   SQL Editor:
   `REVOKE ALL ON FUNCTION public.purge_old_audit_log(integer) FROM PUBLIC, anon, authenticated;`
6. Проверить в Cloudflare R2, что у бакета `cleanway-db-backups` есть
   правило «удалять через 35 дней».

Откат: `RETENTION_PURGE=off` — цикл больше не запускается. Функции миграции
027 откатывать не нужно (без вызова они ничего не делают); убрать их —
`drop function public.purge_auth_audit_log(integer, boolean),
public.delete_auth_audit_log_for_users(uuid[]);` (тогда журнал входов снова
перестанет очищаться).

## Проверка без логов

`GET https://api.cleanway.ai/health/deep` → `components.retention`:

- `mode` — что сейчас стоит в `RETENTION_PURGE` (`off` / `dry_run` / `on`);
- `last_ok_at`, `last_ok_mode` — когда проход последний раз прошёл без ошибок;
- `last_pass_at`, `last_pass_failed` — последний проход и какие правила в нём
  упали (`accounts` — удаление аккаунтов, в том числе когда аккаунты удалены,
  а их строки журнала входов — нет; `auth_audit_log_2y` — журнал входов
  Supabase Auth, до применения миграции 027 падает каждый проход).

`ok: true` только в режиме `on`, если успешный проход был не дольше ~13 ч
назад; иначе `error`: `off`, `dry_run`, `no_recent_pass` или
`redis_unavailable`. Это только для глаз: в `warnings` компонент не входит и
монитор из-за него не пишет. Чисел там нет (эндпоинт публичный) — они в
строке лога `retention.pass_complete`: с 2026-10-22 JSON-лог сохраняет
`tables`, `accounts_would_delete`, `accounts_deleted` и `failed` (раньше
выбрасывал).
