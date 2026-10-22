# Восстановление базы из внешней резервной копии

Каждую ночь `.github/workflows/db-backup.yml` кладёт зашифрованный (age)
`pg_dump` схем `public` и `auth` в бакет Cloudflare R2 `cleanway-db-backups`
(Cloudflare-аккаунт основателя, хранится 35 дней). Первый выбор при сбое —
собственные снимки Supabase; эта копия — на случай, когда сам Supabase
недоступен, проект заблокирован или скомпрометирован.

Переписано 2026-10-22: прежний порядок (сначала `public`, потом данные `auth`)
восстанавливал базу **без защиты**. Дамп снимается с `--no-privileges`, поэтому
в нём нет ни одного GRANT/REVOKE; новый проект Supabase по умолчанию выдаёт
ролям `anon` и `authenticated` все права на каждую восстановленную таблицу и
EXECUTE на каждую функцию — включая SECURITY DEFINER `register_device`,
`revoke_device`, `report_phone`. Так отменялся весь запрет миграций 022–025, и
снова оставался только RLS. Внешние ключи на `auth.users` (миграции 002, 019)
не создавались — в `auth.users` ещё не было строк, — а триггер регистрации
`on_auth_user_created` (010) не восстанавливался вовсе: он висит на
`auth.users`, а `auth` грузился только данными.

## Что нужно

- Ключ расшифровки: связка ключей macOS, запись **«Cleanway DB backup
  decryption key (age)»** на Mac основателя (копия должна быть в менеджере
  паролей). Открытая половина:
  `age1yf0z2az8yrxf3zm50psnzyqker94y66dwllvpxnxrew6lxatwuksf6njkn`.
- Доступ к Cloudflare (R2 → `cleanway-db-backups` → скачать самый новый
  `db/<дата>.dump.age`) или `wrangler r2 object get`.
- `age` и клиент PostgreSQL 17 (`pg_restore`, `psql`):
  `brew install age libpq` или `docker run --rm -it postgres:17` (age там —
  `apt-get install age`).
- Новый проект Supabase (регион EU Central, как у боевого) и строка
  подключения к его базе под пользователем `postgres` — ниже `$NEW_DB_URL`.
- Репозиторий на том коммите, который сейчас в production (миграции из него
  применяются на шаге 6).

## Шаги

1. **Скачать** самый новый объект, например `db/2026-10-15T01-17-04Z.dump.age`.
2. **Расшифровать:**
   ```bash
   security find-generic-password -s "Cleanway DB backup decryption key (age)" -w > /tmp/age.key
   age -d -i /tmp/age.key -o db.dump db/2026-10-15T01-17-04Z.dump.age
   rm -P /tmp/age.key
   ```
3. **Посмотреть:** `pg_restore --list db.dump | head` и сравнить версию схемы
   Auth в дампе и в новом проекте — данные `auth` ложатся только в такую же
   схему. Первая команда печатает самую новую миграцию Auth в дампе, вторая —
   в новом проекте (обе — 14 цифр, дата и время):
   ```bash
   pg_restore --data-only --schema=auth --table=schema_migrations -f - db.dump \
     | grep -E '^[0-9]{14}' | sort | tail -1
   psql "$NEW_DB_URL" -Atc "select max(version) from auth.schema_migrations;"
   ```
   Если в новом проекте версия новее — обычно это только добавленные колонки,
   восстановление пройдёт; если загрузка на шаге 4 падает на колонке — нужен
   проект со схемой Auth той же версии (поддержка Supabase).
4. **Сначала данные `auth`** (схема в новом проекте уже есть; без строк в
   `auth.users` не создадутся внешние ключи `public`). Таблицу
   `auth.schema_migrations` не трогаем — она у нового проекта своя:
   ```bash
   pg_restore --list db.dump | grep -E ' (TABLE DATA|SEQUENCE SET) auth ' \
     | grep -v ' schema_migrations ' > auth.list
   pg_restore --data-only --no-owner --no-privileges -L auth.list -f - db.dump \
     | psql "$NEW_DB_URL" --single-transaction -v ON_ERROR_STOP=1 \
         -c 'SET session_replication_role = replica' -f -
   ```
   `session_replication_role = replica` выключает триггеры, а с ними проверки
   внешних ключей, — так грузит данные и руководство Supabase по
   восстановлению. Без этого загрузка ломается **всегда**: дамп снят со схемой,
   а в таком дампе `pg_dump` ставит данные таблиц по алфавиту, не по внешним
   ключам — `identities`, `sessions`, `refresh_tokens` идут раньше `users`, их
   COPY падает, и они остаются пустыми (проверено на postgres:17 2026-10-22).
   Строки из дампа сами по себе согласованы, поэтому выключить проверку на
   время загрузки безопасно. Всё идёт одной транзакцией: при любой ошибке не
   загрузится ничего, и шаг можно повторить. Ошибка на колонке — см. шаг 3
   (схема Auth другой версии).
5. **Потом `public`** — схема и данные:
   ```bash
   pg_restore --no-owner --schema=public -d "$NEW_DB_URL" db.dump
   ```
   Допустима только одна, безвредная ошибка: `schema "public" already exists`.
   Любая другая — остановиться и разобраться.
6. **Обязательно: заново наложить запрет и триггер** (все шесть миграций
   идемпотентны — повторный запуск безопасен; 025 — последней):
   ```bash
   for f in 010_auto_create_user_records 017_audit_log_retention 022_account_devices \
            023_entitlements 024_store_purchases_revenuecat 025_lock_down_client_access; do
     psql "$NEW_DB_URL" -v ON_ERROR_STOP=1 -f "supabase/migrations/$f.sql" || break
   done
   ```
   017 создаст индекс журнала и закрытую функцию очистки, даже если в
   production её не применяли, — это безвредно.
   Это нужно и после восстановления дампа **с** правами: права в дампе
   записаны относительно значений по умолчанию, и лишние права, которые новый
   проект выдаёт `anon`/`authenticated` при создании таблиц, они не отнимают.
   `tests/test_restore_runbook.py` следит, чтобы каждая миграция, меняющая
   права или вешающая триггер на `auth`, была в этом списке.
7. **Проверить** (`psql "$NEW_DB_URL"`):
   ```sql
   -- а) ни одного права на таблицы у клиентов — ожидается 0 строк
   select c.relname, r.role
   from pg_class c join pg_namespace n on n.oid = c.relnamespace
   cross join (values ('anon'), ('authenticated')) r(role)
   where n.nspname = 'public' and c.relkind in ('r', 'v', 'm', 'p')
     and has_table_privilege(r.role, c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER');

   -- б) закрытые функции клиентам не вызвать — ожидается 0 строк
   select p.oid::regprocedure, r.role
   from pg_proc p join pg_namespace n on n.oid = p.pronamespace
   cross join (values ('anon'), ('authenticated')) r(role)
   where n.nspname = 'public'
     and p.proname in ('register_device', 'revoke_device', 'report_phone',
                       'handle_new_auth_user', 'purge_old_audit_log')
     and has_function_privilege(r.role, p.oid, 'EXECUTE');

   -- в) триггер регистрации на месте — ожидается 1 строка
   select tgname from pg_trigger
   where tgrelid = 'auth.users'::regclass and tgname = 'on_auth_user_created';

   -- г) внешние ключи на auth.users созданы — feedback_reports, brand_watchlist и др.
   select conrelid::regclass, conname from pg_constraint
   where contype = 'f' and confrelid = 'auth.users'::regclass;

   -- д) числа похожи на боевые; identities и sessions — не 0 (0 — значит,
   --    шаг 4 их не загрузил: без identities вход по почте ломается)
   select (select count(*) from auth.users) as auth_users,
          (select count(*) from auth.identities) as identities,
          (select count(*) from auth.sessions) as sessions,
          (select count(*) from public.users) as users,
          (select count(*) from public.entitlements) as entitlements;
   ```
   После проверки удалить расшифрованную копию: `rm -P db.dump auth.list`.
8. **Переключить сервисы** на новый проект: в Railway (`web`) —
   `SUPABASE_URL`, `SUPABASE_SECRET_KEY` / `SUPABASE_PUBLISHABLE_KEY` (у нового
   проекта свои ключи), задеплоить; обновить env мобильного приложения и
   лендинга; подключить почту входа (`bash scripts/wire-supabase-smtp.sh`,
   см. `sign-in-email.md`) и redirect URLs в Auth; затем сменить все ключи
   (`security-incident.md` → «Ротация ключей»). Сессии не переносятся:
   пользователи войдут заново.
9. `GET https://api.cleanway.ai/health/deep` → `"status":"ok"`,
   `"warnings":[]`.

## Учения

Раз в квартал: шаги 1–7 на самом новом объекте, в одноразовый проект
Supabase (на бесплатном тарифе можно держать два проекта) или в локальный
`supabase start`; после — удалить проект. Записать дату ниже. Копия, которую
ни разу не восстанавливали, — надежда, а не резервная копия.

| Дата | Объект | Результат |
|---|---|---|
| 2026-10-14 | первый запуск, `db/2026-10-14T16-32-17Z.dump.age` (194 946 Б) в R2; проверка на свежем дампе | шифрование → расшифровка ключом из связки → `pg_restore --list` 50 таблиц, побайтно равен исходному дампу. **Это не восстановление**: шаги 4–7 ещё ни разу не выполнялись |

## Чего пока нет

- **Восстановление ни разу не прогонялось целиком** — первая полная проверка
  за основателем (таблица выше).
- **Проверка копии в CI.** Ежемесячный job мог бы восстанавливать копию в
  контейнер `supabase/postgres` и выполнять запросы шага 7; нужен новый
  workflow (их правит только основатель — токен Claude не может пушить
  `.github/workflows/`).
- **Возраст копии** виден минутному монитору, если подключить ему R2
  (`ops/uptime-worker/README.md`, проверка `backup`).
