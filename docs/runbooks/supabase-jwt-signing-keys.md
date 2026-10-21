# Supabase: ключи подписи JWT и отзыв legacy-секрета

Проект Supabase `bpyqgzzclsbfvxthyfsf` подписывает токены пользователей
**асимметричным ключом ES256** (в JWKS: `https://bpyqgzzclsbfvxthyfsf.supabase.co/auth/v1/.well-known/jwks.json`,
статус `in_use`). Старый общий секрет HS256 (`SUPABASE_JWT_SECRET`) — в статусе
`previously_used`: Supabase всё ещё принимает подписанные им токены, поэтому
любой, у кого есть этот секрет, может подделать токен для любого пользователя.

## Как API проверяет токены (с PR fix/jwt-jwks-es256)

`api/services/auth.py`:

- ключи берутся из JWKS проекта (`<SUPABASE_URL>/auth/v1/.well-known/jwks.json`),
  кэш 10 минут в процессе; неизвестный `kid` → один повторный запрос JWKS
  (не чаще раза в 30 с);
- принимаются только `ES256` / `RS256`; проверяются подпись, `exp`, `iat`,
  `aud == "authenticated"`, `iss == <SUPABASE_URL>/auth/v1`, наличие `sub`;
- токены HS256 **отклоняются**. Аварийный флаг `SUPABASE_ALLOW_LEGACY_HS256=1`
  снова пускает их (issuer и audience всё равно проверяются) — включать только
  если что-то сломалось и нужно время; по умолчанию выключен;
- JWKS недоступен и ключей в кэше нет → `503 {"code": "auth_unavailable"}`
  (не 500); если ключи уже были — работаем на последних известных;
- `POST /api/v1/auth/extension-session` и `DELETE /api/v1/user/account`
  требуют свежий токен (`iat` не старше 10 минут), иначе
  `401 {"code": "reauth_required"}`. Приложение и сайт в ответ обновляют
  сессию и повторяют запрос один раз. После удаления аккаунта API завершает
  все сессии пользователя (`POST /auth/v1/logout?scope=global` с токеном
  пользователя).

## HMAC-ключи, которые раньше были legacy-секретом

`SUPABASE_JWT_SECRET` ещё использовался как HMAC-ключ:

| Где | Новая переменная | Что будет при смене |
|-----|------------------|---------------------|
| Ссылки «отписаться» в письмах (`api/routers/email_unsubscribe.py`) | `UNSUBSCRIBE_HMAC_KEY` | Новые ссылки подписываются новым ключом; старые (подписанные legacy-секретом) работают, пока `SUPABASE_JWT_SECRET` задан — их срок 90 дней |
| Хэш IP в журнале аудита (`api/services/audit_log.py`) | `AUDIT_IP_HASH_KEY` | Хэши IP в новых строках не совпадут со старыми (сопоставление «тот же IP» до/после смены теряется — это допустимо) |

Пока новые переменные не заданы, используется `SUPABASE_JWT_SECRET` — ничего
не ломается.

## Какой ключ API использует бэкенд (с PR feat/supabase-secret-key)

Все обращения API к Supabase (PostgREST, Auth admin, вызовы RPC, задача
Watchtower) идут через `api/services/supabase_keys.py`:

| Назначение | Переменная (новая, приоритетная) | Запасная (legacy) |
|------------|----------------------------------|-------------------|
| Серверный ключ (обходит RLS) | `SUPABASE_SECRET_KEY` = `sb_secret_…` | `SUPABASE_SERVICE_KEY` (service_role JWT) |
| Публичный ключ (`/auth/v1/verify`, `/logout`, проверка `/health/deep`) | `SUPABASE_PUBLISHABLE_KEY` = `sb_publishable_…` | `SUPABASE_ANON_KEY` |

- Новые ключи — **не JWT**. Бэкенд отправляет их только в заголовке
  `apikey` и **не** кладёт в `Authorization: Bearer` (Supabase принимает их
  там лишь если значение совпадает с `apikey` и советует заголовок не
  заполнять). Legacy JWT-ключи по-прежнему уходят и в `apikey`, и в `Bearer`.
- Заголовки строятся по виду ключа, а не по имени переменной: значение
  `sb_secret_…`, вставленное в старую `SUPABASE_SERVICE_KEY`, тоже работает.
- При старте API проверяет ключи и **не запускается** (в любом окружении),
  если: в `SUPABASE_SECRET_KEY` не `sb_secret_…` (например, publishable);
  в `SUPABASE_SERVICE_KEY` публичный ключ (publishable или anon JWT);
  в `SUPABASE_PUBLISHABLE_KEY` не `sb_publishable_…`; в `SUPABASE_ANON_KEY`
  серверный ключ. В staging/production нужен хотя бы один серверный ключ;
  если это ещё legacy service_role — в логах предупреждение
  `supabase_server_key is the legacy service_role key`.
- `/health/deep` → `components.supabase_server_key` (информационно, не
  будит дежурного): `{"ok": true, "kind": "secret", "status": 200}` значит,
  что серверный ключ — новый и Auth admin API принимает его как
  service_role (запрос `GET /auth/v1/admin/users?per_page=1`, ответ не
  сохраняется). `kind: "legacy_service_role"` — бэкенд всё ещё на старом
  ключе. Сам ключ нигде не выводится.

## Шаги для основателя (по порядку)

1. **Railway → сервис API → Variables** — добавить две переменные, каждая —
   новая случайная строка (64+ символа; например `openssl rand -hex 48`):
   - `UNSUBSCRIBE_HMAC_KEY`
   - `AUDIT_IP_HASH_KEY`

   Railway сам перезапустит сервис. Проверка: `https://api.cleanway.ai/health` — ok.
2. **Создать новые ключи.** Supabase → Project Settings → **API Keys** →
   вкладка «Publishable and secret API keys»: если ключей ещё нет — *Create
   new API keys*. Получится `sb_publishable_…` (default) и `sb_secret_…`
   (default). Старые anon/service_role при этом продолжают работать.
   Секретный ключ можно открыть только кнопкой «показать» — копировать
   его сразу в Railway, никуда больше (ни в чат, ни в код).
3. **Railway → сервис API → Variables** — добавить:
   - `SUPABASE_SECRET_KEY` = `sb_secret_…`;
   - `SUPABASE_PUBLISHABLE_KEY` = `sb_publishable_…`.

   Старые `SUPABASE_SERVICE_KEY` / `SUPABASE_ANON_KEY` пока **не удалять** —
   это откат: если что-то пойдёт не так, достаточно удалить две новые
   переменные. Railway сам передеплоит сервис.
4. **Проверить API.** Через 2–3 минуты:
   - `https://api.cleanway.ai/health` → `ok` (если сервис не стартовал — в
     логах Railway `ConfigError`: в переменную попал не тот ключ);
   - `https://api.cleanway.ai/health/deep` → в
     `components.supabase_server_key` должно быть `"ok": true` и
     `"kind": "secret"`; в `components.supabase` — `"ok": true`;
   - в приложении или на сайте: войти, открыть настройки, нажать
     «подключить расширение» — работает.
5. **GitHub → Settings → Secrets and variables → Actions** — секрет
   `SUPABASE_SERVICE_KEY` (им пользуется ежедневная задача Watchtower)
   заменить значением `sb_secret_…`. Скрипт сам поймёт, что это новый ключ.
   Проверка: Actions → «Refresh Watchtower» → *Run workflow* → зелёный.
6. **Перевести клиентов на publishable key** (если ещё не сделано в PR #215):
   - сайт (Vercel): `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` = `sb_publishable_…`
     (сайт предпочитает его старому `NEXT_PUBLIC_SUPABASE_ANON_KEY`);
   - мобильное приложение: `EXPO_PUBLIC_SUPABASE_PUBLISHABLE_KEY` (нужна
     новая сборка; старые сборки с anon-ключом перестанут входить после
     шага 8 — дождаться, пока большинство обновится);
   - расширения получают ключ от сайта при подключении — отдельно ничего
     делать не нужно.
7. Подождать **90 дней** после шага 1, если важно, чтобы старые ссылки
   «отписаться» в уже отправленных письмах продолжали работать. (Если не
   важно — можно сразу.)
8. **Отозвать legacy-ключи.** Supabase → Project Settings → API Keys →
   вкладка «Legacy API keys» → *Disable JWT-based API keys* (это обратимо:
   если что-то сломалось — включить обратно). Сразу после этого снова
   открыть `/health/deep` (`supabase_server_key.ok` = `true`) и проверить
   вход в приложении и на сайте. Затем Project Settings → JWT Keys: legacy
   HS256 secret → *Revoke* (это уже необратимо). После этого в Railway можно
   удалить `SUPABASE_SERVICE_KEY` и `SUPABASE_ANON_KEY`;
   `SUPABASE_JWT_SECRET` пока оставить — конфиг ещё требует её в production.

## Если после деплоя все получают 401

- Проверить, что `SUPABASE_URL` в Railway = `https://bpyqgzzclsbfvxthyfsf.supabase.co`
  без хвоста `/auth/v1` — из него строятся адрес JWKS и ожидаемый `iss`.
- В логах API искать `jwt_invalid`, `jwt_algorithm_refused`,
  `jwt_unknown_signing_key`, `jwks_unavailable`.
- Временная мера, только если токены действительно HS256: `SUPABASE_ALLOW_LEGACY_HS256=1`
  в Railway, затем разобраться и выключить.
