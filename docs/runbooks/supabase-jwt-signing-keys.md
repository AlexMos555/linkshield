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

## Шаги для основателя (по порядку)

1. **Railway → сервис API → Variables** — добавить две переменные, каждая —
   новая случайная строка (64+ символа; например `openssl rand -hex 48`):
   - `UNSUBSCRIBE_HMAC_KEY`
   - `AUDIT_IP_HASH_KEY`

   Railway сам перезапустит сервис. Проверка: `https://api.cleanway.ai/health` — ok.
2. **Перевести клиентов на publishable key.** Supabase → Project Settings →
   API Keys: создать (если ещё нет) `sb_publishable_…` и `sb_secret_…`.
   Заменить:
   - сайт (Vercel): `NEXT_PUBLIC_SUPABASE_ANON_KEY` → publishable key;
   - мобильное приложение: `EXPO_PUBLIC_SUPABASE_ANON_KEY` → publishable key
     (нужна новая сборка; старые сборки с anon-ключом перестанут входить после
     шага 4 — дождаться, пока большинство обновится);
   - расширения: ключ, который сайт передаёт расширению (`anon_key` при
     подключении) — берётся из той же переменной сайта;
   - Railway: `SUPABASE_ANON_KEY` → publishable key, `SUPABASE_SERVICE_KEY` →
     secret key (`sb_secret_…`).
3. Подождать **90 дней** после шага 1, если важно, чтобы старые ссылки
   «отписаться» в уже отправленных письмах продолжали работать. (Если не
   важно — можно сразу.)
4. **Отозвать legacy-ключи.** Supabase → Project Settings → JWT Keys:
   legacy HS256 secret → *Revoke*; API Keys → legacy `anon` / `service_role` →
   *Disable*. После этого `SUPABASE_JWT_SECRET` в Railway больше ничего не
   подписывает и не проверяет (переменную можно оставить — конфиг пока
   требует её в production).

## Если после деплоя все получают 401

- Проверить, что `SUPABASE_URL` в Railway = `https://bpyqgzzclsbfvxthyfsf.supabase.co`
  без хвоста `/auth/v1` — из него строятся адрес JWKS и ожидаемый `iss`.
- В логах API искать `jwt_invalid`, `jwt_algorithm_refused`,
  `jwt_unknown_signing_key`, `jwks_unavailable`.
- Временная мера, только если токены действительно HS256: `SUPABASE_ALLOW_LEGACY_HS256=1`
  в Railway, затем разобраться и выключить.
