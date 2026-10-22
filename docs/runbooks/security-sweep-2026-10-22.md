# Внешний security-sweep Cleanway — 2026-10-22

Авторизованная **неразрушающая** внешняя проверка собственного продукта
(repo `AlexMos555/linkshield`). Цель владельца: защита от **скачивания базы
клиентов и получения их паролей**. Проверка — глазами атакующего, у которого
есть только публичная информация (публичный anon-ключ, клиентские бандлы,
production-эндпоинты).

Границы: без создания аккаунтов, без входа, без отправки писем на реальные
адреса, только чтение (GET / read-only SQL), < нескольких сотен запросов,
секреты в отчёте не приводятся (только имена ключей).

## Итог

**Поверхность атаки, которую просил закрыть владелец (дамп базы, пароли),
защищена надёжно.** Публичный anon-ключ не даёт доступа ни к одной таблице,
RLS включён на всех таблицах `public`, в клиентских бандлах нет `service_role`
и других секретов, SSRF/JWT/CORS/заголовки/open-redirect закрыты на уровне
кода и подтверждены в production.

**Уязвимостей уровня HIGH/MEDIUM не найдено** — ни в коде, ни в конфигурации.
Исправлять в коде нечего: все замечания — уровня LOW/INFO и относятся к DNS/
конфигурации почты (Cloudflare), которую по условиям проверки меняет владелец
вручную (см. раздел «Рекомендации по конфигурации»).

| # | Область | Severity | Статус |
|---|---------|----------|--------|
| 1 | Supabase: доступ к данным через anon-ключ | — | защищено, уязвимостей нет |
| 2 | Секреты в клиентских бандлах / расширениях | — | секретов нет |
| 3 | Auth flows (JWT, enumeration, redirect) | — | защищено |
| 4 | API (CORS, заголовки, SSRF, IDOR, docs, ошибки) | — | защищено |
| 5 | DNS/почта (SPF/DKIM/DMARC/MTA-STS/CAA) | LOW | 3 рекомендации по конфигурации |

---

## 1. Supabase — доступ к данным (критично для «дампа базы»)

Проект `bpyqgzzclsbfvxthyfsf`. Публичный anon-ключ (`EXPO_PUBLIC_SUPABASE_ANON_KEY`,
роль декодируется как `anon`) — публичен by design.

**Проверено (production, с anon-ключом):**

- `GET /rest/v1/` → `401 {"message":"Invalid API key","hint":"Only the
  service_role API key can be used for this endpoint."}` — корень PostgREST
  закрыт для anon.
- Прямые GET на чувствительные таблицы — `401 / 42501 permission denied for
  table …`: `users`, `subscriptions`, `sms_reports`, `feedback_reports`,
  `user_settings`, `families`, `org_members`, `entitlements`. Привилегии
  таблиц у `anon`/`authenticated` отозваны (миграция `025_lock_down_client_access.sql`),
  RLS — вторая стена.
- `GET /graphql/v1` → `pg_graphql extension is not enabled` (доступа к данным
  через GraphQL нет).
- `GET /storage/v1/bucket` → `[]` (публичных бакетов нет).
- `GET /realtime/v1/` → `401` для anon.
- `POST /rest/v1/rpc/report_phone` → `404` (функция отозвана у anon/authenticated,
  доступна только `service_role` — миграция 025 §6).

**RLS по всем таблицам `public` (read-only SELECT через Management API,
`pg_class`/`pg_policies`):** RLS включён на всех 23 таблицах. Без политик
(deny-all для клиента) — только `family_members` и `revenuecat_events`; это
by design: `family_members` читается лишь через `SECURITY DEFINER`-функции
(`shares_family_with`, миграция 025 §5), `revenuecat_events` пишется только
вебхуком под `service_role`. Таблиц с выключенным RLS — нет.

**Архитектурно:** клиенты (mobile/landing/расширения) используют
`@supabase/supabase-js` только для Auth и не делают `.from()`/`.rpc()` — все
данные идут через `api.cleanway.ai` под `service_role`. Клиентам привилегии не
нужны и не выданы. **Уязвимостей нет.**

---

## 2. Секреты в клиентских бандлах и расширениях

**Проверено:** распакованы `dist/store-artifacts/*.zip` (chrome/firefox/edge/
opera/safari) и просканированы вместе с `extension*/`, `packages/`,
`landing/`, `mobile/src/` по шаблонам `service_role`, `sk_live_`, `rk_live_`,
`sk_test_`, `re_…`, `SUPABASE_SECRET/SERVICE`, `xoxb-`, `ghp_`, `AKIA…`,
`-----BEGIN`.

**Результат:** секретов не найдено. Единственные совпадения — защитный код,
который **отклоняет** `service_role` JWT, если его по ошибке подставят в
клиент (`landing/lib/supabase/public-key.ts`, `mobile/src/utils/supabase-key.ts`:
`if (role === "service_role") return "secret"`). Это ровно та защита, которую
ищет атакующий, — и она на месте.

**`.env` в git:** в репозитории только `*.env.example`; реальных `.env` в
индексе нет. `.gitleaks.toml` + pre-commit настроены. **Утечек нет.**

---

## 3. Auth flows

Код: `api/services/auth.py`, `api/routers/auth.py`, `landing/app/auth/callback/route.ts`,
`landing/lib/signup-flow.ts`.

- **JWT (alg confusion / none / просрочка / aud).** Проверка только по JWKS
  проекта, алгоритмы `ES256`/`RS256`; `HS256` отклоняется, пока явно не
  включён `SUPABASE_ALLOW_LEGACY_HS256`. Обязательны `exp,iat,iss,aud,sub`,
  проверяются `aud == authenticated` и `iss`. Чёрный ящик (production):
  мусорный токен и подделанный `alg:none` → `401 {"detail":"Invalid or
  expired token"}`. **Подделать нельзя.**
- **User enumeration.** `POST /api/v1/auth/check-email` возвращает только
  `{disposable, domain}` и не раскрывает, существует ли аккаунт. Сам вход —
  через Supabase GoTrue; ответы по существованию адреса — ответственность
  Supabase (enumeration на реальные адреса не проверялся по условиям —
  без писем на реальные ящики).
- **Open redirect.** Колбэк магической ссылки (`safeRedirectPath`) парсит
  `next` относительно своего origin и сверяет origin; `safeSignupNext` —
  строгий allowlist (`/extension/connect?state=…`, `/account`,
  `/account/restore`). Обрабатываются backslash, protocol-relative и
  percent-encoding. **Open-redirect нет.**
- **`extension-session`.** Адрес берётся из проверенного JWT, не из запроса;
  требуется свежий токен (`iat` ≤ 10 мин); проверяется `session_user.id ==
  user.id`; лимит 10/час. Чужую сессию выдать нельзя.

**Уязвимостей нет.**

---

## 4. API (api.cleanway.ai)

- **Заголовки безопасности (production, подтверждено curl):** HSTS
  `max-age=31536000; includeSubDomains; preload`, CSP `default-src 'none';
  frame-ancestors 'none'; base-uri 'none'; form-action 'none'`, X-Frame-Options
  DENY, X-Content-Type-Options nosniff, Referrer-Policy, развёрнутый
  Permissions-Policy, COOP/CORP. `Server`-заголовок приложения снят
  (`railway-hikari` — это edge-прокси Railway, не управляется кодом).
- **Docs / OpenAPI:** `/docs`, `/redoc`, `/openapi.json` → `404` в production
  (отключены в `api_docs_settings`).
- **CORS:** статичный allowlist из env (без wildcard). Чёрный ящик: preflight
  с `Origin: https://evil.example` → **без** `Access-Control-Allow-Origin`
  (браузер заблокирует); `Origin: https://cleanway.ai` → origin отражается
  корректно. **Reflection нет.**
- **SSRF (ключевое для URL-сканера).** `api/services/domain_validator.py` —
  образцовый guard: порты только 80/443; запрещены single-label имена и
  суффиксы `.internal/.railway.internal/.local/.localhost/.localdomain/.arpa`;
  проверяется **каждый** разрезолвленный адрес на публичность (включая IPv4-
  в-IPv6: `::ffff:`, 6to4, NAT64; Teredo запрещён); блок-листы приватных/
  loopback/link-local/metadata-сетей (`169.254.0.0/16`, `127.0.0.0/8` и т.д.);
  подключение идёт к **уже проверенному адресу**, не к имени (защита от DNS
  rebinding). Все исходящие fetch пользовательского хоста (`site_probes.py`,
  `favicon_hash.py`, `lookalike_generator.py`) идут через `pinned_http`/
  `resolve_public` и **вручную валидируют каждый redirect-hop**. Прочие
  httpx-вызовы (`analyzer.py`, `safe_browsing`, `web_risk`, `pwned_passwords`
  и т.д.) бьют по фиксированным доверенным провайдерам; `domain`
  интерполируется только в path, а строгая regex `validate_domain` не
  пропускает `/ @ ? #`. **Активные SSRF-пейлоады в production не отправлялись
  намеренно** (риск для живого сервиса) — guard подтверждён ревью кода, он
  исчерпывающий.
- **IDOR.** Эндпоинты устройств (`DELETE/PATCH /account/devices/{id}`) скоупятся
  по `user.id` из JWT; store фильтрует по `id=eq.{device_id}` **и**
  `user_id=eq.{account_id}` (`account_store.rename_device`), revoke — RPC с
  `p_user_id`. Чужое устройство тронуть нельзя.
- **Verbose errors.** `404 {"detail":"Not Found"}`, стек-трейсов нет;
  ошибки `>=400` помечаются `Cache-Control: no-store`.

**Уязвимостей нет.**

---

## 5. DNS / почта (спуфинг домена в фишинге против наших пользователей)

Проверено `dig` (`cleanway.ai`):

- **SPF:** `v=spf1 include:_spf.mx.cloudflare.net ~all` — есть (softfail `~all`).
- **DMARC:** `v=DMARC1; p=reject; sp=reject; adkim=s; aspf=r; pct=100` —
  **сильная политика** (reject + строгое выравнивание DKIM). Нет `rua`
  (агрегатные отчёты не собираются).
- **DKIM:** селектор `resend` присутствует (почту шлёт Resend; DKIM-выравнивание
  работает).
- **CAA:** настроен (`issue`/`issuewild`: letsencrypt, digicert, pki.goog,
  comodoca, ssl.com; `iodef mailto:security@cleanway.ai`).
- **MTA-STS:** **отсутствует** (нет TXT `_mta-sts` и policy-эндпоинта).
- **TLS-RPT:** **отсутствует** (нет `_smtp._tls`).

Severity: **LOW**. Домен уже защищён от прямого спуфинга (`DMARC p=reject` +
DKIM). Пробелы — в наблюдаемости и защите входящей почты от downgrade.

---

## Рекомендации по конфигурации (меняет владелец вручную; код не трогаем)

Все пункты — конфигурация Cloudflare/DNS, не код репозитория.

1. **DMARC `rua`** (Cloudflare DNS, LOW): добавить агрегатные отчёты в запись
   `_dmarc.cleanway.ai`, например
   `v=DMARC1; p=reject; sp=reject; adkim=s; aspf=r; pct=100; rua=mailto:dmarc@cleanway.ai`
   — чтобы видеть попытки спуфинга и легитимные источники перед ужесточением.
2. **MTA-STS + TLS-RPT** (Cloudflare DNS + статический policy-хост, LOW):
   - TXT `_mta-sts.cleanway.ai` → `v=STSv1; id=2026102201`;
   - policy по `https://mta-sts.cleanway.ai/.well-known/mta-sts.txt`
     (`version: STSv1`, `mode: enforce`, `mx: route1.mx.cloudflare.net` и
     остальные MX, `max_age: 604800`);
   - TXT `_smtp._tls.cleanway.ai` → `v=TLSRPTv1; rua=mailto:tls-reports@cleanway.ai`.
   Защищает входящую почту от downgrade/перехвата.
3. **SPF `~all` → `-all`** (Cloudflare DNS, LOW, опционально): hardfail строже;
   при `DMARC p=reject` почти нулевой эффект, но убирает двусмысленность.
   Менять только убедившись, что все отправители (Resend, Cloudflare Email
   Routing) покрыты.

Информационно (менять нечего):
- PostgREST на несуществующую таблицу отдаёт `PGRST205` с подсказкой соседних
  имён таблиц (`devices`, `family_alerts`) — поведение Supabase по умолчанию,
  данные при этом защищены; имена таблиц не являются секретом.
- `landing` CSP содержит `script-src 'unsafe-inline'` (нужно для inline-
  bootstrap Next.js). Это задокументированный компромисс; усиление требует
  nonce-middleware (отдельная задача, не правка в рамках sweep).

---

## Что НЕ делалось (по условиям / из осторожности)

- Активные SSRF-пейлоады (`169.254.169.254`, `localhost`, внутренние хосты
  Railway, `127.0.0.1.nip.io`) в production **не отправлялись**: guard
  подтверждён ревью `site_probes.py`/`domain_validator.py`, а живой пробой
  против работающего сервиса несёт риск. При желании владельца — отдельный
  контролируемый тест на staging.
- Enumeration через `/auth/v1/otp` и `/recover` на реальные адреса —
  не выполнялось (запрет на письма реальным адресатам).
- Никаких write/delete, создания аккаунтов, входа, нажатий deploy.
- Секреты (anon-ключ, `SUPABASE_ACCESS_TOKEN`, SMTP) в отчёте не приводятся.
