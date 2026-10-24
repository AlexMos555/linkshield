# DNS в отдельном сервисе Railway (`dns.cleanway.ai`)

**Для кого:** основатель (что нажать в Railway и Cloudflare) и Claude (точные
проверки). **Состояние на 2026-10-24:** код готов, прод не менялся. Один сервис
Railway `web` отвечает и на `api.cleanway.ai`, и на `dns.cleanway.ai`;
переменная `SERVICE_ROLE` не задана, это значит `all` — всё как раньше.

## Зачем

[capacity.md](capacity.md), «Что сделать», пункт 3: DNS и публичная проверка
`/check` живут в одних воркерах, и всплеск `/check` (краулеры, боты) отнимает
CPU у DNS всех телефонов. В отдельном сервисе у DNS свой CPU, свои реплики и
свой масштаб. Сделать **до публичного релиза iOS** (или от ~5 тыс. телефонов):
пока на DNS сидит мало людей, короткий перерыв при переносе домена (шаг 4)
почти никого не задевает.

## Как будет

| Сервис | Домен | `SERVICE_ROLE` | Реплики |
|---|---|---|---|
| `web` (как сейчас) | `api.cleanway.ai` | не задана (`all`), через сутки после переноса — `api` | 2, как сейчас |
| `dns` (новый) | `dns.cleanway.ai` | `dns` | 2 |

Тот же репозиторий и тот же `Dockerfile`: каждый merge в `main` выкатывает оба
сервиса, каждый со своим health check `/health`.

## Что значит `SERVICE_ROLE`

| | `all` (по умолчанию) | `dns` | `api` |
|---|---|---|---|
| Отвечает | всё; под `dns.cleanway.ai` — только DNS (как сейчас) | `/dns-query`, `/health`, `/health/doh` под **любым** именем, остальное — 404 | всё, кроме `/dns-query` и `/health/doh` (404). Под `dns.cleanway.ai` DNS всё равно отвечает — страховка от неправильного порядка шагов |
| ML-модель при старте | да | нет (DNS сайты не оценивает) | да |
| Список в памяти для DNS (`doh_filter`) | да | да | нет: если DNS-запрос всё же придёт, решение берётся из Redis |
| Удаление данных по срокам (`RETENTION_PURGE`) | да | нет | да |
| Строка лога `doh_stats` раз в 5 минут | да | да | да (в ней `proxy_peers` для всех запросов, [cloudflare-proxy.md](cloudflare-proxy.md)) |
| Проверка переменных при старте | все, как раньше | только нужное DNS: в production `SENTRY_DSN` и `TRUSTED_PROXY_CIDRS`; Supabase, Stripe, вебхуки не нужны | все, как раньше |
| `/health` | как раньше | + `"service_role":"dns"` | + `"service_role":"api"` |

Опечатка (`SERVICE_ROLE=dsn`) не даёт процессу запуститься — Railway оставит
работать прежний деплой. Регистр и пробелы не важны, пустое значение = `all`.
Не путать с `ROLE` (`api` | `billing`): та выбирает российский биллинг.

## Шаги

### 0. Подготовка (накануне, 5 минут)

1. PR смёржен, Railway выкатил `web`: `curl -s https://api.cleanway.ai/health`
   отвечает `"status":"ok"` **без** `service_role`.
2. Cloudflare → `cleanway.ai` → DNS → запись `dns` (CNAME, серое облако — так
   и остаётся, [cloudflare-proxy.md](cloudflare-proxy.md)). Записать текущую
   цель — на 2026-10-24 это `ics2mtji.up.railway.app` (нужна для отката). TTL
   поставить **1 min** вместо Auto (5 минут), минимум за час до шага 4.

### 1. Создать сервис `dns` (5 минут)

1. Railway → проект `honest-playfulness` → **+ New** (или **Create**) →
   **GitHub Repo** → `AlexMos555/linkshield`. Railway сразу начнёт сборку без
   переменных — не страшно: публичного адреса у сервиса пока нет.
2. Новый сервис → **Settings**, всё **как у `web`** (открыть `web` → Settings
   рядом и сверить):
   - имя сервиса: `dns`;
   - Source: ветка `main`; сборка — `Dockerfile` (Railway находит его сам),
     Custom Start Command — пусто, как у `web`;
   - Deploy → **Healthcheck Path** `/health`;
   - Deploy → регион **тот же, что у `web` и `Redis`** (EU West), **2 реплики**;
   - лимиты CPU/RAM — как у `web`. Воркеру DNS памяти нужно примерно вдвое
     меньше (локально при старте ~125 МБ против ~260 МБ у `all`), CPU — так же:
     ≥ 2 vCPU на реплику для двух воркеров;
   - Networking → **Generate Domain**: `dns-…up.railway.app`, для проверки до
     переключения. Private networking не нужен.

### 2. Переменные `dns` (5 минут)

`web` → **Variables** → **Raw Editor**: скопировать строки с этими именами
**в том виде, как они там записаны** (если `REDIS_URL` записан ссылкой
`${{Redis.REDIS_URL}}` — так и копировать), затем `dns` → Variables → Raw
Editor → вставить и добавить `SERVICE_ROLE`:

```
SERVICE_ROLE=dns
ENVIRONMENT=…           # как у web (production)
REDIS_URL=…             # как у web
TRUSTED_PROXY_CIDRS=…   # как у web (100.64.0.0/10)
SENTRY_DSN=…            # как у web
WEB_CONCURRENCY=…       # как у web (2)
```

Скопировать ещё, **если они есть у `web`** (настройки DNS-шлюза и сброса
нагрузки): все `DOH_*`, все `LOAD_SHED_*`, `STRICT_CONFIG`, `SENTRY_RELEASE`.
Переменную, которой у `web` нет, не добавлять: пустое значение у числовой
настройки не даёт процессу стартовать.

**Не копировать** — DNS их не читает, а у самого открытого сервиса секретов
должно быть меньше всего: все `SUPABASE_*`, `STRIPE_*`, `REVENUECAT_*`,
ключи почты и LLM (`RESEND_*`, `ANTHROPIC_API_KEY`), источники проверок
(`GOOGLE_SAFE_BROWSING_*`, `WEB_RISK_API_KEY`, `IPQUALITYSCORE_KEY`,
`PHISHTANK_API_KEY`, `HIBP_API_KEY`), `UNSUBSCRIBE_HMAC_KEY`,
`AUDIT_IP_HASH_KEY`, `BENCHMARK_BYPASS_TOKEN`, `RETENTION_PURGE`,
`RATE_LIMIT_FAIL_CLOSED`, `BILLING_*`, `ROLE`, `MOBILE_*`, `SMS_*`,
`PUBLISH_CONFIRMED_THREATS`, `LOOKALIKE_*`, `SECURITY_ALERTS_*`,
`ALLOWED_ORIGINS`.

Значение, скопированное как есть (не ссылкой), при смене в `web` надо
поменять и в `dns` — или записать ссылкой: `SENTRY_DSN=${{web.SENTRY_DSN}}`.
Сохранить (если Railway показывает несохранённые изменения с кнопкой
**Deploy** — нажать её): `dns` передеплоится.

### 3. Проверить `dns` до переключения (10 минут)

Railway → `dns` → Deployments: деплой зелёный. Logs: строка
`Cleanway API starting` с `"service_role": "dns"`, затем `doh_filter_loaded`
(`count` ~600 тыс.); строки `ml_model_warmed` нет — так и должно быть.

```bash
D=https://dns-xxxx.up.railway.app      # домен из шага 1
curl -s $D/health                      # "status":"ok", "redis":"ok", "service_role":"dns"
curl -s $D/health/doh                  # "ok":true, "filter":{"loaded":true,…}
curl -s -o /dev/null -w '%{http_code}\n' $D/          # 404 — API тут нет
curl -s -o /dev/null -w '%{http_code}\n' --doh-url $D/dns-query https://example.com   # 200
python3 scripts/dns_canary.py --dns-base $D           # из папки репозитория: DNS canary против нового сервиса
```

Канарейка проверяет имена, которые обязаны открываться, блок проверочного
имени **нашим** NXDOMAIN, живые фишинговые хосты и `/health/doh` нового
сервиса; артефакт и `/health/deep` — как обычно, у `api.cleanway.ai`. В конце
`DNS canary OK`. Что-то красное — не переключать, разбираться.

### 4. Перенести `dns.cleanway.ai` (ночью, 10–20 минут)

Единственный шаг, который видят телефоны. Свой домен в Railway принадлежит
одному сервису: Railway не даст добавить `dns.cleanway.ai` к `dns`, пока он
висит на `web`. Между удалением с `web` и сертификатом на `dns` iPhone с
DNS-защитой не могут ничего открыть (приложение на iOS 26+ может переключиться
на DNS сети — `allowFailover`; профиль `.mobileconfig` и iOS постарше — нет).
Поэтому: самый тихий час (03:00–05:00 МСК), и всё подряд, без пауз.

1. В терминале запустить наблюдение и не закрывать до конца шага:
   ```bash
   while true; do printf '%s ' "$(date -u +%T)"; curl -s -m 5 https://dns.cleanway.ai/health | grep -o '"service_role":"[a-z]*"\|"status":"[a-z]*"' | tr '\n' ' '; echo; sleep 5; done
   ```
   Сейчас печатает `"status":"ok"` без `service_role` — это `web`.
2. Railway → `web` → Settings → Networking → `dns.cleanway.ai` → удалить.
   **`api.cleanway.ai` не трогать.**
3. Сразу: Railway → `dns` → Settings → Networking → **+ Custom Domain** →
   `dns.cleanway.ai`. Railway покажет цель CNAME (`xxxx.up.railway.app`) и,
   возможно, TXT-запись для подтверждения.
4. Cloudflare → DNS → запись `dns`: Target — новая цель, Proxy status —
   **DNS only (серое)**, TTL 1 min. Если Railway просил TXT — добавить и её.
5. Ждать зелёную галочку у домена в Railway (выпуск сертификата). Наблюдение
   из п. 1 начинает печатать `"service_role":"dns"`.
6. Проверить:
   ```bash
   dig +short CNAME dns.cleanway.ai              # новая цель
   curl -s https://dns.cleanway.ai/health        # "service_role":"dns"
   curl -s https://dns.cleanway.ai/health/doh    # "ok":true, "filter":{"loaded":true,…}
   curl -s -o /dev/null -w '%{http_code}\n' --doh-url https://dns.cleanway.ai/dns-query https://example.com   # 200
   curl -s https://api.cleanway.ai/health/deep   # 200, "status":"ok", "warnings":[] — API не задет
   ```
   GitHub → Actions → **DNS canary** → Run workflow — зелёный.
7. Галочки нет за 15 минут или DNS не отвечает — «Откат», вариант 1.

TTL записи `dns` можно вернуть на Auto через сутки. Сказать Claude, что
перенос сделан: таблицы «что где живёт» в `deploy.md`, `infra-readiness.md`
и `docs/architecture/environments.md` пока описывают один сервис `web`.

### 5. `web` без DNS (через сутки, по желанию)

Когда `dns` сутки отработал без писем монитора: `web` → Variables →
`SERVICE_ROLE=api` (и **Deploy**, если Railway его просит). Ждать сутки нужно
потому, что `web` в режиме `all` — мгновенная цель для отката домена. После
перезапуска:

```bash
curl -s https://api.cleanway.ai/health                # "service_role":"api"
curl -s -o /dev/null -w '%{http_code}\n' "https://api.cleanway.ai/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"   # 404
curl -s https://api.cleanway.ai/health/deep           # 200, "warnings":[]
```

В `/health/deep` у `components.doh` теперь `"filter":{"loaded":false,…}` —
это нормально: список в памяти держит только `dns`, а проверка блока у API
идёт через набор в Redis. Если по ошибке сделать этот шаг раньше шага 4,
телефоны не пострадают: имя `dns.cleanway.ai` `web` обслуживает в любой роли
(только медленнее, через Redis).

## Реплики и деньги

- `dns`: 2 реплики × `WEB_CONCURRENCY=2`. Правило из capacity.md (+1 реплика
  на каждые ~5 тыс. новых активных телефонов, CPU > 60 % 10 минут, `p95_ms_le`
  ≥ 200) теперь про сервис `dns`. `web` масштабируется по нагрузке `/check`.
- Новый сервис добавляет постоянную память двух реплик (порядка 0,5 ГБ);
  CPU — тот же, что DNS тратит сейчас внутри `web`.

## Что меняется для мониторинга

- **Монитор `cleanway-uptime`** (`ops/uptime-worker`) ничего менять не нужно:
  `doh_resolve`, `doh_block` и `dns_latency` (p95 из `/health/doh` ≥ 200 мс
  5 минут подряд) спрашивают `dns.cleanway.ai` — после шага 4 это сервис
  `dns`. `api`, `blocklist`, `dns_filter`, `server_key` читают
  `api.cleanway.ai/health/deep` — сервис `web`.
- **DNS canary** (GitHub) с 2026-10-24 задаёт DNS-вопросы и читает
  `/health/doh` у `dns.cleanway.ai`, а артефакт и `/health/deep` — у
  `api.cleanway.ai`, так что работает и до, и после переноса.
- **Railway:** Metrics и Logs у каждого сервиса свои; `doh_stats` и строки
  `load_shed` DNS — в логах `dns`.
- **Sentry:** у событий тег `service_role` (`dns` / `api`), если роль задана.

## Приложения

Менять ничего не нужно. iPhone (`CleanwayVpnModule.swift`, `serverURL`),
профиль `.mobileconfig` (`api/services/mobileconfig.py`) и страница
`cleanway.ai/dns` всегда указывали `https://dns.cleanway.ai/dns-query`: имя
и путь не меняются, установленные профили и настройки продолжают работать.
Android-щит фильтрует на телефоне и берёт список с
`api.cleanway.ai/api/v1/blocklist/dns` — это остаётся на `web`. Остальные
запросы приложений и расширений идут на `api.cleanway.ai`.

## Откат

1. **Домен на `dns` не поднялся (шаг 4).** Railway → `dns` → Networking →
   удалить `dns.cleanway.ai`; `web` → **+ Custom Domain** → `dns.cleanway.ai`;
   Cloudflare → запись `dns` → цель, которую покажет Railway (могла остаться
   прежней, `ics2mtji.up.railway.app`). `web` в режиме `all` отвечает на DNS
   сразу, как появится сертификат.
2. **Сломался деплой `dns` позже.** Как для `web` ([rollback.md](rollback.md)):
   Railway → `dns` → Deployments → предыдущий рабочий → **Redeploy**. Если
   сервис не поднимается совсем — вариант 1 (вернуть домен на `web`; он
   отвечает на `dns.cleanway.ai` и с `SERVICE_ROLE=api`).
3. **Вернуть всё как было.** Домен — на `web` (вариант 1), у `web` удалить
   `SERVICE_ROLE`, сервис `dns` удалить (Settings → Danger → Delete Service).

## В коде

- `api/config.py` — `service_role`, `serves_api()` / `serves_dns()`, проверка
  переменных для `dns`;
- `api/services/request_guards.py` — `DnsRouting` и `serves()`: какой путь
  под каким именем отвечает (стоит снаружи быстрого пути DNS);
- `api/main.py` — что запускается при старте в каждой роли, `service_role` в
  `/health`;
- `api/routers/doh.py` — `startup(load_filter=…)`;
- тесты: `tests/test_service_role.py`; монитор —
  `ops/uptime-worker/worker.test.mjs`; канарейка — `tests/test_dns_canary.py`.
