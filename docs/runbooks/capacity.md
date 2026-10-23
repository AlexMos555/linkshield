# Ёмкость API перед запуском (capacity runbook)

Замерено 2026-10-22 локально в Docker (продовый `Dockerfile`), без единого
нагрузочного запроса в прод. Исправления, найденные по ходу, — PR #268
(уже в проде). Как повторить — в конце.

## Коротко (для основателя)

* **Главная нагрузка — DNS (`/dns-query`).** Один телефон с включённой
  защитой — это ~3 000 DNS-запросов в сутки (принято 2–5 тыс.), в час пик
  ~2,5× от среднего ≈ **0,09 запроса/с на телефон**.
* **Сейчас (2 реплики × 2 воркера) выдерживаем ≈ 1 200 DNS-запросов/с с
  запасом** (60 % CPU, задержка в норме) и ≈ 2 000/с на пределе. Это
  **≈ 10–13 тыс. активных телефонов** при 3 тыс. запросов/сутки
  (8 тыс. при 5 тыс./сутки, 20 тыс. при 2 тыс./сутки). Если Railway даёт
  реплике только 1 vCPU — вдвое меньше: ~6 тыс. телефонов.
* **Добавлять реплику (или выносить DNS в отдельный сервис), когда:**
  CPU сервиса `web` в час пик > 60 % от `2 × реплики` vCPU, или
  `p95_ms_le` в `/health/doh` ≥ 200, или растёт `servfail`. Правило на
  пальцах: **+1 реплика (2 воркера) на каждые ~5 тыс. новых активных
  телефонов.**
* **Redis не узкое место:** ~150 МБ в покое со всем списком (585–650 тыс.
  имён), пик ~250 МБ во время обновления списков; DNS почти не ходит в Redis
  (≈0,06 операции на запрос).
* **Деньги:** при 10 тыс. телефонов ≈ **$45–60/мес** на Railway (CPU ~$15,
  RAM ~$12, трафик ~$18, Redis ~$3–5). При 100 тыс. — порядка
  **$350–450/мес** (нужно 8–15 реплик). Альтернатива «Cloudflare Worker перед
  DNS» из doh-gateway.md стоит ~$180/мес уже на 10 тыс. телефонов.
* **Что было сломано и исправлено (PR #268):** публичная проверка `/check`
  тратила 86 мс CPU даже на ответ из кэша (новый TLS-контекст на каждый
  запрос) — один vCPU держал < 25 проверок/с и при этом отнимал CPU у DNS.
  Теперь 5–6 мс (в 14 раз меньше). Свежий анализ: 190 → 20–30 мс CPU (ML-модель
  крутила десятки потоков вхолостую). `/health/doh` отвечал 500 после
  перегрузки — монитор считал бы DNS мёртвым.
* **Риск, который остаётся:** DNS и публичная проверка живут в одних и тех же
  воркерах. Всплеск `/check` (SEO-краулеры, боты) отнимает CPU у DNS всех
  телефонов. С 2026-10-23 сервер при перегрузке **сбрасывает лишнее**
  (раздел «Сброс нагрузки» ниже): у DNS, `/health` и остального API свои
  бюджеты, сверх бюджета — мгновенный `503` с `Retry-After`, дорогой свежий
  анализ ограничен отдельно. Пока API затоплен, закэшированные DNS-ответы
  приходят за миллисекунды вместо секунд, память не растёт. Но отказ — это
  всё равно отказ: масштабировать **заранее**, по 60 % CPU, а не по факту.

### Что сделать (по порядку)

1. Railway → сервис `web` → Metrics: проверить, сколько vCPU реально
   получает реплика под нагрузкой и какой лимит у тарифа (Settings →
   Resources). Нужно ≥ 2 vCPU и ≥ 1 ГБ на реплику (2 воркера ≈ 300–550 МБ).
2. Алерт: CPU `web` > 60 % 10 минут подряд, и внешний монитор на
   `/health/doh` (non-200, `p95_ms_le` ≥ 200, `over_ms` растёт), плюс
   строки лога `load_shed` в Railway — сервер начал отказывать.
3. Перед публичным релизом iOS (или от ~5 тыс. телефонов): **вынести
   `dns.cleanway.ai` в отдельный Railway-сервис из того же образа** (2
   реплики, свой домен) — тогда `/check` и сайт не могут «уронить» DNS, и DNS
   масштабируется отдельно.
4. Дальше — реплики по правилу выше; второй регион и Cloudflare —
   см. `doh-gateway.md`.

## Методика

* Образ из корневого `Dockerfile`; `uvicorn` с `WEB_CONCURRENCY=2`; контейнер
  ограничен `--cpus 1` или `2`, `--memory 1g` (тариф Railway неизвестен —
  1 vCPU / 1 ГБ на реплику по умолчанию, 2 vCPU как «Railway без жёсткого
  лимита»: два однопоточных воркера больше двух ядер не съедят).
* Redis 7 в контейнере, засеян как прод: `dangerous_domains` 650 001 имя +
  v2-артефакт (`scripts/doh_loadtest.py seed --count 650000`), копии `:prev`,
  `tranco:ranks` ~1 млн (`scripts/capacity/seed_extra.py`).
* DoH-апстрим — заглушка RFC 8484 по **HTTP/2 + TLS** (как Cloudflare;
  по plain HTTP httpx уходит в HTTP/1.1, а он ведёт себя иначе), +10 мс.
  Внешние источники анализатора (Safe Browsing, RDAP, DNS, пробы сайта…) и
  сравнение с Cloudflare Families заменены сном 40–400 мс и «безопасным»
  ответом (`scripts/capacity/stub_app.py`); Redis-проверки, скоринг, ML,
  сериализация — настоящие.
* Нагрузка — k6 (`grafana/k6`), constant-arrival-rate.
  DoH: GET, 88 % популярных имён (Zipf по top-5000, 30 % с `www.`), 2 % из
  блоклиста, 10 % никогда не виденных; A/AAAA/HTTPS 45/45/10; половина с EDNS0
  padding. Доля попаданий в кэш в тесте — 53–60 % (кэш на воркер, тест
  короткий); в проде при тысячах телефонов она выше, т.е. оценки
  консервативны.
* CPU на запрос — по cgroup (`cpu.stat usage_usec`) контейнера.
* Машина: i5-9600K, Docker Desktop VM (6 vCPU). В этой VM Python примерно
  в 2–3 раза медленнее, чем нативно (тот же DoH нативно — ~0,6 мс CPU на
  запрос, см. doh-gateway.md), так что цифры ниже — нижняя граница.

## Цифры

### CPU на запрос (1 контейнер, 2 воркера, низкая нагрузка)

| путь | до PR #268 | после |
|---|---:|---:|
| `/dns-query` (смесь выше) | 2,4 мс | **1,4–1,9 мс** |
| `/health` | 5,0 мс | 3,4 мс |
| `/api/v1/public/check` — ответ из кэша | 86 мс | **4,9 мс** |
| `/api/v1/public/check` — популярный домен (allowlist) | 78 мс | **5,0 мс** |
| `/api/v1/public/check` — свежий анализ (источники-заглушки) | 190 мс | **19–30 мс** |

Свежий анализ в проде дороже: настоящие TLS-рукопожатия к ~10 источникам
и пробы сайта, ~10 мс на признаки ML (difflib по брендам). Он ограничен
5 свежими проверками в минуту на IP/установку.

### DoH, пропускная способность одной реплики (2 воркера)

| ресурсы | запросов/с | p50 | p95 | p99 | CPU |
|---|---:|---:|---:|---:|---:|
| 1 vCPU | 300 | 12 мс | 141 мс | 436 мс | 0,64 |
| 1 vCPU | 500 | 1,2 мс | 30 мс | 307 мс | 0,71 |
| 1 vCPU | 600 | 2,0 мс | 144 мс | 881 мс | 0,86 |
| 1 vCPU | 800 (предложено) | 672 выдано | 4,2 с | — | насыщение |
| 2 vCPU | 600 | 2,5 мс | 68 мс | 361 мс | 0,88 |
| 2 vCPU | 1 000 | 6,4 мс | 508 мс | 1,2 с | 1,56 |
| 2 vCPU | 1 200 (предложено) | 734 выдано | 4,4 с | — | насыщение |

0 HTTP-ошибок до насыщения. За насыщением задержки уходят в секунды и
запросы копятся в памяти (до ~550 МБ, однажды 917 МБ на `/health`-перегрузке
при лимите 1 ГБ). p95 на 1 vCPU шумный: два воркера делят одну квоту CFS.
(Так было до 2026-10-23 — теперь лишнее сбрасывается, см. «Сброс нагрузки».
917 МБ давал сам `/health`: каждый запрос, пришедший до первой загрузки
артефакта, тянул из Redis свою копию списка, ~5 МБ base64 + расшифровка.)

Две реплики стенд не смог честно нагрузить (k6, заглушка апстрима, Redis и
два контейнера делят 6 vCPU одной VM — CPU на запрос вырос до 3 мс). Реплики
ничего не делят, кроме Redis (≤ 60 операций/с при 1 000 DNS-запросов/с), так
что две реплики = 2 × одна.

**Итог для текущей схемы (2 реплики × 2 воркера):**
комфортно ~1 200 DNS-запросов/с (2 × 600), предел ~2 000/с (2 × 1 000)
при 2 vCPU на реплику; при 1 vCPU — ~1 000/с комфортно, ~1 300/с предел.

### Телефоны

| запросов/телефон/сутки | пик, запросов/с на телефон | телефонов на 1 200 запросов/с |
|---:|---:|---:|
| 2 000 | 0,058 | ~20 тыс. |
| **3 000** | **0,087** | **~13 тыс.** |
| 5 000 | 0,145 | ~8 тыс. |

Пик = среднее × 2,5 (вечерний час). Планировать по ~10 тыс.

### Публичная проверка и `/health`

* Ответ из кэша / allowlist: ~5 мс CPU → ~100 запросов/с на vCPU с p50
  20–30 мс (1 vCPU: 50/с — p50 25 мс; 2 реплики по 1 vCPU: 200/с — p50 30 мс).
  До исправления 1 vCPU захлёбывался на ~20/с.
* Свежий анализ (заглушки 40–400 мс): 25/с на 1 vCPU — p50 430 мс; 50/с —
  очередь (p50 3,5 с). Реальный предел задаёт лимит 5/мин на IP и бюджет
  источников, а не CPU.
* `/health`: 2 операции Redis + полный стек FastAPI (~3–5 мс CPU). Для
  мониторов нормально; не опрашивать чаще раза в 10–30 с.

### Redis

| что | память |
|---|---:|
| `dangerous_domains` (650 тыс. имён) | ~41 МБ |
| `dangerous_domains:prev` (откат) | ~41 МБ |
| артефакт v2 + `:prev` (base64) | ~10,5 МБ |
| `tranco:ranks` (~1 млн) | ~58 МБ |
| **итого в покое** | **~145 МБ** |
| пик при обновлении (staging-копии списка и tranco) | ~250 МБ |
| кэш публичных проверок | 0,4–2 КБ на домен (100 тыс. доменов ≈ 50–200 МБ) |

Операции: DoH ≈ 0,06 на запрос (2 % подтверждений блокировки + опрос
артефакта раз в 30 с), публичная проверка ≈ 7, `/health` 2. На 1 900 оп/с
Redis в контейнере загружен < 15 % CPU. Запас: Redis на 1 ГБ хватит до
~2–3 млн имён в блоклисте.

### Деньги (Railway, по потреблению)

Ставки Railway: ~$20 за vCPU·месяц, ~$10 за ГБ RAM·месяц, исходящий трафик
~$0,05/ГБ (проверить актуальные в Railway → Usage). Ответ DoH с заголовками
HTTP/2 и TLS ≈ 300–500 байт.

| телефонов | DNS-запросов/с (среднее / пик) | CPU (среднее) | реплик | ≈ $/мес |
|---:|---:|---:|---:|---:|
| 1 тыс. | 35 / 90 | 0,1 vCPU | 2 | ~$12–20 (минимум за 2 реплики) |
| 10 тыс. | 350 / 870 | 0,5–0,7 vCPU | 2 | ~$45–60 |
| 30 тыс. | 1 040 / 2 600 | 1,5–2 vCPU | 4–5 | ~$130–180 |
| 100 тыс. | 3 470 / 8 700 | 3–7 vCPU | 8–15 | ~$350–450 |

Большая часть счёта на 100 тыс. — трафик (~$180) и RAM реплик; CPU растёт
линейно с телефонами.

## Сброс нагрузки (load shedding)

С 2026-10-23 (`api/services/load_shedding.py`). Каждый запрос занимает место
в бюджете своего класса; места нет — мгновенный `503` с `Retry-After: 2`, до
маршрутизации, авторизации, разбора тела и строки лога. Лимиты — **на
воркер** (при `WEB_CONCURRENCY=2` у реплики вдвое больше), `0` = без лимита.

| что | одновременно | сверх лимита |
|---|---:|---|
| DNS, `/dns-query` | 1024 | `503` без тела; телефон повторяет запрос |
| `/health`, `/health/doh`, `/health/deep` | 64 | `503` JSON |
| всё остальное API | 128 | `503` JSON `{"detail": …}` |
| свежий анализ (`/check`, свежий путь `/public/check`) | 16 | `/public/check`: `503`, квота свежих проверок не тратится (запрос того же домена, что уже анализируется, ждёт этот анализ без места); `/check`: что не влезло — вердикт по адресу, `checks_incomplete: ["analysis"]`, не кэшируется и не списывается с квоты |
| живые вызовы LLM (судья; объяснения — отдельно) | 4 | судья пропущен, вердикт без него; объяснение — шаблон, ничего не кэшируется |
| сравнение с Cloudflare | 32 | `competitors: []` |
| исходящие вызовы анализа (источники, пробы сайта) | 256 | ждут очереди внутри бюджета анализа (3 с); при 16 анализах × 13 проверок не ждут никогда |

Классы раздельные: поток публичных проверок получает `503`, а DNS и мониторы
— свои места. У DNS счётчик самый большой нарочно: промах кэша ждёт апстрим
до 4 с, и медленный Cloudflare не должен вытеснять ответы из кэша. Цена —
при чистой DNS-перегрузке принятый запрос может стоять в очереди дольше
(локально: 256 → p95 0,9 с, 1024 → 2,5–3 с). CPU для DNS освобождает то, что
дорогая работа ограничена, а всё сверх бюджетов отбивается дёшево. Порог по
задержке event loop поверх счётчиков пробовали — в этих замерах он ничего не
менял (DNS из кэша p50 26–30 мс и с ним, и без), поэтому его нет.

Тот же PR: артефакт списка (`/health`, синхронизация телефонов) читается из
Redis **один раз** на воркер при смене sha — остальные ждут эту копию. Отсюда
были 917 МБ на `/health`-перегрузке: каждый запрос до первой загрузки тянул
свою копию.

**Где смотреть.** `/health/doh` → `load_shed` (по воркеру, который ответил):
`in_flight / limit / peak / shed` по каждому бюджету, `waited` у исходящих.
В логе — одна строка `load_shed` с этими счётчиками не чаще раза в 10 с на
воркер, пока идут отказы. В покое `shed` — 0, `peak` — единицы-десятки.

**Что крутить** (Railway → Variables; воркеры перечитывают при рестарте):
`LOAD_SHED_DNS_MAX_INFLIGHT`, `LOAD_SHED_HEALTH_MAX_INFLIGHT`,
`LOAD_SHED_API_MAX_INFLIGHT`, `LOAD_SHED_FRESH_ANALYSIS_MAX_INFLIGHT`,
`LOAD_SHED_LLM_MAX_INFLIGHT`, `LOAD_SHED_OUTBOUND_MAX_INFLIGHT`,
`LOAD_SHED_RETRY_AFTER_S`; аварийный выключатель — `LOAD_SHED_ENABLED=false`.
* растёт `shed` при высоком CPU — не хватает мощности: добавить реплику
  (лимиты не поднимать — принятые запросы снова начнут опаздывать);
* растёт `dns.shed` при низком CPU — тормозит апстрим: поднять
  `LOAD_SHED_DNS_MAX_INFLIGHT`;
* растёт `fresh_analysis.shed` при низком CPU — источники медленные: можно
  поднять `LOAD_SHED_FRESH_ANALYSIS_MAX_INFLIGHT` (и `OUTBOUND` до ×13 от него).

### Замер до/после (2026-10-23)

Docker на машине был неисправен, поэтому замер **нативно** (macOS, i5-9600K,
без лимита CPU, 2 воркера `uvicorn` на 2 ядрах), стенд из `scripts/capacity`
(«Как повторить без Docker» ниже): `stub_app` с заглушками источников,
заглушки апстрима DoH и Cloudflare по HTTP/2 + TLS, Redis — `fake_redis.py`
(650 тыс. имён), нагрузка — `loadgen.py` (открытый цикл, как
constant-arrival-rate у k6), по 30 с. «До» — `origin/main`, «после» — эта
ветка, на одном стенде. Машину параллельно грузили другие задачи (load
average 5–18 во время «до», 5–7 во время «после»; в более шумных прогонах
картина та же). Задержка — от запланированного момента отправки; таймаут
генератора 10 с (DNS, `/health`) и 15 с (проверки). RSS — пик суммы мастера и
двух воркеров; в покое ~530–545 МБ (воркер ~250 МБ: ML-модель и список
DoH-фильтра).

| сценарий | до: p50 / p95 отвеченных | до: потери | до: RSS | после: p50 / p95 отвеченных | после: `503` | после: RSS |
|---|---:|---:|---:|---:|---:|---:|
| DoH 2 000/с (~2× предел) | 7 мс / 4,0 с | — | 597 МБ | 7 мс / 3,2 с | 17 % | 587 МБ |
| `/health` 2 500/с | 3,9 с / 5,4 с | 17 % таймаутов, 53 % не отправлено¹ | **1 332 МБ** (воркер 960) | **102 мс / 246 мс** | 69 % | 537 МБ |
| свежие проверки 300/с (~3×) | 9,0 с / 12,8 с | 66 % таймаутов, 20 % не отправлено | 759 МБ | **0,57 с / 0,81 с** | 79 % | 528 МБ |
| DNS 400/с² + свежие проверки 300/с: **DNS** | 1,0 с / 7,9 с | 19 % таймаутов | 774 МБ | **3,5 мс / 62 мс**, все ответы | 0 | 553 МБ |
| …то же: проверки | 12,2 с / 14,8 с | 57 % таймаутов, 21 % не отправлено | | 0,58 с / 0,90 с | 80 % | |
| DNS 400/с² + проверки из кэша 2 000/с: **DNS** | 0,74 с / 7,6 с | 11 % таймаутов | 789 МБ | **26 мс** / 4,1 с³, все ответы | 0 | 557 МБ |
| …то же: проверки | 11,0 с / 13,5 с | 21 % таймаутов, 65 % не отправлено | | 0,41 с / 1,4 с | 80 % | |

¹ генератор упёрся в 6 000 открытых соединений. ² закэшированные имена (топ-50,
кэш прогрет до начала) — то, что телефон спрашивает чаще всего. ³ хвост —
~15 % промахов кэша, которые ждут заглушку апстрима: Python на той же машине
под этой нагрузкой не отвечал за 4 с (`upstream_failed` в `/health/doh`, и «до»
тоже); в проде апстрим — Cloudflare. DoH-перегрузка в этом стенде упирается в
ту же заглушку, поэтому разница там мала; в более шумных прогонах «до» давало
p50 1,6–3,5 с, «после» — 5–7 мс. В обычной нагрузке (DNS 400/с + проверки
100/с) — 0 отказов.

Вывод: за пределом сервер больше не копит запросы — память остаётся у уровня
покоя (на `/health`-перегрузке было 1,3 ГБ), принятые запросы отвечают за
доли секунды, а не за 4–12 с, и DNS из кэша отвечает за миллисекунды, пока
API затоплен. Ёмкость это не добавляет: отказанный запрос — отказ,
масштабировать по-прежнему заранее.

## Что ещё видно, но не исправлено

* ~~Нет сброса нагрузки (load shedding)~~ — исправлено 2026-10-23, раздел
  «Сброс нагрузки» выше. Лимиты на воркер, не на реплику: балансировщик
  Railway о них не знает и шлёт запросы и в воркер, который отказывает.
* Каждый не-DNS запрос проходит два `BaseHTTPMiddleware` и пишет JSON-строку
  лога (~3 мс CPU в VM) — это «пол» для `/check` и `/health`.
* ~~В строках `analysis_complete` поле `level` (уровень риска) перезаписывало
  уровень лога~~ — исправлено 2026-10-22: уровень риска теперь в поле
  `verdict`, `level` всегда уровень лога (`api/services/logger.py`).
* Признаки ML для свежего анализа: ~10 мс CPU (difflib по ~140 брендам).

## Как повторить

```bash
docker build -t cleanway-api .
docker network create cwcap
docker run -d --name cwcap-redis --network cwcap redis:7 redis-server --save ''
docker run --rm --network cwcap -e REDIS_URL=redis://cwcap-redis:6379 \
  -v $PWD/scripts:/app/scripts:ro cleanway-api \
  sh -c 'python scripts/doh_loadtest.py seed --count 650000 && python scripts/capacity/seed_extra.py'

# HTTP/2 + TLS upstream stub (self-signed cert for CN/SAN "upstream")
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 30 \
  -subj /CN=upstream -addext subjectAltName=DNS:upstream
docker run -d --name cwcap-up --network cwcap --network-alias upstream \
  -v $PWD/scripts:/repo/scripts:ro -v $PWD:/certs:ro -w /repo/scripts/capacity \
  python:3.11.15-slim-bookworm sh -c 'pip install hypercorn==0.17.3 uvloop==0.21.0 && \
  hypercorn --workers 3 --worker-class uvloop --certfile /certs/cert.pem \
  --keyfile /certs/key.pem --bind 0.0.0.0:8443 stub_upstream:app'

# The API: certifi bundle + the stub's cert, so TLS context cost is realistic
docker run --rm cleanway-api sh -c 'cat $(python -c "import certifi;print(certifi.where())")' > bundle.pem
cat cert.pem >> bundle.pem
docker run -d --name api --network cwcap --cpus 1 --memory 1g \
  -e REDIS_URL=redis://cwcap-redis:6379 -e WEB_CONCURRENCY=2 -e PORT=8080 \
  -e DOH_UPSTREAMS=https://upstream:8443/dns-query -e SSL_CERT_FILE=/certs/bundle.pem \
  -e DOH_RATE_LIMIT_PER_WINDOW=1000000000 -e PUBLIC_RATE_LIMIT_PER_WINDOW=1000000000 \
  -e PUBLIC_FRESH_CHECKS_PER_MINUTE=1000000000 -e PUBLIC_FRESH_IP_CEILING_PER_MINUTE=1000000000 \
  -e PYTHONPATH=/app/scripts/capacity:/app -v $PWD/scripts:/app/scripts:ro -v $PWD:/certs:ro \
  cleanway-api sh -c 'exec python -m uvicorn stub_app:app --host 0.0.0.0 --port 8080'

# Load: RATE req/s for DUR; MODE = hit | miss | allow | health
docker run --rm --network cwcap -v $PWD:/repo -w /repo/scripts/capacity -e RATE=500 -e DUR=30s \
  grafana/k6 run k6_doh.js
docker run --rm --network cwcap -v $PWD:/repo -w /repo/scripts/capacity -e RATE=50 -e MODE=hit \
  grafana/k6 run k6_public.js
# CPU per request: read /sys/fs/cgroup/cpu.stat usage_usec in the api container before/after.
# Profile: docker run --rm --pid=container:api --cap-add SYS_PTRACE <image with py-spy> py-spy record -p <worker pid>
```

Перегружать стенд дольше 30 с бессмысленно: после насыщения контейнер ещё
минуты разгребает очередь — перезапускайте его между сериями.

### Как повторить без Docker

Так снят замер «Сброс нагрузки». Всё на одной машине, только локально.
`hypercorn` и `fakeredis` — для стенда, не зависимости проекта.

```bash
uv venv -p 3.11 /tmp/cap && uv pip install --python /tmp/cap/bin/python -r requirements.txt \
  hypercorn==0.17.3 "fakeredis[lua]==2.40.0"
PY=/tmp/cap/bin/python
$PY scripts/capacity/fake_redis.py --port 16391 --count 650000 &   # или настоящий redis-server

openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 30 \
  -subj /CN=upstream -addext "subjectAltName=IP:127.0.0.1"
cat "$($PY -c 'import certifi;print(certifi.where())')" cert.pem > bundle.pem
# DoH upstream on 18443 (4 workers), the Cloudflare comparison on 18444 (2) — separate,
# so a flood of public checks does not starve the DNS upstream
for spec in 18443:4 18444:2; do
  (cd scripts/capacity && REPO_SCRIPTS=$PWD/.. $PY -m hypercorn --workers ${spec#*:} --worker-class uvloop \
    --certfile ../../cert.pem --keyfile ../../key.pem --bind 127.0.0.1:${spec%:*} stub_upstream:app) &
done

REDIS_URL=redis://127.0.0.1:16391 WEB_CONCURRENCY=2 SSL_CERT_FILE=$PWD/bundle.pem \
  DOH_UPSTREAMS=https://127.0.0.1:18443/dns-query STUB_UPSTREAM=https://127.0.0.1:18444 \
  DOH_RATE_LIMIT_PER_WINDOW=1000000000 PUBLIC_RATE_LIMIT_PER_WINDOW=1000000000 \
  PUBLIC_FRESH_CHECKS_PER_MINUTE=1000000000 PUBLIC_FRESH_IP_CEILING_PER_MINUTE=1000000000 \
  PUBLIC_FRESH_IP_CEILING_PER_WINDOW=1000000000 PYTHONPATH=scripts/capacity:. \
  $PY -m uvicorn stub_app:app --host 127.0.0.1 --port 18080 --timeout-keep-alive 75 &
API=$!

# Warm: the 500 names of MODE=hit into the public cache, the top-50 names into the DNS cache
for i in $(seq 0 499); do curl -s -o /dev/null http://127.0.0.1:18080/api/v1/public/check/shop$i.capstore.com; done
$PY scripts/capacity/loadgen.py --mode doh-cached --rate 400 --duration 5 > /dev/null

# Load: one JSON line per run. A new --seed every run (the "miss" names must be unseen);
# --preconnect opens the connections first (macOS accepts 128 at a time).
$PY scripts/capacity/loadgen.py --mode doh --rate 2000 --duration 30 --procs 2 --preconnect 3000 \
  --seed $RANDOM --rss-pid $API
$PY scripts/capacity/loadgen.py --mode health --rate 2500 --duration 30 --procs 2 --preconnect 3000 --rss-pid $API
$PY scripts/capacity/loadgen.py --mode miss --rate 300 --duration 30 --timeout 15 --preconnect 3000 --seed $RANDOM
# DNS while the API is flooded: both at once
$PY scripts/capacity/loadgen.py --mode miss --rate 300 --duration 30 --timeout 15 --preconnect 3000 --seed $RANDOM &
$PY scripts/capacity/loadgen.py --mode doh-cached --rate 400 --duration 30 --preconnect 1500 --rss-pid $API
curl -s http://127.0.0.1:18080/health/doh   # load_shed: what was refused, and why
```

«До» — то же из `git archive origin/main api scripts data` (скопировав в него
`scripts/capacity/`). API перезапускать между прогонами.
