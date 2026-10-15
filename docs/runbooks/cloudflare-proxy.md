# Cloudflare-прокси («оранжевое облако») перед api.cleanway.ai

**Для кого:** основатель (что нажать и зачем) и Claude (точные проверки).
**Состояние на 2026-10-15:** DNS зоны `cleanway.ai` уже в Cloudflare, все записи
серые (DNS only). Код готов к включению прокси (PR `feat/cloudflare-proxy-ready`).
Переключение — ручной шаг основателя в панели Cloudflare; Claude настройки
Cloudflare и Railway не меняет.

## Коротко

| Имя | Решение | Почему |
|---|---|---|
| `api.cleanway.ai` | **включить прокси** (оранжевое облако) | WAF, защита от DDoS, rate limiting на краю Cloudflare |
| `dns.cleanway.ai` | **оставить DNS only** (серое облако) | см. «Почему dns.cleanway.ai остаётся серым» |

## Что сделано в коде (зачем это было нужно)

Цепочка при включённом прокси: **клиент → край Cloudflare → край Railway
(100.64.0.0/10) → приложение**. Railway дописывает в `X-Forwarded-For` адрес
того, кто к нему подключился, — то есть адрес Cloudflare, а не пользователя.
Без доработки все пользователи за одним узлом Cloudflare попали бы в одну
корзину rate limit, и DNS/проверки ссылок начали бы получать 429.

Теперь `api/services/rate_limiter.py` (`_extract_client_ip`):

1. Идёт по `X-Forwarded-For` справа налево, пропуская адреса Railway
   (`TRUSTED_PROXY_CIDRS=100.64.0.0/10`), как и раньше.
2. Если первый «чужой» адрес — **из официальных диапазонов Cloudflare**
   (`api/data/cloudflare_ips.txt`), клиентом считается `CF-Connecting-IP`
   (Cloudflare сам перезаписывает этот заголовок). Нет заголовка или он битый —
   берётся адрес ровно на шаг левее (его дописал Cloudflare).
3. В любом другом случае `CF-Connecting-IP` **игнорируется**: его может
   подделать кто угодно, обратившись к Railway напрямую.
4. Без прокси поведение не изменилось.

`TRUSTED_PROXY_CIDRS` менять **не нужно** (Cloudflare в неё добавлять не надо;
если добавить — ничего не сломается).

Телеметрия (лог `doh_stats` раз в 5 минут, поле `proxy_peers`, только агрегаты,
без адресов):

| ключ | значит |
|---|---|
| `100.64.0.0/10\|xff=1\|trusted` | запрос пришёл через край Railway — норма |
| `cloudflare\|client=header` | запрос прошёл через Cloudflare, клиент взят из `CF-Connecting-IP` — норма после включения |
| `cloudflare\|client=xff` | через Cloudflare, но без заголовка — должно быть около 0 |
| `cloudflare_header_ignored` | кто-то прислал `CF-Connecting-IP` не через Cloudflare (подделка / прямой заход на Railway) — заголовок проигнорирован |
| `xff_ignored_untrusted_peer` | **тревога**: неверный `TRUSTED_PROXY_CIDRS`, все пользователи в одной корзине |

Диапазоны Cloudflare меняются редко. Обновление:
`python scripts/refresh_cloudflare_ips.py` (перезапишет файл) или
`--check` (код выхода 1, если файл устарел) → коммит диффа.

## Почему dns.cleanway.ai остаётся серым

Проверено по коду DoH (`api/services/doh_fastpath.py`, `api/routers/doh.py`):

- **Кэш не сломается**, но и не нужен. Ответ 200 несёт
  `Cache-Control: max-age=<минимальный TTL>` (RFC 8484 §5.1), ошибки и 429 —
  `no-store` (тесты `tests/test_doh_rfc8484.py`: `test_a_429_is_never_cacheable`,
  `test_a_get_answer_is_shared_cache_safe`). Ответ зависит только от URL (GET)
  или тела (POST — Cloudflare его не кэширует), `Set-Cookie` нет, согласования
  по `Accept` нет, поэтому `Vary` не нужен. По умолчанию Cloudflare кэширует
  только файлы со статическими расширениями — `/dns-query` в их число не входит.
- **HTTP/2 push** приложение не использует (uvicorn его не умеет, Cloudflare его
  отключил в 2022), к origin Cloudflare ходит по HTTP/1.1 — это совместимо.
- **Главный риск — проверки ботов.** DNS-клиент (профиль iOS, VPN-щит Android)
  не умеет проходить JS-челлендж. Любой challenge от Bot Fight Mode, Browser
  Integrity Check или managed-правила WAF = «нет интернета» на телефоне.
- **Задержка.** Лишний прыжок на каждый DNS-запрос, а их десятки на одну
  страницу.
- **Приватность.** Cloudflare начал бы видеть все имена (включая
  заблокированные) вместе с IP пользователя; сейчас он видит только
  незаблокированные имена от нашего сервера. Это потребовало бы правки политики
  конфиденциальности.

Если позже понадобится fail-open Worker из `docs/runbooks/doh-gateway.md`
(шаг 2), включать прокси на `dns.` только вместе с правилом, которое
пропускает `/dns-query` мимо всех проверок (см. ниже), и после правки политики.
Код определения IP для этого уже готов.

## Пре-чеки (Claude, до переключения)

1. PR `feat/cloudflare-proxy-ready` смёржен, деплой Railway зелёный:
   `curl -s -o /dev/null -w '%{http_code}\n' https://api.cleanway.ai/health` → `200`.
2. Railway → web → Variables: `TRUSTED_PROXY_CIDRS=100.64.0.0/10` (только чтение).
3. В логах Railway последний `doh_stats` → `proxy_peers` содержит
   `100.64.0.0/10|xff=1|trusted` и **не** содержит `xff_ignored_untrusted_peer`.
4. `python scripts/refresh_cloudflare_ips.py --check` → «up to date».
5. Сертификат origin валиден для имени (нужно для Full (strict)):
   `curl -sv https://api.cleanway.ai/health 2>&1 | grep -E 'subject:|issuer:|expire'`
   → subject `api.cleanway.ai`, срок не истёк.
6. `dig +short CAA cleanway.ai` — есть `letsencrypt.org` (Railway) и CA
   Cloudflare (Cloudflare добавляет их сам для Universal SSL).
7. Запомнить текущую цель CNAME `api` (`xxxx.up.railway.app`) — для отката она
   не меняется, меняется только облако.

## Переключение (основатель, ~5 минут)

1. **SSL/TLS → Overview → режим `Full (strict)`.** Railway отдаёт валидный
   сертификат Let's Encrypt, поэтому strict работает. Никогда не `Flexible`
   (бесконечные редиректы и трафик к origin по HTTP). Сейчас ни одна запись не
   проксируется, поэтому смена режима на зону ничего не задевает.
2. **SSL/TLS → Edge Certificates:** Minimum TLS `1.2`; `Always Use HTTPS` — можно
   включить. HSTS в Cloudflare не включать — приложение отправляет его само.
3. **Security → Bots → Bot Fight Mode: OFF.** На Free-плане его нельзя обойти
   правилом WAF Skip, а он ломает мобильное приложение, расширение браузера,
   вебхуки RevenueCat/Stripe и DNS. Block AI bots — тоже OFF для этой зоны
   (API не сайт).
4. **Security → WAF → Custom rules → Create rule** «API: skip browser checks»:
   - Expression: `(http.host eq "api.cleanway.ai")`
   - Action: **Skip** → отметить `Browser Integrity Check` и `Security Level`
     (на Free также видно `All remaining custom rules` — не отмечать).
   - Зачем: мобильные HTTP-клиенты и вебхуки без «браузерного» User-Agent не
     должны получать challenge.
5. **WAF → Managed rules:** на Free автоматически работает
   «Cloudflare Free Managed Ruleset» — оставить как есть (полный Cloudflare
   Managed Ruleset и OWASP — только Pro). Если увидим ложные блокировки —
   добавить исключение по пути, а не выключать целиком.
6. **WAF → Rate limiting rules** (на Free — 1 правило, окно 10 с, счёт по IP):
   - Name: `auth and export`
   - Expression:
     `(http.host eq "api.cleanway.ai" and (starts_with(http.request.uri.path, "/api/v1/auth/") or http.request.uri.path eq "/api/v1/user/export"))`
   - When rate exceeds: `20` requests per `10 seconds`, Action: Block, Duration:
     `10 seconds`.
   - Пороги щедрые специально: за одним IP оператора (CGNAT, Tele2) сидят
     сотни телефонов. Точные лимиты остаются в приложении. **Никогда** не
     ставить лимиты Cloudflare на `/dns-query`, `/api/v1/blocklist*`,
     `/api/v1/webhooks/*`, `/api/v1/payments/webhook`.
7. **Caching → Cache Rules:** на этом шаге ничего не добавлять. Если позже
   добавим кэш (например для `/api/v1/check`), правило обязано исключать
   `/dns-query`, `/api/v1/me/*`, `/api/v1/user/*` и всё с `Authorization`.
8. **DNS → Records → `api` → Edit → Proxy status: Proxied (оранжевое) → Save.**
   Цель CNAME не трогать. `dns` остаётся **DNS only**.

## Проверка после переключения (Claude, 5–10 минут)

1. `dig +short api.cleanway.ai` → адреса Cloudflare (104.x / 172.6x / 2606:4700:…).
2. `curl -sI https://api.cleanway.ai/health` → `HTTP/2 200`, есть `server: cloudflare`
   и `cf-ray`.
3. Один запрос к лимитируемому по IP эндпоинту:
   `curl -s -o /dev/null -w '%{http_code}\n' https://api.cleanway.ai/api/v1/pricing/tiers` → `200`.
4. `dns.cleanway.ai` не изменился: `dig +short dns.cleanway.ai` → CNAME на
   Railway (не Cloudflare); `curl -s -o /dev/null -w '%{http_code}\n' https://dns.cleanway.ai/health/doh` → `200`.
5. Через ≤ 5 минут в логах Railway `doh_stats` → `proxy_peers`:
   растёт `cloudflare|client=header`; `cloudflare|client=xff` ≈ 0;
   **нет** `xff_ignored_untrusted_peer`. Это и есть доказательство, что в логике
   лимитов реальные IP пользователей, а не адреса Cloudflare.
6. В течение часа: нет всплеска 429 (`rate_limited` в security alerts,
   `doh.counts.rate_limited`), Sentry спокоен, приложение и расширение работают
   (открыть приложение, проверить ссылку; расширение — проверить ссылку).
7. Security → Events: нет блокировок/челленджей на пути приложения
   (`/api/v1/check`, `/api/v1/public/*`, `/api/v1/blocklist`).

## Откат (1 минута)

**DNS → Records → `api` → Proxy status: DNS only (серое) → Save.** TTL записи
300 с — через ≤ 5 минут клиенты снова ходят напрямую в Railway. Код ничего
делать не нужно: без Cloudflare он работает как раньше. Режим SSL и правила WAF
можно не трогать — для серой записи они не применяются.

Когда откатывать сразу: `/health` не 200 через Cloudflare (ошибки 52x — проблема
SSL/origin, проверить режим `Full (strict)` и сертификат), массовые 403/challenge
в Security → Events для приложения, рост 429, жалобы «не работает».

## Остаточные риски (знать, но не блокеры)

- **Origin доступен в обход Cloudflare** (`xxxx.up.railway.app` и сам
  `api.cleanway.ai` по адресу Railway). Railway не умеет пускать только IP
  Cloudflare. WAF при прямом заходе не работает, но лимиты приложения работают
  по реальному IP: подделать `CF-Connecting-IP` нельзя. Если понадобится —
  Transform Rule с секретным заголовком и проверка в приложении (отдельная задача).
- Лимит Cloudflare на время ответа origin — 100 с, на тело запроса — 100 МБ
  (Free). Наши максимумы: голос 25 МБ, ответы — секунды.
- Подзапрос Cloudflare Worker из чужой зоны приходит с `CF-Connecting-IP` из
  адресов Cloudflare — такой клиент получит общую корзину, выбрать себе ключ
  он не может.
