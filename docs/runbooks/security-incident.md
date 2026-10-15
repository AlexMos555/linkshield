# Runbook: письмо «Cleanway security: …»

API само считает подозрительные события и присылает письмо, когда их
становится необычно много (код: `api/services/security_alerts.py`). Одно
письмо на событие не чаще раза в час (бюджет платных источников — раз в
сутки), даже если атака продолжается. Письмо — это повод посмотреть, а не
доказательство взлома: начните с логов.

## Настройка (один раз)

Railway → проект `honest-playfulness` → сервис `web` → Variables:

| Переменная | Значение |
|---|---|
| `SECURITY_ALERT_EMAIL` | ваш адрес для тревог (личная почта основателя) |
| `RESEND_API_KEY` | ключ Resend (`re_...`), тот же, что для писем Supabase |
| `SECURITY_ALERT_FROM` | не обязательно; по умолчанию `alerts@cleanway.ai` (домен уже подтверждён в Resend) |

Без `SECURITY_ALERT_EMAIL` писем нет — только строка `CRITICAL security_alert`
в логах (и событие в Sentry). Порог любого правила меняется переменной
`SECURITY_ALERT_THRESHOLD_<СОБЫТИЕ>` (для правила «на одного
пользователя/ключ» — с суффиксом `_PER_KEY`), `0` выключает правило,
`SECURITY_ALERTS_ENABLED=false` выключает всё.

## Что значит каждое письмо

| Событие | Порог по умолчанию | Что значит | Что сделать первым |
|---|---|---|---|
| `auth_invalid_token` | 200 за 5 мин | Поддельные/чужие/битые токены входа (истёкшие не считаются) | Логи `jwt_invalid`, `jwt_unknown_signing_key`, `jwt_algorithm_refused`. Если похоже на утечку ключа подписи — ротация ключей JWT (`supabase-jwt-signing-keys.md`) |
| `reauth_required` | 50 за 5 мин; 10 за час на пользователя | Удаление аккаунта / сессия расширения со старым (возможно украденным) токеном | `audit_log` по пользователю; завершить его сессии (ниже) |
| `user_export` | 20 за 5 мин всего; 4 за час на пользователя | Массовая выгрузка данных — типичный след захвата аккаунтов | `audit_log`, логи `/user/export`; завершить сессии затронутых |
| `account_delete` | 5 за 5 мин | Много удалений аккаунтов подряд | `audit_log` (`account.delete_requested`); у людей 30 дней на восстановление |
| `webhook_signature_invalid` | 5 за 5 мин на провайдера | Вебхук Stripe / RevenueCat / биллинга / партнёра с неверной подписью | Подделка или сменился секрет у провайдера. Сверить секрет в Railway и в дашборде провайдера; при сомнении — перевыпустить |
| `ssrf_blocked` | 50 за 5 мин | Кто-то пытается заставить сервер ходить во внутреннюю сеть | Блокировка сработала. Логи `SSRF attempt blocked`, `redirect_hop_blocked`; при упорстве — блок источника (ниже) |
| `paid_budget_exhausted` | 1 раз в сутки на источник | Дневной бюджет IPQS / LLM кончился | Логи `paid_budget_exhausted`, `ip_rate_limit_exceeded`: бот или рост трафика? Сбросится в полночь UTC |
| `rate_limited` | 1000 отказов 429 за 5 мин на категорию | Всплеск упёршихся в лимит запросов (бот, DDoS) | Логи `ip_rate_limit_exceeded`, категория — в письме |
| `admin_or_service_key_use` | 30 за 5 мин; 5 за час на пользователя | Сервисный ключ Supabase выпускает сессии расширения от имени запросов | Логи `extension_session_*`; при подозрении — завершить сессии пользователя |

## Первые шаги (10 минут)

1. **Логи.** Railway → `web` → Logs, поиск `security_alert`, затем имя события
   и соседние строки (`jwt_invalid`, `webhook_signature_invalid`,
   `ip_rate_limit_exceeded` …). Посмотрите, идёт ли ещё, с каких путей и
   категорий. Ошибки — в Sentry.
2. **Кто пострадал.** Supabase → SQL Editor:
   `select * from audit_log order by created_at desc limit 100;`
   (IP там только в виде хэша).
3. **Завершить сессии.** Одного пользователя:
   `delete from auth.sessions where user_id = '<uuid>';` — всех:
   `delete from auth.sessions;`. Уже выданные access-токены живут до часа;
   чтобы убить и их — ротация ключа подписи JWT
   (`docs/runbooks/supabase-jwt-signing-keys.md`).
4. **Решить: атака продолжается и вредит?** Тогда ротация ключей и/или
   остановка (ниже). Нет — запишите вывод и, если порог шумит, поднимите его
   переменной.

## Ротация ключей (если мог утечь секрет)

Меняйте в источнике, затем в Railway Variables (сервис перезапустится):

- **Supabase service_role и anon / publishable** — Project Settings → API Keys.
  Anon-ключ зашит в приложения и сайт: после смены нужны новые сборки.
- **Ключ подписи JWT Supabase** — `supabase-jwt-signing-keys.md`.
- **Stripe** — Developers → Webhooks → Roll secret → `STRIPE_WEBHOOK_SECRET`;
  при утечке и `STRIPE_SECRET_KEY` (API keys → Roll).
- **RevenueCat** — `REVENUECAT_WEBHOOK_AUTH` (и в дашборде RevenueCat),
  `REVENUECAT_SECRET_API_KEY`.
- **Resend** — API Keys → новый ключ → `RESEND_API_KEY` в Railway и SMTP-пароль
  Supabase (`scripts/wire-supabase-smtp.sh`), старый удалить.
- **Остальные переменные Railway** — `UNSUBSCRIBE_HMAC_KEY`,
  `AUDIT_IP_HASH_KEY`, ключи платных источников (IPQS, Anthropic и др.).
- **GitHub** — Settings → Developer settings → токены; секреты репозитория
  (Settings → Secrets and variables → Actions); проверить Deploy keys.

## Остановить или прикрыть API

- **Блок источника.** `api.cleanway.ai` в Cloudflare сейчас DNS-only (серое
  облако), поэтому WAF не действует. Чтобы включить фильтрацию: DNS → запись
  `api` → Proxied (оранжевое облако), SSL/TLS = Full (strict), затем
  Security → WAF (правило по IP/стране/пути) или Under Attack Mode.
  `dns.cleanway.ai` не проксируйте — DoH телефонов сломается.
- **Полная остановка.** Railway → `web` → Deployments → активный деплой →
  ⋯ → Remove. API и DNS-фильтр (`dns.cleanway.ai`) перестанут отвечать.
  Вернуть: тот же деплой → Redeploy (`docs/runbooks/rollback.md`).
- **Точечно.** Платные источники выключаются бюджетом
  (`IPQS_DAILY_BUDGET=0` и т.п.).

## Кому писать

- Supabase — Dashboard → Support (приоритет «security»).
- Stripe — dashboard.stripe.com/support; RevenueCat — app.revenuecat.com → Support.
- Railway — station.railway.com; Resend — resend.com/help; GitHub — support.github.com.
- Если утекли **персональные данные пользователей**: зафиксируйте время
  обнаружения. По GDPR (пользователи из ЕС) надзорный орган уведомляется
  в течение 72 часов, затронутые пользователи — без задержки при высоком
  риске; для ОАЭ — PDPL. Обратитесь к юристу в тот же день.
- Внешние сообщения об уязвимостях приходят на `security@cleanway.ai`
  (`SECURITY.md`).

После инцидента: короткая запись в `CHANGELOG.md` или отдельный разбор в
`docs/runbooks/` (что было, что сделали, какой порог поправили).
