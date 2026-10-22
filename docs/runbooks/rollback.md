# Откат: production сломан или деградировал

Переписано 2026-10-22. Прежняя версия судила по `/health` (он всегда 200),
называла несуществующий сервис `cleanway-api-prod` и флаг
`FEATURE_EMAIL_WEEKLY`, которого нет в коде.

## Понять, что сломалось (1 минута)

1. **Письмо монитора** `Cleanway: не работает …` — имя проверки говорит что
   (таблица в `ops/uptime-worker/README.md`): `api`, `doh_resolve`,
   `doh_block`, `landing`, `install_page`, `blocklist`, `dns_filter`,
   `server_key`, `backup`.
2. **`curl -s https://api.cleanway.ai/health/deep`** — `status`, `warnings` и
   `components`: что именно не `ok` (`redis`, `supabase`,
   `supabase_server_key`, `blocklist`, `doh`). Для DNS —
   `curl -s https://api.cleanway.ai/health/doh` (`ok`, `filter.loaded`).
3. **Связано ли с деплоем.** Railway → `honest-playfulness` → `web` →
   Deployments: время последнего деплоя против начала проблемы; GitHub —
   последний коммит в `main`. Лендинг — Vercel → Deployments.

Сломалось сразу после деплоя — откатывайте, разбирайтесь потом.

## API и DNS (Railway), ~2 минуты

1. Railway → `honest-playfulness` → `web` → **Deployments**.
2. Последний рабочий деплой (обычно сразу под сломанным) → **⋯** →
   **Redeploy**.
3. Проверить `/health/deep` и `/health/doh` (выше); письмо монитора
   «снова работает» придёт само через пару минут.
4. **Сразу** откатить и сам коммит: `git revert <sha>` → PR → merge. Иначе
   следующий merge в `main` выкатит поломку снова.

## Лендинг (Vercel), ~1 минута

Vercel → проект лендинга → **Deployments** → последний рабочий → **⋯** →
**Promote to Production** (Instant Rollback). Затем revert-PR, как выше.

## Без отката: выключатели

Railway → `web` → **Variables**; после изменения сервис перезапустится сам.

| Переменная | Что делает |
|---|---|
| `RETENTION_PURGE=off` | останавливает удаление данных по срокам (`data-retention.md`) |
| `BILLING_ENABLED=false` | убирает маршруты российского биллинга (`docs/BILLING.md`; действует только в деплое `ROLE=billing`) |
| `IPQS_DAILY_BUDGET=0`, `LLM_JUDGE_DAILY_BUDGET=0`, `EXPLAINER_DAILY_BUDGET=0` | выключают платные источники и LLM |
| `PUBLISH_CONFIRMED_THREATS`, `LOOKALIKE_GENERATOR_ENABLED` — удалить | перестают публиковать собственные хосты в список; удалить **и** в Railway, **и** в GitHub → Settings → Secrets and variables → Actions → Variables (`monitoring.md`) |
| `DOH_FAST_PATH=false` | DNS-запросы идут через обычный стек (для отладки шлюза) |
| `SECURITY_ALERTS_ENABLED=false` | глушит письма о тревогах (если шумят) |

Список, заблокировавший нормальный сайт для всех на DNS-профиле, —
`monitoring.md`, «When the DNS canary goes red» → `BLOCKED A POPULAR NAME`.

## База

Откат миграции почти всегда теряет данные: лучше новая миграция, которая
исправляет предыдущую. Если данные испорчены — восстанавливать **в новый
проект**, никогда поверх production: снимок Supabase (Database → Backups)
или ночная копия из R2 (`restore.md`), потом переключить переменные.

## Частые случаи

- **Supabase недоступен** — `/health/deep` 503, `supabase` не ok. Проверки
  сайтов работают (им база не нужна), вход, аккаунты и оплаты — нет. Откат не
  поможет: status.supabase.com, ждать.
- **Redis недоступен** — `/health/deep` 503, `redis` не ok; DNS отвечает, но
  фильтр может не блокировать (`doh` в `warnings`). Railway → сервис `Redis` →
  Deployments → Restart.
- **Не работает серверный ключ Supabase** — `server_key` / `supabase_server_key`:
  удаление аккаунтов и записи сервера падают. Ключ поменяли или отключили
  legacy-ключи — `supabase-jwt-signing-keys.md`.
- **Платёж не дошёл до аккаунта** — письмо `webhook_processing_failed`
  (`security-incident.md`).
- **Не приходят коды входа** — `sign-in-email.md`.

## После

В течение дня: короткая запись в `CHANGELOG.md` или отдельный разбор в
`docs/runbooks/` — когда началось и закончилось (UTC), что видели
пользователи, что сделали, что поменять, чтобы не повторилось.
