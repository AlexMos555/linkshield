# Деплой: как код попадает в production

Переписано 2026-10-22. Прежняя версия описывала автоматический staging,
ручной запуск «Deploy to production» и одобрение вторым человеком — ничего
из этого нет. Ниже — как есть на самом деле.

## Что где живёт и как выкатывается

| Что | Где | Как выкатывается |
|---|---|---|
| API и DNS-шлюз (`api.cleanway.ai`, `dns.cleanway.ai`) | Railway, проект `honest-playfulness`, сервис `web` (EU West, 2 реплики) + сервис `Redis` | **Сам, на каждый коммит в `main`** (интеграция Railway с GitHub). Railway собирает корневой `Dockerfile`; старые реплики работают, пока новая не ответит на health check `/health`. Статус виден на коммите в GitHub: `honest-playfulness - web` |
| Лендинг `cleanway.ai` | Vercel (`landing/vercel.json`) | Production — сам, на каждый коммит в `main`; на каждый PR — превью (статус `Vercel` в PR) |
| База | Supabase `bpyqgzzclsbfvxthyfsf` (EU) | **Не автоматически.** Миграции из `supabase/migrations/` применяет основатель вручную (SQL Editor) |
| Мониторы | Cloudflare Workers `cleanway-uptime`, `cleanway-backup-sink` | Вручную: загрузить `worker.js` (`ops/uptime-worker/README.md`, `ops/backup-sink/README.md`) |
| Приложения, расширения | сторы | отдельно (`docs/STORES.md`, `docs/CWS_SUBMISSION.md`) |

Staging-окружения нет. Workflow `deploy-staging.yml` (только ручной запуск,
нет ни сервиса, ни секретов; последние запуски — апрель 2026, все упали) и
`deploy-production.yml` (3 запуска 2026-08-18, все упали) удалены 2026-10-23:
ни один деплой через них не шёл. Деплой — только интеграция Railway с GitHub
(выше), GitHub-секреты Railway (`RAILWAY_TOKEN_*`, `RAILWAY_SERVICE_*`,
`STAGING_HEALTH_URL`, `PROD_HEALTH_URL`) не нужны.

## Коротко

1. Ветка (`fix/…`, `feat/…`) и PR. В описании: что и зачем, новые миграции,
   новые переменные окружения, как откатить.
2. CI зелёный: `test`, `lint`, `openapi-drift`, `mobile`, `docker`, Security
   (`gitleaks`, `bandit`, `pip-audit`, `npm-audit`, `trivy`, `hadolint`),
   CodeQL. Для лендинга — ещё `e2e-landing`: его задачи стартуют поздно,
   дождитесь их до merge.
3. Если нужна миграция или переменная — **до** merge: миграцию в SQL Editor
   (код должен работать и со старой, и с новой схемой), переменную — Railway →
   `web` → Variables (сервис перезапустится сам).
4. Merge в `main`. Railway и Vercel выкатывают сами (обычно несколько минут).
5. Проверить:
   ```bash
   curl -s https://api.cleanway.ai/health/deep   # 200, "status":"ok", "warnings":[]
   curl -s https://dns.cleanway.ai/health/doh    # "ok":true, "filter":{"loaded":true,…}
   gh api repos/AlexMos555/linkshield/commits/<sha>/statuses \
     --jq '.[] | [.context, .state, .description] | @tsv'   # web и Vercel — success
   ```
   По желанию: GitHub → Actions → **DNS canary** → Run workflow (полная
   проверка DNS снаружи, ~1 минута).
6. Минут 10 смотреть: письма монитора (`Cleanway: не работает …`), Railway →
   `web` → Logs, Sentry. Что-то не так — [rollback.md](rollback.md).

`/health` для проверки не годится: он всегда 200, пока процесс жив (это
liveness-проверка Railway).

## Если деплой не прошёл

1. Статус `honest-playfulness - web` на коммите → ссылка на деплой → Build /
   Deploy logs. Частые причины:
   - `ModuleNotFoundError` — зависимость не в `requirements.txt`;
   - сканер уязвимостей Railway остановил сборку — обновить пакет (для
     транзитивных — `overrides` в `package.json`);
   - `ConfigError: … is required in environment=production` — не хватает
     переменной в Railway → `web` → Variables.
2. Пока новая версия не прошла health check, работает предыдущая — пользователи
   поломки не видят. Чините следующим PR.

## Срочное исправление

Тот же путь: PR → CI → merge. Обходной дороги нет и не нужна — Railway
выкатит merge за минуты. Если CI сломан не по вашей вине (упал внешний
сервис), перезапустите упавшую задачу; упала второй раз — это не случайность.
Быстрее любого исправления — откат ([rollback.md](rollback.md)).
