# Коды входа по почте: настройка, проверка, сбои

Вход в Cleanway — по 6-значному коду из письма. Письмо отправляет **Supabase
Auth** через SMTP **Resend** (`smtp.resend.com`, отправитель
`no-reply@cleanway.ai`, домен `cleanway.ai` в регионе Resend `eu-west-1`).
Настраивает всё скрипт `bash scripts/wire-supabase-smtp.sh`
(`scripts/supabase_mail.py`): SMTP, русские шаблоны, DNS-записи, проверку.

Не приходят коды — никто не может войти, зарегистрироваться, купить подписку
на сайте. Письма самого API (приветствие, тревоги безопасности) идут другим
путём — через HTTP API Resend из Railway (`email.md`); общий у них только ключ
Resend (`security-incident.md`, «Ротация ключей»).

Этот файл заменяет `docs/EMAIL_SIGNIN.md`, на который ссылались скрипты, —
его в репозитории никогда не было.

## Проверить, что всё работает (5 минут)

1. **Живая конфигурация Supabase Auth** (нужен `SUPABASE_ACCESS_TOKEN` в
   корневом `.env`, он не попадает в git):
   ```bash
   bash scripts/wire-supabase-smtp.sh --step verify
   ```
   Ждём: `smtp_host: smtp.resend.com`, `emails per hour` больше 2,
   `otp length/exp: 6 digits / 600 s (10 min)`, `code in templates: yes` и в
   конце `SMTP wired — sign-in can scale`. `smtp_host: (built-in Supabase
   mailer — 2 emails/hour)` значит, что SMTP отключён: письма получают только
   участники проекта, 2 в час.
2. **Resend** → Domains → `cleanway.ai`: статус **Verified** (SPF/DKIM).
   Не Verified — `bash scripts/wire-supabase-smtp.sh --provider resend --step dns --check-dns`
   покажет, каких записей в DNS (Cloudflare) не хватает.
3. **Resend** → Emails: последние письма от `no-reply@cleanway.ai` —
   Delivered. Bounced / Complained — смотреть получателя и причину.
4. **Resend** → Settings → Usage / Billing: на бесплатном тарифе **100 писем
   в день и 3 000 в месяц** на всё (коды и письма API вместе). Исчерпали — коды
   перестают уходить до следующего дня; это самая вероятная причина массового
   сбоя после запуска.
5. **Живой тест**: на `cleanway.ai` или в приложении запросить код на свой
   адрес — письмо за минуту, код подходит.

## Если коды не приходят

1. **Supabase** → проект → **Logs → Auth**: найти запрос `/otp` (или
   `/signup`) на этот адрес. Ошибки вида `Error sending … email` / `gomail` /
   `535 Authentication` — SMTP не принимает ключ: перейти к «Ротации ключа»
   ниже. `429` / `over_email_send_rate_limit` — сработал лимит Supabase
   (`emails per hour` из шага 1, по умолчанию 200 в час; одному адресу — не
   чаще раза в 60 с).
2. **Resend → Emails**: письма нет совсем — Supabase его не отправил (п. 1);
   есть и Delivered — оно у человека в «Спаме» или у его почты задержка
   (Mail.ru / Яндекс иногда держат минуты); Bounced — адрес не существует.
3. **Лимит Resend** (шаг 4 выше): исчерпан — поднять тариф (Pro, $20 в месяц,
   50 000 писем) или ждать сброса.
4. **Домен** (шаг 2): `Verified` пропал — кто-то менял DNS `cleanway.ai` в
   Cloudflare; вернуть записи из `--step dns`.
5. Проверка — снова «Живой тест».

## Ротация ключа Resend

Ключ один на два места: SMTP-пароль Supabase и `RESEND_API_KEY` в Railway.

1. Resend → API Keys → **Create** (доступ Sending, домен `cleanway.ai`).
2. Supabase: `SMTP_PROVIDER=resend SMTP_PASS=<новый ключ>` в корневом `.env`,
   затем
   ```bash
   bash scripts/wire-supabase-smtp.sh --provider resend --step smtp --apply
   bash scripts/wire-supabase-smtp.sh --step verify
   ```
   (`--force`, если кроме пароля ничего не поменялось.)
3. Railway → `web` → Variables → `RESEND_API_KEY` = новый ключ (сервис
   перезапустится).
4. «Живой тест» входа, и только потом — Resend → API Keys → удалить старый.

## Что пока не наблюдается

Ни минутный монитор (`ops/uptime-worker`), ни DNS canary, ни `/health/deep`
не проверяют, что код входа доходит. `/health/deep` про почту молчит
намеренно: ключ API — с доступом только на отправку, состояние домена им не
прочитать, а вечное «предупреждение» заглушило бы остальные тревоги монитора.

**Проект канарейки входа** (делать, когда будет готовность завести тестовый
адрес):

1. **Адрес-приёмник.** Cloudflare → Email Routing: `signin-canary@cleanway.ai`
   → Email Worker (`email()`-обработчик), который при письме от
   `no-reply@cleanway.ai` записывает в KV только время получения. Текст
   письма не сохраняется — код в нём действующий.
2. **Тестовый пользователь** с этим адресом — создаёт основатель (Supabase →
   Authentication → Add user), исключить его из метрик.
3. **Запрос кода** раз в 6 часов из минутного монитора:
   `POST https://bpyqgzzclsbfvxthyfsf.supabase.co/auth/v1/otp` с
   `{"email": "signin-canary@cleanway.ai", "create_user": false}` и
   публичным ключом; время запроса — в KV. Если в Supabase включена captcha,
   запрос без токена captcha отклонят — тогда сначала проверить, пропускает
   ли Supabase такой запрос с серверным ключом, иначе канарейка невозможна.
4. **Тревога**, если через 10 минут после запроса письма нет — обычным письмом
   монитора («не работает signin_mail»); заодно оно проверяет лимит Resend.
5. **Цена**: 4 письма в день из лимита Resend и Supabase.
