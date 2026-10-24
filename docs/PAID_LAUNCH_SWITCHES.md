# Включение платных тарифов: переключатели по порядку

**Для кого:** основатель (что нажать и где), Claude (код и проверки).
**Состояние на 2026-10-24:** ничего из списка не включено, Cleanway бесплатный.
Начинать, когда решено брать деньги. Основа списка — анализ цен 2026-10-24: что
сделать по лицензиям и тарифам сервисов до первого платежа.

Правила:

- Идти по порядку. Шаги 1–11 денег не берут. С шага 12 сервер может принять
  платёж, а люди видят цены с шагов 13 и 15 (мир) и 18 (Россия).
- Шаги 7–10 (лицензии данных) закончить до первого платежа: бесплатные условия
  этих источников платный продукт не покрывают.
- **Основатель** — аккаунты, оплата сервисов, переменные production и кнопки
  деплоя (Claude менять переменные production запрещено). **Claude** — код (сначала
  тест), PR, тексты, проверки.
- Цены сервисов — публичные на октябрь 2026 и из
  [`ACCOUNTS_BILLING_PLAN.md`](ACCOUNTS_BILLING_PLAN.md) §4. Перед оплатой сверить
  на странице тарифа.

## Сводка

| № | Шаг | Кто | $ в месяц |
|---|---|---|---:|
| 0 | Проверить, что уже выключенное так и осталось | Claude | 0 |
| 1 | Paid Apps, налоговые формы, вопрос удержания налога в США | основатель + бухгалтер | 0 |
| 2 | Apple Small Business Program | основатель | 0 (−15 % комиссии) |
| 3 | Vercel Hobby → Pro | основатель | 20 |
| 4 | Supabase Free → Pro | основатель | 25 |
| 5 | Resend Free → Pro | основатель | 20 |
| 6 | Sentry: не трассировать `/dns-query`, потом тариф | Claude, основатель | 0–26 |
| 7 | Google Web Risk вместо Safe Browsing | основатель, Claude | 0 до 100 тыс. запросов |
| 8 | AlienVault OTX и PhishStats → `RESTRICTED_CHECKS` | Claude | 0 |
| 9 | Phishing.Database: #317 и один прогон с `force` | Claude, основатель | 0 |
| 10 | VirusTotal (и Safe Browsing) из публичного бенчмарка | основатель, Claude | 0 |
| 11 | `ENVIRONMENT=production` | основатель | 0 |
| 12 | Stripe: живой ключ, цены, вебхук, портал | основатель | комиссия с платежа |
| 13 | RevenueCat: Google Play и App Store | основатель, Claude | 0 до $2 500 выручки |
| 14 | Прогон e2e «stripe on» | Claude | 0 |
| 15 | `NEXT_PUBLIC_STRIPE_LIVE=1`, последним для сайта | основатель | 0 |
| 16 | Россия: юрлицо, договор с MIXPLAT, оферта | основатель + юрист | — |
| 17 | Россия: сервер и база в РФ (152-ФЗ), уведомление РКН | основатель, Claude | 45–70 |
| 18 | Россия: флаги операторской оплаты, `NEXT_PUBLIC_BILLING_ENABLED` последним | основатель, Claude | 0 |

Постоянные расходы мира — около $65–90 в месяц. Россия добавляет $45–70 и
комиссию оператора.

---

## 0. Что уже выключено — проверить, что так и осталось

Выключено в октябре 2026, подробности — в [`THIRD_PARTY_FEEDS.md`](THIRD_PARTY_FEEDS.md):

- `LICENSED_INTEL` по умолчанию `licensed` (с 2026-10-21): анализатор не спрашивает
  SURBL, Spamhaus DBL, URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker
  ([`api/services/licensed_intel.py`](../api/services/licensed_intel.py)).
- Переменная репозитория `BLOCKLIST_LICENSED_ONLY=true` (с 2026-10-22): список для
  телефонов собирается без OpenPhish, phishing.army, CSIRT Italia.
- `PUBLISH_CONFIRMED_THREATS` не задан: вердикты Safe Browsing и Web Risk в список не
  попадают, условия обоих запрещают передавать их дальше. Так и оставить.
- URLhaus снят навсегда (`RETIRED_FEEDS`), Tranco убран из обучения и рейтинга.

**Проверить.** `gh variable list` показывает `BLOCKLIST_LICENSED_ONLY true` и не
показывает `PUBLISH_CONFIRMED_THREATS`. Railway → `honest-playfulness` → `web` →
Variables: нет `LICENSED_INTEL=all` и нет `PUBLISH_CONFIRMED_THREATS`.

## 1. Paid Apps, налоговые формы, вопрос удержания налога в США

- **Зачем.** Apple и Google не платят без налоговой анкеты США. От страны компании
  и анкеты зависит, удержат ли они налог с продаж покупателям из США. Это меняет
  чистую выручку, поэтому выяснить до запуска.
- **Где.** App Store Connect → Business: принять Paid Apps Agreement, указать банк,
  Tax Forms → форма США (для компании W-8BEN-E). Apple разрешает это и частному
  аккаунту (тогда форма W-8BEN на человека), но мы решили ждать: Paid Apps, банк,
  налоги и подписки оформляем только после перевода аккаунта на компанию, чтобы
  выручка сразу шла компании ([`runbooks/company-accounts.md`](runbooks/company-accounts.md),
  [`IOS.md`](IOS.md) §3.1). Google Play Console → Settings → Payments profile →
  налоговые данные США.
- **Вопросы бухгалтеру.** Есть ли у страны компании договор с США об избежании
  двойного налогообложения? Какую ставку Apple и Google удержат с продаж в США?
  Отдельно — НДС. В App Store и Google Play налог с покупателя платит магазин. В
  Stripe продавец — сама компания, и VAT/НДС с цифровых услуг в ЕС, Великобритании и
  других странах — её обязанность. Варианты: Stripe Tax (около 0,5 % с платежа,
  сверить) или продавец-посредник вроде Paddle (5 % + $0,50, `ACCOUNTS_BILLING_PLAN.md` §4).
- **Сколько и кто.** 0 $ (бухгалтер отдельно). Основатель и бухгалтер.
- **Проверить.** App Store Connect → Business: Paid Apps — Active, Tax и Banking
  заполнены. В Play Payments profile нет предупреждений о налоговых данных. В первом
  отчёте о выплате удержание (или его отсутствие) совпадает с ответом бухгалтера.

## 2. Apple Small Business Program

- **Зачем.** Без программы Apple берёт 30 % в первый год подписки и 15 % со
  второго. В программе — 15 % с первого дня, пока выручка меньше $1 млн в год. Ставка
  снижается с одобрения, не задним числом, поэтому подать до первой продажи. Google
  Play и так берёт 15 % с подписок с первого дня, заявка не нужна.
- **Где.** developer.apple.com/app-store/small-business-program → Enroll. Подаёт
  Account Holder, указывает связанные аккаунты разработчика. После шага 1.
- **Сколько и кто.** 0 $, экономит 15 % выручки App Store в первый год каждой
  подписки. Основатель.
- **Проверить.** Письмо Apple об одобрении. В Payments and Financial Reports доля
  Apple с подписок — 15 %.

## 3. Vercel Hobby → Pro

- **Зачем.** Тариф Hobby разрешён только для личного некоммерческого использования.
  Сайт с ценами и кнопкой оплаты — коммерческий.
- **Где.** Vercel → аккаунт с проектом `cleanway-landing` → Settings → Billing →
  Upgrade to Pro. Если Vercel попросит создать команду, перенести в неё проект
  (Project → Settings → Transfer).
- **Сколько и кто.** $20 в месяц за участника. Основатель. Сделать до шага 15.
- **Проверить.** Billing → Plan: Pro. У `cleanway-landing` на месте домены
  `cleanway.ai` и `www.cleanway.ai`, переменные `NEXT_PUBLIC_*` и деплой из Git.
  Последний деплой `main` — Ready, `https://cleanway.ai` отвечает 200.

## 4. Supabase Free → Pro

- **Зачем.** В Supabase живут аккаунты и записи об оплате (`entitlements`), с
  платными людьми их нельзя терять. На бесплатном тарифе у Supabase нет своих
  ежедневных копий ([`runbooks/infra-readiness.md`](runbooks/infra-readiness.md)),
  есть только наша выгрузка в R2 (`.github/workflows/db-backup.yml`). Лимиты
  бесплатного тарифа малы.
- **Где.** supabase.com/dashboard → организация проекта `bpyqgzzclsbfvxthyfsf` →
  Billing → Change subscription plan → Pro. Spend cap оставить включённым.
- **Сколько и кто.** $25 в месяц. Основатель.
- **Проверить.** Billing → Plan: Pro. На следующий день в Database → Backups есть
  ежедневная копия. `https://api.cleanway.ai/health/deep` → `components.supabase` в порядке.

## 5. Resend Free → Pro

- **Зачем.** Бесплатный тариф — 100 писем в день и 3 000 в месяц на всё: коды входа
  и письма API вместе ([`runbooks/sign-in-email.md`](runbooks/sign-in-email.md)).
  После запуска это самая вероятная причина массового сбоя входа.
- **Где.** resend.com → Settings → Billing → Pro. Ключ не меняется (`RESEND_API_KEY`
  в Railway и SMTP-пароль Supabase).
- **Сколько и кто.** $20 в месяц, 50 000 писем. Основатель.
- **Проверить.** Settings → Usage: квота 50 000. `bash scripts/wire-supabase-smtp.sh --step verify`
  заканчивается строкой `SMTP wired — sign-in can scale`. Код входа на свой адрес
  приходит за минуту.

## 6. Sentry: не трассировать `/dns-query`, потом тариф

- **Зачем.** Сервер отправляет в Sentry 10 % всех запросов как трассировки
  (`traces_sample_rate: 0.1` в `sentry_init_options`,
  [`api/services/sentry_scrubber.py`](../api/services/sentry_scrubber.py)), и
  DNS-запросы `/dns-query` тоже. Телефон шлёт их десятками на каждую страницу: это
  съедает квоту Sentry и CPU под нагрузкой ([`runbooks/capacity.md`](runbooks/capacity.md)).
  Имена сайтов из них скрабер вычищает, но в Sentry им вообще нечего делать.
- **Что.** Claude: PR, сначала тест. В `sentry_init_options` появляется
  `traces_sampler`: 0 для `/dns-query` и проб `/health*`, 0,1 для остального.
  Переменные не меняются. Потом тариф: Sentry → Settings → Subscription. Developer
  бесплатный, но на одного человека и с маленькой квотой; Team — около $26 в месяц.
  После правки неделю смотреть Stats: возможно, бесплатного хватит.
- **Сколько и кто.** 0–26 $. Claude (код), основатель (тариф).
- **Проверить.** Sentry → Traces: за сутки после деплоя ни одной транзакции
  `/dns-query`. Stats: объём трассировок упал. Ошибки приходят как раньше.

## 7. Google Web Risk вместо Safe Browsing

- **Зачем.** Условия Safe Browsing v4 запрещают коммерческое использование без
  отдельного договора. Web Risk — тот же поиск, но это коммерческий продукт Google
  Cloud ([`THIRD_PARTY_FEEDS.md`](THIRD_PARTY_FEEDS.md) §2).
- **Где.**
  1. Google Cloud: проект с привязанной оплатой, на компанию (для российского юрлица
     Google Cloud может быть недоступен, не проверено) → включить **Web Risk API** →
     APIs & Services → Credentials → API key. В Restrict key → API restrictions
     оставить только Web Risk API. Billing → Budgets & alerts → бюджет, например $10.
  2. Railway → `web` → Variables → `WEB_RISK_API_KEY`. С ним `safe_browsing.get_client()`
     отдаёт `WebRiskClient` ([`api/services/web_risk.py`](../api/services/web_risk.py))
     для `/check`, `/public/check`, `/email/analyze` и `confirmed_threats`. Если заданы
     оба ключа, используется Web Risk.
  3. Через сутки, если проверка прошла, удалить из `web` и `GOOGLE_SAFE_BROWSING_API_KEY`,
     и `GOOGLE_SAFE_BROWSING_KEY` (сервер принимает оба имени, [`api/config.py`](../api/config.py)).
     Тогда сервер не вернётся тихо к Safe Browsing, если ключ Web Risk пропадёт: в
     staging и production он напишет в лог `neither google_safe_browsing_key nor web_risk_api_key set`.
  4. Claude: тексты для людей. Правила Web Risk для предупреждений
     (cloud.google.com/web-risk/docs/user-warnings, прочитано 2026-10-24) строже, чем
     просто другое название. Того же требуют и условия Safe Browsing, так что пробел
     есть уже сейчас; закрыть его здесь, до первого платежа. Сначала тест, потом тексты:
     - **Подпись.** Предупреждение по данным Google несёт строку «Advisory provided by
       Google» со ссылкой на Web Risk Advisory (cloud.google.com/web-risk/docs/advisory).
       Только когда среди причин есть сигнал `safe_browsing` (с ключом Web Risk он
       называется так же): на предупреждениях по другим источникам подписи Google быть
       не должно. Сейчас её нет нигде в репозитории.
     - **Осторожные слова.** Не утверждать, что сайт опасен без сомнений: «возможно»,
       «подозревается», «может быть».
     - **Узнать больше.** Ссылка: про фишинг — antiphishing.org, про вредоносные
       программы — Google Search Central (страница о malware).
     - **Защита не идеальна.** Раз мы говорим, что защищаем от опасных сайтов, до
       включения защиты человек видит, что возможны ложные срабатывания (безопасный
       сайт помечен) и пропуски (опасный не помечен). Сейчас это есть только в
       условиях (`landing.terms.sections[1]`) и в подписях проверки на сайте («совет, не
       гарантия»); проверить онбординг приложения и расширения.
     - **Строки, которые показывают попадание в Web Risk** — переписать по правилам выше
       (сейчас «Google flags this site as dangerous», без оговорок):
       `extension.reason.flagged_dangerous`, `extension.evidence.flagged_dangerous`
       («Google Safe Browsing — the list Chrome, Firefox and Safari use… marks this site
       as unsafe»), `mobile.reason.flagged_dangerous` (её же показывает проверка на
       сайте: `safe_browsing` → `flagged_dangerous` в
       [`landing/lib/reason-label.ts`](../landing/lib/reason-label.ts)).
     - **Где назван «Google Safe Browsing» → «Google Web Risk»:** пункт 5 политики
       (`landing.privacy_policy.sections[4]`), `landing.privacy.server_note`, FAQ
       (`landing.faq.items[0]`, `[3]`), согласие webmail в расширении
       (`extension.webmail.setting_consent`), [`PRIVACY.md`](PRIVACY.md), `THIRD_PARTY_FEEDS.md` §2.
     - **Тексты магазинов.** [`STORE_SUBMISSION_KIT.md`](STORE_SUBMISSION_KIT.md):
       описание Google Play EN и RU (§1.2, §1.3), ответ для Data safety (§1.5),
       описание расширения EN и RU (§2.1, §2.2). [`APP_STORE_LISTING.md`](APP_STORE_LISTING.md):
       описание App Store EN и RU. Опубликованные описания основатель меняет в консолях.

     Все 10 языков, затем `python3 scripts/build-i18n.py`. В расширении и приложении
     строки обновятся с их следующим выпуском, поэтому выпуск — тоже до первого платежа.
- **Сколько и кто.** 0 $ до 100 000 запросов в месяц, дальше плата за каждую тысячу
  (cloud.google.com/web-risk/pricing). Запрос уходит только при свежем анализе; ответ
  «угроза» кешируется до `expireTime` (не дольше часа), «чисто» — на 5 минут.
  Основатель (Google Cloud, Railway, тексты в консолях магазинов), Claude (подпись,
  тексты, выпуски).
- **Проверить.** Cloud Console → Web Risk API → Metrics: запросы идут, ошибок нет.
  У Safe Browsing API запросов ноль, кроме воскресного бенчмарка (шаг 10). Railway →
  `web` → Logs: нет `web_risk_api_error`, со временем появляются `web_risk_hit`.
  Проверка сайта, приложение и расширение на адресе из Web Risk показывают «Advisory
  provided by Google» со ссылкой и ссылку «узнать больше»; на сайте, помеченном только
  другими списками, подписи Google нет. `git grep -i "safe browsing"` по текстам для
  людей (`packages/i18n-strings/src`, `docs/PRIVACY.md`, тексты магазинов) пуст.

## 8. AlienVault OTX и PhishStats → `RESTRICTED_CHECKS`

- **Зачем.** Бесплатный OTX — для некоммерческого использования, по анализу цен.
  В `THIRD_PARTY_FEEDS.md` §2 его условия ещё помечены *likely*: перед решением
  перечитать условия OTX (LevelBlue). Условия PhishStats (редакция июня 2026, #317):
  §10 — лицензия для исследований и threat intelligence, §11 — «только для
  информационных целей и исследований безопасности», §5 запрещает распространять
  сырые ленты. Строгое прочтение: в платном продукте нельзя. Основатель решил
  2026-10-24 оставить оба, пока продукт бесплатный.
- **Что.** Механизм готов: проверки из `RESTRICTED_CHECKS`
  ([`api/services/licensed_intel.py`](../api/services/licensed_intel.py)) при
  `LICENSED_INTEL=licensed` (по умолчанию) не запрашиваются и не считаются в
  знаменателе уверенности: проверок станет 11 из 19 вместо 13. Claude делает PR,
  сначала тест: в [`tests/test_licensed_intel.py`](../tests/test_licensed_intel.py)
  добавить в `RESTRICTED` `"phishstats"` и `"alienvault"`, затем то же в
  `RESTRICTED_CHECKS`. Обновить docstring, `.env.example`, комментарий к
  `load_shed_outbound_max_inflight` в `api/config.py` («32 x 13») и
  `THIRD_PARTY_FEEDS.md` §2. Убрать оба источника из текстов для людей — тех же, что
  в шаге 7. Можно иначе: получить от PhishStats и LevelBlue письменное разрешение на
  платный продукт, тогда ничего не выключать.
- **Что теряем.** Сигналы `phishstats` (вес 65), `alienvault_otx` и
  `alienvault_otx_high` в [`api/services/scoring.py`](../api/services/scoring.py).
  ML-модель их не использует, LLM-судья будет получать `alienvault_pulse_count = 0`.
- **Сколько и кто.** 0 $. Claude (PR), основатель (решение и «мержим»).
- **Проверить.** После деплоя в Railway → `web` → Logs в строках `analysis_complete`
  поле `checks` не больше 11, строк `phishstats_hit` нет. Ближайший воскресный
  бенчмарк: полнота упала не больше чем на 5 п. п. (при большем падении workflow сам
  откроет PR о регрессии).

## 9. Phishing.Database: #317 и один прогон с `force`

- **Зачем.** Мейнтейнеры ленты не называют источники, а MIT на компиляцию не
  перелицензирует чужие данные: коммерческое использование не подтверждено
  (подробно в #317). Основатель решил 2026-10-24 (вариант В): пока бесплатно —
  оставить, перед первым платежом вернуться к #317.
- **Что.** Claude перебазирует черновик #317 (`fix/phishing-database-provenance`) на
  `main`, перемеряет числа, добивается зелёного CI. PR добавляет `"Phishing.Database"`
  в `NON_COMMERCIAL_FEEDS` ([`scripts/refresh_dangerous_domains.py`](../scripts/refresh_dangerous_domains.py)),
  а их не читает сборка с `BLOCKLIST_LICENSED_ONLY=true`. Флаг уже стоит, поэтому
  мерж сразу выключает ленту. В день мержа (порядок из #317):
  1. Мержить сразу после зелёного планового прогона `refresh-dangerous-domains.yml`
     (каждые 6 часов, в :23 UTC). После мержа плановые прогоны красные: уходит
     55–58 % имён, а шлюз пропускает не больше 50 % (`MAX_CHURN`). Сроки идут от
     последней успешной публикации: через ~13 часов `/health/deep` скажет «устарел»
     (`MAX_HEALTHY_AGE_S`), придут письма канарейки и монитора; через 48 часов Android
     сочтёт копию устаревшей (`STALE_AFTER_MS`); через 72 часа список истечёт
     (`TTL_SECONDS`) и DNS-блокировка перестанет работать.
  2. Actions → Refresh DNS blocklist → Run workflow: `dry_run: true`, `force` выключен.
     Прогон красный с `PUBLISH GATE: churn ~55–58 %`, так и должно быть. В логе —
     `licence switch: N published names only Phishing.Database backed leave with this publish`,
     N ≈ 381 000. Строк `FEED DEGRADED` быть не должно; если есть — остановиться и
     ждать, пока лента восстановится. `force` здесь не включать: он отключает и
     проверку размеров лент, урезанная лента станет незаметна.
  3. Сразу после — Run workflow с `force: true`, без `dry_run`. Прогон зелёный, в логе
     `publish gate: ok` и та же строка.
  4. Следующий плановый прогон без `force` — зелёный.

  Android-сборку (её seed — `mobile/scripts/fetch-seed-blocklist.sh`) собирать только
  после пункта 3. Если мейнтейнеры письменно назовут источники и условия
  (contact@phish.co.za, письмо не отправлено), ленту можно вернуть пунктами 2–4.
- **Сколько и кто.** 0 $. Цена — качество, по замерам #317 от 2026-10-24: −56,5 % имён
  списка, −4,3 п. п. полноты на всём дампе PhishTank, −1 из 200 в выборке бенчмарка.
  Claude: перебазирование, мерж после «да» основателя, прогоны 2–3 (или основатель
  кнопкой Run workflow).
- **Проверить.** `https://api.cleanway.ai/health/deep` → `components.blocklist`:
  `ok: true`, `age_s` меньше часа, `count` примерно вдвое меньше прежнего (в #317
  ~263 тыс. хэшей вместо ~602 тыс.).

## 10. VirusTotal (и Safe Browsing) из публичного бенчмарка

- **Зачем.** Бесплатный API VirusTotal нельзя использовать в коммерческом продукте
  (анализ цен), а еженедельный бенчмарк публикуется на сайте платного продукта
  (`/transparency/methodology`). В список VirusTotal не входит, это только колонка
  сравнения (`THIRD_PARTY_FEEDS.md` §4).
- **Где.** GitHub → репозиторий → Settings → Secrets and variables → Actions →
  `VT_API_KEY` → Remove. Без секрета [`scripts/eval_fresh_urls.py`](../scripts/eval_fresh_urls.py)
  не сравнивает с VirusTotal (`if VT_KEY and not args.no_virustotal`), прогон идёт
  ~30 минут вместо ~110. Claude убирает VirusTotal со страницы методологии
  (`landing/app/[locale]/transparency/methodology/page.tsx`, строка
  `landing.methodology.mapping_virustotal`) и из комментариев
  `.github/workflows/weekly-benchmark.yml`.
- **Тот же вопрос — колонка `gsb`.** Бенчмарк спрашивает Safe Browsing ключом из
  секрета `GOOGLE_SAFE_BROWSING_KEY`, а условия Safe Browsing коммерческое
  использование запрещают (шаг 7). Решить вместе с VirusTotal: удалить и этот секрет
  (колонку Claude уберёт со страницы) или оставить сравнение осознанно.
- **Сколько и кто.** 0 $. Основатель (секреты), Claude (страница, комментарии).
- **Проверить.** `gh secret list` без `VT_API_KEY`. В ближайшем воскресном
  `docs/benchmarks/<дата>-fresh-urls.json` нет `virustotal`, на странице методологии
  VirusTotal не упоминается.

## 11. `ENVIRONMENT=production`

- **Зачем.** Без этой переменной сервер работает как `development` и не примет живой
  ключ Stripe `sk_live_…`, а в production требует именно его (`validate_settings`,
  [`api/config.py`](../api/config.py)). Обязательные настройки тоже проверяются только
  в production.
- **Где.** Railway → `web` → Variables, если ещё не задано (на 2026-10-10 не было,
  [`PLAN.md`](PLAN.md), раздел Railway). Сначала `TRUSTED_PROXY_CIDRS=100.64.0.0/10`,
  потом `ENVIRONMENT=production`. Ещё production требует `DEBUG=false`,
  `SUPABASE_JWT_SECRET` не короче 64 символов, `SUPABASE_URL` и `SUPABASE_SECRET_KEY`
  (или старый `SUPABASE_SERVICE_KEY`), `SENTRY_DSN`, `RATE_LIMIT_FAIL_CLOSED=true` —
  по замеру 2026-10-10 всё это есть. Если в `STRIPE_SECRET_KEY` сейчас тестовый
  `sk_test_…`, убрать его до переключения: в production он запрещён, живой ставится
  в шаге 12.
- **`STRICT_CONFIG` не трогать до конца шага 12.** Пока `STRICT_CONFIG=false` (по
  умолчанию), ошибка настройки не роняет сервер: пишется `startup_validation_failed_lax_mode`,
  и остальные проверки настройки пропускаются. С `STRICT_CONFIG=true` та же ошибка
  останавливает запуск (`startup_validation_failed_strict`), а сервис `web` один на
  `api.cleanway.ai` и `dns.cleanway.ai`: упадут и API, и DNS-защита телефонов. Самая
  вероятная такая ошибка — живой ключ Stripe без секрета вебхука (шаг 12), поэтому
  `STRICT_CONFIG=true` — только в конце шага 12.
- **Сколько и кто.** 0 $. Основатель; Claude читает логи.
- **Проверить.** `https://api.cleanway.ai/health` отвечает 200. В логах
  `config.validated` с `environment: production`, нет `startup_validation_failed_lax_mode`.
  Пока `STRIPE_SECRET_KEY` не задан, ожидаемы строки CRITICAL
  `STRIPE_WEBHOOK_SECRET is empty in production` и `REVENUECAT_WEBHOOK_AUTH is empty in production`
  (до шагов 12–13). Это только предупреждения. Ключ Stripe без секрета вебхука —
  уже не строка CRITICAL, а ошибка настройки (см. шаг 12).

## 12. Stripe: живой ключ, цены, вебхук, портал

- **Зачем.** Оплата на сайте для всех, кто не в России.
- **Где.** Подробно — [`runbooks/LAUNCH_ROADMAP.md`](runbooks/LAUNCH_ROADMAP.md), шаг 5.2.
  **Порядок важен.** В production живой ключ без секрета вебхука — ошибка настройки:
  `Production requires STRIPE_WEBHOOK_SECRET when STRIPE_SECRET_KEY is set`
  (`validate_settings`, раздел 5d). При `STRICT_CONFIG=true` такой деплой не
  запускается, и вместе с API пропадает DNS (тот же сервис `web`). При `false` сервер
  работает, но остальные проверки настройки не выполняются. Поэтому оба значения
  сначала получить в Stripe, а в Railway поставить одним деплоем (пункт 5).

  1. Stripe: активировать аккаунт на компанию (налоги — шаг 1).
  2. Stripe → Developers → API keys → Secret key `sk_live_…`. Нужен именно `sk_live_`:
     ограниченный ключ `rk_live_…` сервер в production отвергнет, хотя в
     LAUNCH_ROADMAP написано «Restricted key». В Railway пока не ставить.
  3. Цены, с ключом только в окружении своего терминала (`export STRIPE_SECRET_KEY=…`;
     скрипт сам `.env` не читает; в чат не вставлять):
     `python3 scripts/create_stripe_prices.py --dry-run` покажет 16 цен:
     тариф и доп. устройство × 4 ценовых уровня × 2 периода, суммы из
     [`api/services/pricing.py`](../api/services/pricing.py). Потом то же без
     `--dry-run`: скрипт печатает `STRIPE_PRICE_DEVICES_T{1..4}_{MONTHLY|YEARLY}` и
     `STRIPE_PRICE_EXTRA_DEVICE_T{1..4}_{MONTHLY|YEARLY}`, они нужны в пункте 5.
     Повторный запуск безопасен. Пока цен нет, `POST /api/v1/payments/checkout`
     отвечает 503 `checkout_not_configured`.
  4. Stripe → Developers → Webhooks → endpoint `https://api.cleanway.ai/api/v1/payments/webhook`,
     события `checkout.session.completed`, `customer.subscription.updated`,
     `customer.subscription.deleted`, `customer.subscription.trial_will_end`,
     `invoice.paid`, `invoice.payment_failed`, `customer.deleted`, `charge.refunded`,
     `charge.dispute.created`. Endpoint можно создать до ключа в Railway: события
     пойдут только после первых покупок. Скопировать Signing secret `whsec_…`.
  5. Railway → `web` → Variables, одним набором: `STRIPE_SECRET_KEY=sk_live_…`,
     `STRIPE_WEBHOOK_SECRET=whsec_…` из пункта 4 (старый тестовый `whsec_`, если есть,
     заменить: он подходит по формату, но подписи живого endpoint не совпадут) и
     цены из пункта 3. Railway копит изменения переменных и применяет их одной кнопкой
     Deploy: нажать её, когда в списке есть и ключ, и секрет. Без секрета checkout
     тоже отвечает 503: платёж, который вебхук не запишет, не продаём. Если деплой
     всё же упал — убрать `STRIPE_SECRET_KEY` и задеплоить снова.
  6. Stripe → Settings → Billing → Customer portal → включить (кнопка «Управлять»,
     `POST /api/v1/payments/portal`).
  7. Когда в логе деплоя из пункта 5 есть `config.validated` и нет
     `startup_validation_failed_lax_mode`, можно поставить `STRICT_CONFIG=true` (шаг 11)
     отдельным деплоем.

  Миграция `024_store_purchases_revenuecat.sql` уже применена (`PLAN.md`).
- **Сколько и кто.** Абонплаты нет, комиссия с платежа около 2,9 % + $0,30
  (`ACCOUNTS_BILLING_PLAN.md` §4), точная — по стране компании. Основатель. Скрипт
  цен может запустить и Claude, если ключ лежит в корневом `.env` (Claude загрузит его
  в окружение, не печатая); ключ в чат не вставлять.
- **Проверить.** В логах деплоя `config.validated` с `has_stripe: true`, нет
  `startup_validation_failed_lax_mode` и `startup_validation_failed_strict`, нет строки
  CRITICAL про `STRIPE_WEBHOOK_SECRET`. В логах Railway нет `checkout_not_configured`.
  Stripe → Webhooks → endpoint → Send test event → 200. Полная покупка — в шаге 15.

## 13. RevenueCat: Google Play и App Store

- **Зачем.** Подписки внутри приложений. Google и Apple принимают оплату подписки
  внутри приложения только через свои магазины.
- **Где.** Подробно — [`runbooks/revenuecat.md`](runbooks/revenuecat.md) и
  [`IOS.md`](IOS.md) §3.4.
  - Магазины. Google Play: подписки `cleanway.devices` и `cleanway.extra_device`
    (базовые планы `monthly`, `yearly`), сервисный аккаунт, уведомления в реальном
    времени (runbook §1–3). App Store, после шага 1: `cleanway.devices.monthly` и
    `.yearly`, ключ In-App Purchase `.p8`, App Store Server Notifications V2 (runbook §9).
  - Сервер, Railway → `web`. `REVENUECAT_WEBHOOK_AUTH` — случайная строка не короче
    32 символов, та же в RevenueCat → Integrations → Webhooks → Authorization header.
    `REVENUECAT_SECRET_API_KEY=sk_…` — секретный ключ API v1. `REVENUECAT_ACCEPT_SANDBOX`
    к запуску `false` или не задан, `true` — только пока тестируете сами.
    `REVENUECAT_PRODUCTS` пустой, если продукты совпадают с `api/services/store_products.py`.
  - Сборки — это и есть включение в приложении. Android: `EXPO_PUBLIC_DISTRIBUTION=play`
    и `EXPO_PUBLIC_REVENUECAT_ANDROID_KEY=goog_…`. iOS: `EXPO_PUBLIC_REVENUECAT_IOS_KEY=appl_…`
    (переменные EAS или `mobile/.env` для локальной сборки). В сборки идут только
    публичные ключи. На iOS ключ включает и дневной лимит проверок (`IOS.md` §1.2).
  - Анкеты: App Store → App Privacy → Purchases → Purchase History (`IOS.md` §3.5),
    Google Play → Data safety → история покупок.
- **Сколько и кто.** RevenueCat бесплатен, пока выручка через него меньше $2 500 в
  месяц, дальше около 1 % (сверить на revenuecat.com/pricing). Магазины берут 15 % с
  подписок (Apple — после шага 2). Основатель (магазины, RevenueCat, переменные),
  Claude (сборки, анкеты, логи).
- **Проверить.** RevenueCat → Send test event → 200 `{"result": "ignored"}`.
  Тестировщик покупает месячный тариф → в логах `revenuecat_webhook_received`
  (`INITIAL_PURCHASE`) → `GET /api/v1/me/entitlement` возвращает `source: google_play`
  (или `app_store`) и `device_limit: 3` (runbook §6).

## 14. Прогон e2e «stripe on»

- **Зачем.** Переменные `NEXT_PUBLIC_*` вшиваются в сайт при сборке. Матрица
  [`.github/workflows/e2e-landing.yml`](../.github/workflows/e2e-landing.yml) уже
  собирает сайт четыре раза (`billing: [off, on]` × `stripe: [off, on]`) и проверяет,
  что увидят люди (`landing/e2e/pricing.spec.ts`, `home.spec.ts`, `billing.spec.ts`;
  флаг читает `landing/e2e/billing-flag.ts`).
- **Где.** Actions → «E2E — Landing (Playwright)» → Run workflow на `main`, или
  `gh workflow run e2e-landing.yml --ref main`.
- **Сколько и кто.** 0 $. Claude.
- **Проверить.** На последнем коммите `main` зелёные `e2e (billing off, stripe on)`,
  а перед Россией и `e2e (billing on, stripe on)`. E2E-задачи стартуют с опозданием:
  дождаться их, а не только CI.

## 15. `NEXT_PUBLIC_STRIPE_LIVE=1`, последним для сайта

- **Зачем.** Пока флаг выключен, мировой `/pricing` — бесплатная страница
  (`FreePricing`: без карточек тарифа, без кнопки, без Offer в JSON-LD). С флагом
  страница продаёт тариф по устройствам ([`landing/lib/billing-config.ts`](../landing/lib/billing-config.ts),
  [`BILLING_LANDING.md`](BILLING_LANDING.md)).
- **Где.** Vercel → `cleanway-landing` → Settings → Environment Variables →
  Production: `NEXT_PUBLIC_STRIPE_LIVE=1` → Deployments → Redeploy **без build cache**.
  Откат: удалить переменную и снова пересобрать без кэша.
- **Сколько и кто.** 0 $. Основатель.
- **Проверить.** `https://cleanway.ai/pricing` не из России: карточки тарифа и кнопка
  покупки; `/business` и `/account` ведут на цены. Купить своей картой → Stripe →
  Payments: платёж есть; Webhooks: доставки 200; `GET /api/v1/me/entitlement` →
  `source: stripe`; «Управлять» открывает портал Stripe. Потом Refund в Stripe →
  событие `charge.refunded`.

## 16. Россия: юрлицо, договор с MIXPLAT, оферта

- **Зачем.** Оплату со счёта телефона в России принимает российский продавец по
  договору с агрегатором. Черновики оферты и согласий написаны под ИП на УСН
  ([`legal/README.md`](legal/README.md)). Без этого `BILLING_ENABLED` не включают:
  пять условий перечислены в [`BILLING.md`](BILLING.md).
- **Что.** ИП или ООО (решение основателя, `legal/README.md`). Шаги 16 и 18 и код
  написаны под ИП. Для ООО до шага 18 нужна работа Claude, которой здесь нет: оферта
  (`legal/OFFER_RU.md`, «ОГРНИП {{OGRNIP}}») и согласие (`legal/CONSENT_RU.md`,
  написано «после регистрации ИП»), проверка
  реквизитов на сайте ([`landing/lib/billing.ts`](../landing/lib/billing.ts):
  `sellerFromEnv` принимает только ИНН из 12 цифр и ОГРНИП из 15, а у ООО ИНН — 10
  цифр, ОГРН — 13, и реквизиты покажутся неполными), имя переменной
  `NEXT_PUBLIC_BILLING_SELLER_OGRNIP`, строки `requisites_*` на сайте и тест
  `landing/e2e/billing.spec.ts`. Договор с MIXPLAT;
  вопросы менеджеру — в `BILLING.md`, раздел Providers: `amount` или `amount_merchant`,
  поле валюты, `recurrent_id`, адреса вебхука, отправка SMS, кто выдаёт чеки по 54-ФЗ.
  Короткий номер для SMS «СТОП». Юрист проверяет `legal/OFFER_RU.md` и `legal/CONSENT_RU.md`.
- **Сколько и кто.** Регистрация и бухгалтерия — вне этого списка. Комиссия
  оператора 30–50 %, уточнить у MIXPLAT (`ACCOUNTS_BILLING_PLAN.md` §4). Основатель,
  юрист, бухгалтер.
- **Проверить.** Договор подписан. На руках project id и API-ключ MIXPLAT, реквизиты
  (для ИП: имя, ИНН — 12 цифр, ОГРНИП — 15 цифр; для ООО: название, ИНН — 10 цифр,
  ОГРН — 13 цифр, и сделана работа Claude из пункта «Что»), короткий номер. Оферта
  проверена юристом.

## 17. Россия: сервер и база в РФ (152-ФЗ), уведомление РКН

- **Зачем.** Номер телефона — персональные данные. По ч. 5 ст. 18 152-ФЗ данные
  россиян записываются в базу на территории РФ ([`PRIVACY.md`](PRIVACY.md), раздел о
  подписке в России). До начала обработки — уведомление Роскомнадзора.
- **Что.** Yandex Cloud `ru-central1`: Managed PostgreSQL для `DATABASE_URL_BILLING`,
  ключи — в Lockbox. Отдельный сервис из того же образа с `ROLE=billing`,
  `ENVIRONMENT=production`, своим Redis и `RATE_LIMIT_FAIL_CLOSED=true`. Миграции —
  `python -m api.billing.migrate`. Claude: инструкция по развёртыванию и запуск
  `python -m api.billing.scheduler` раз в 15 минут (сейчас его ничто не вызывает).
- **Вопрос юристу.** Почта российских пользователей с аккаунтом и сейчас лежит в
  Supabase в ЕС. Нужна ли локализация и для неё, когда оператором станет российское лицо?
- **Сколько и кто.** $45–70 в месяц за сервер и базу (`ACCOUNTS_BILLING_PLAN.md` §4).
  Основатель (Yandex Cloud, уведомление РКН), Claude (настройка, миграции, планировщик).
- **Проверить.** Миграции прошли один раз без ошибок. Компания есть в реестре
  операторов персональных данных (pd.rkn.gov.ru).

## 18. Россия: флаги операторской оплаты, `NEXT_PUBLIC_BILLING_ENABLED` последним

- **Зачем.** Код готов и выключен. Маршруты `/billing/v1` появляются, только когда
  `BILLING_ENABLED=true` и `ROLE=billing` заданы вместе (`routes_enabled()`,
  [`api/billing/settings.py`](../api/billing/settings.py)): `web` на Railway их не
  откроет, даже если флаг туда попадёт.
- **Где.** Сервис оплаты в России (шаг 17):

  | Переменная | Значение |
  |---|---|
  | `BILLING_ENABLED` / `ROLE` / `ENVIRONMENT` | `true` / `billing` / `production` |
  | `DATABASE_URL_BILLING` | база из шага 17 |
  | `BILLING_ENTITLEMENT_PRIVATE_KEY`, `_KEY_ID`, `_PUBLIC_KEYS` | пара из `api.billing.entitlement.generate_keypair()` |
  | `BILLING_MSISDN_KEY`, `BILLING_HMAC_KEY` | каждый — `openssl rand -base64 32` |
  | `BILLING_MIXPLAT_PROJECT_ID`, `BILLING_MIXPLAT_API_KEY` | из договора |
  | `BILLING_MIXPLAT_TEST` | `false`. С `true` в production сервер не запустится без `BILLING_MIXPLAT_TEST_ALLOWED_IN_PRODUCTION=true` (только для осознанной пробы) |
  | `BILLING_FAKE_PROVIDER_ENABLED` | `false`, в production иначе нельзя |
  | `BILLING_MIXPLAT_WEBHOOK_IPS` | адреса от менеджера MIXPLAT (пусто — без списка) |
  | `BILLING_PRICE_*_RUB`, `BILLING_PLAN_VERSION`, `BILLING_TRIAL_DAYS`, `BILLING_GRACE_DAYS`, `BILLING_LAPSE_POLICY` | если не 99/270/399, 1, 14, 7, `basic` |

  Приложение: экраны подписки — черновик #73 (`feat/billing-mobile`, флаг
  `EXPO_PUBLIC_BILLING_RU_ENABLED`), не влит, Claude доделывает. Сайт, Vercel
  (имена — для ИП; для ООО сначала работа Claude из шага 16):
  `NEXT_PUBLIC_BILLING_SELLER_NAME`, `_SELLER_INN`, `_SELLER_OGRNIP`,
  `NEXT_PUBLIC_BILLING_STOP_NUMBER`, `NEXT_PUBLIC_SUPPORT_PHONE`, цены и сроки — если
  не по умолчанию. Перед флагом Claude запускает
  `python3 scripts/check-landing-claims.py --billing-on` и переписывает «бесплатно» на
  русских страницах, оферта опубликована. Последним — `NEXT_PUBLIC_BILLING_ENABLED=1`
  и пересборка без кэша: с ним появляется страница, куда ведёт `BILLING_MIXPLAT_RETURN_URL`.
- **Сколько и кто.** 0 $ сверх шагов 16–17. Основатель (переменные, Vercel), Claude
  (#73, планировщик, тексты).
- **Проверить.** `GET https://<хост оплаты>/billing/v1/plans` → 99, 270, 399 ₽. В логах
  `billing.settings.validated` с `mixplat_test: false` и `environment: production`. С
  российской SIM открыть `/ru/pricing`, `/ru/cancel`, `/ru/terms`, `/ru/privacy-policy`,
  `/ru` ([`BILLING_LANDING.md`](BILLING_LANDING.md)). Купить на свой номер, отменить в
  одно касание и SMS «СТОП»: больше ничего не списывается.
