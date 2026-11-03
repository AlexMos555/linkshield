# Письма, которые может понадобиться отправить

Готовые черновики на английском. Отправляет основатель со своей почты
(amoskotin@gmail.com) или с адреса на cleanway.ai. Claude не отправляет
письма сам. Перед отправкой проверьте даты и номера версий.

## 1. Apple: просьба ускорить проверку

**Когда:** версия 1.0.4 всё ещё «Waiting for Review» через 2–3 дня после того,
как 24.10.2026 было принято новое соглашение Paid Apps. Проверка стоит с
14.10.2026.

**Где:** форма [Request an Expedited App Review](https://developer.apple.com/contact/app-store/?topic=expedite).
Войти Apple ID разработчика, выбрать приложение «Cleanway: Scam Protection»
(Apple ID 6821030874), платформа iOS, версия 1.0.4.

**Текст для поля с объяснением:**

> Cleanway: Scam Protection 1.0.4 has been in "Waiting for Review" since
> October 14, 2026. The delay was likely caused by an updated agreement that
> we have now accepted (Free Apps on October 21, the new Paid Applications
> agreement on October 24). The app protects people from phishing and scam
> messages, and users are waiting for this first release. Nothing about the
> build has changed since submission. We would be grateful if you could look
> at it. Thank you.

Apple ускоряет проверку не всегда. Если откажут, ничего не теряется: версия
остаётся в очереди.

## 2. Cloudflare: публикация сравнения с 1.1.1.1 for Families

**Зачем:** еженедельный замер на cleanway.ai сравнивает, какие фишинговые
адреса ловим мы и какие блокирует 1.1.1.1 for Families. Условия Cloudflare
(§6, cloudflare.com/website-terms) прямо не разрешают и не запрещают
публиковать такие цифры. Подробности: [THIRD_PARTY_FEEDS.md](../THIRD_PARTY_FEEDS.md) §2b.
Если Cloudflare ответит «нет», убираем `cloudflare_families` из публикуемого
замера.

**Кому:** support@cloudflare.com (контакт из §15 их условий).
Тема: *Question about publishing benchmark results that use 1.1.1.1 for Families*

> Hello,
>
> We run Cleanway, an anti-phishing service. Once a week we take a sample of
> about 200 newly reported phishing URLs from a public feed, check each domain
> against our own service and against 1.1.1.1 for Families
> (family.cloudflare-dns.com), and publish how many of them each one blocks on
> our methodology page (cleanway.ai/transparency/methodology). That is a few
> hundred DNS lookups a week. We also keep the per-URL results in a public
> repository.
>
> Section 6 of your Website and Online Services Terms of Use reserves the data
> of the Online Services. Could you confirm whether publishing block rates
> computed from 1.1.1.1 for Families answers in this way is permitted? If you
> would prefer us not to, we will remove the comparison.
>
> Thank you,
> Aleksandr Moskotin
> ACECORE GLOBAL TECHNOLOGIES – FZCO (Cleanway)

## 3. Авторам Phishing.Database: откуда данные

**Когда:** перед запуском платных тарифов (решение основателя от 24.10.2026:
пока продукт бесплатный, база остаётся; [PAID_LAUNCH_SWITCHES.md](../PAID_LAUNCH_SWITCHES.md),
черновик PR #317).

**Кому:** contact@phish.co.za (указан мейнтейнерами Phishing.Database).
Тема: *Phishing.Database sources and commercial use*

> Hello,
>
> Thank you for maintaining Phishing.Database. We use the ACTIVE domains list
> in Cleanway, an anti-phishing service, to block phishing domains for our
> users (DNS filtering and link checks). We are preparing to offer paid plans
> and want to make sure our use respects the terms of every source.
>
> The repository is MIT-licensed, but we could not find which upstream feeds
> the lists are built from. Could you tell us which sources feed the ACTIVE
> lists, and whether any of them restrict commercial use? If commercial use
> needs permission or a licence, we would be glad to discuss it.
>
> Best regards,
> Aleksandr Moskotin
> ACECORE GLOBAL TECHNOLOGIES – FZCO (Cleanway)

## 4. PhishTank / Cisco Talos: ключ для коммерческого сервиса

**Когда:** сейчас. Ключ бесплатный, коммерческое использование API PhishTank
разрешено (FAQ: «Yes, it is OK»). Без ключа базу тоже можно скачивать, только
с меньшим лимитом («a few downloads per day», developer_info.php), поэтому
до ответа берём её раз в сутки без ключа. Регистрация на phishtank.org
03.11.2026 закрыта («New user registration temporarily disabled»), поэтому
ключ только письмом. В том же письме спросить прямо, можно ли раздавать
список, собранный из их данных, приложениям и DNS: в FAQ об этом ничего нет.
Замер 03.11.2026 (смоделировано выгрузкой без ключа): ключ даёт +6 п.п. на
независимом фишинге из TweetFeed за неделю и почти всё, что раньше давала
phishing.army ([THIRD_PARTY_FEEDS.md](../THIRD_PARTY_FEEDS.md)).

**Кому:** через phishtank.org → Contact (ведёт Cisco Talos).
Тема: *API application key for a commercial anti-phishing service*

> Hello,
>
> We run Cleanway, an anti-phishing service that blocks phishing sites for
> its users through DNS filtering and link checks on iPhone, Android and the
> web. We would like to use the PhishTank online-valid data feed with an
> application key. Your FAQ says commercial use of the API is OK, but new
> user registration is currently disabled, so we cannot create an account
> and register an application.
>
> Could you create an account and an application key for us, or tell us how
> to get one? Until then we download the public online-valid file once a day
> with a descriptive User-Agent, and we will switch to the key as soon as we
> have it. We credit PhishTank on our methodology page.
>
> Please also confirm one point: our apps receive a blocklist built partly
> from PhishTank data (hashed hostnames), and our DNS service blocks those
> names for our users. Is that use fine with you?
>
> Best regards,
> Aleksandr Moskotin
> ACECORE GLOBAL TECHNOLOGIES – FZCO (Cleanway)

**После ответа:** ключ положить в Railway и в секреты GitHub как
`PHISHTANK_API_KEY`, включить `BLOCKLIST_PHISHTANK_SOURCE`. Значение в чат не
присылать. Еженедельный бенчмарк сейчас берёт фишинг из PhishTank; с ключом
выборка станет «сама себя проверяющей», и её нужно перевести на другой
источник до первого прогона с ключом. Это делает Claude.

## 5. OpenPhish: пробный доступ к Premium и цена

**Когда:** по желанию, не срочно. Бесплатная лента Community запрещает любое
коммерческое использование, и по замеру 03.11.2026 она добавляет 0–3 сайта на
любой выборке. Платные Premium и Platinum не измерены: нет доступа, цены на
сайте нет («Contact Us»). Покупать только после бесплатного пробного доступа и
замера тем же способом.

**Кому:** contact@openphish.com. OpenPhish просит писать с адреса компании.
Из обычной почты от имени @cleanway.ai письмо не дойдёт: у домена DMARC
`p=reject`, а отправлять от его имени настроено только письма сервиса (Resend).
Пока писать с amoskotin@gmail.com, назвав компанию.
Тема: *Premium feed: trial and commercial licence for Cleanway*

> Hello,
>
> We run Cleanway, an anti-phishing service by ACECORE GLOBAL TECHNOLOGIES –
> FZCO (Dubai), that blocks phishing sites for its users through DNS filtering
> and link checks. We are evaluating commercial phishing feeds before our paid
> launch.
>
> Could you tell us the price of the Premium and Platinum feeds for this use,
> and whether a trial is possible? We would like to measure the feed's
> coverage against our current sources before buying. Please also confirm
> what the licence allows. Today our apps download our combined blocklist to
> block domains on the user's device; if OpenPhish entries may only be used
> on our servers (in link checks), we would like to know that too.
>
> Best regards,
> Aleksandr Moskotin
> ACECORE GLOBAL TECHNOLOGIES – FZCO (Cleanway)
