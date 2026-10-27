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
