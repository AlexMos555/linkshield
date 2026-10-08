package ai.cleanway.app

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Link and phone extraction from free message text. An SMS rarely carries a
 * scheme, so bare names must be found — and the Russian text around them is
 * full of dots that are NOT links: amounts, times, dates, abbreviations.
 */
class MessageLinksTest {

    private val tlds = MessageTestSupport.rules.bareTlds

    private fun hosts(text: String): List<String> = LinkExtractor.extract(text, tlds).map { it.host }

    /** Every message whose hosts differ from the expected ones, so one run names them all. */
    private fun assertHosts(expected: List<Pair<String, List<String>>>) {
        val wrong = expected.mapNotNull { (text, want) ->
            val got = hosts(text)
            if (got == want) null else "$text → $got (want $want)"
        }
        assertEquals(emptyList(), wrong, "${wrong.size} of ${expected.size} messages")
    }

    private fun assertNoLinks(texts: List<String>) = assertHosts(texts.map { it to emptyList() })

    // ── what IS a link ────────────────────────────────────────────────────

    @Test
    fun `finds scheme links and bare domains, path included in the text`() {
        val links = LinkExtractor.extract(
            "Войдите: https://Gosuslugi-Help.ru/login?id=7 или sberbank-bonus.ru/login, а ещё gosuslugi.help",
            tlds,
        )
        assertEquals(listOf("gosuslugi-help.ru", "sberbank-bonus.ru", "gosuslugi.help"), links.map { it.host })
        assertEquals("https://Gosuslugi-Help.ru/login?id=7", links[0].text)
        assertEquals("sberbank-bonus.ru/login", links[1].text)
    }

    @Test
    fun `cyrillic domains become punycode, the form the blocklist hashes`() {
        assertEquals(listOf("xn--c1aapkosapc.xn--p1ai"), hosts("Оплатите на госуслуги.рф сегодня"))
        assertEquals(listOf("xn--80aswg.xn--p1ai"), hosts("Сайт: https://сайт.рф/вход"))
    }

    @Test
    fun `trailing punctuation and wrapping brackets are not part of the link`() {
        val links = LinkExtractor.extract("(подробнее: clck.ru/3Abc). «vk.cc/xYz», gosuslugi.help!", tlds)
        assertEquals(listOf("clck.ru/3Abc", "vk.cc/xYz", "gosuslugi.help"), links.map { it.text })
    }

    @Test
    fun `a link glued to a label by a colon is still found`() {
        assertEquals(listOf("clck.ru"), hosts("Подробнее:clck.ru/3FgH7k"))
    }

    @Test
    fun `userinfo and port are stripped from a scheme link`() {
        assertEquals(listOf("evil.example"), hosts("https://user:pass@evil.example:8443/x"))
    }

    @Test
    fun `an IP address counts only with a path or a scheme`() {
        val links = LinkExtractor.extract("Проверьте: http://185.176.43.12/gosuslugi и 10.20.30.40/login", tlds)
        assertEquals(listOf("185.176.43.12", "10.20.30.40"), links.map { it.host })
        assertTrue(links.all { it.isIp })
        assertEquals(emptyList(), hosts("Версия 1.2.3.4 установлена"))
    }

    @Test
    fun `apk paths and mixed-script hosts are flagged`() {
        val apk = LinkExtractor.extract("Смотри: photo-album24.ru/img_2931.apk", tlds).single()
        assertTrue(apk.isApk)
        val lookalike = LinkExtractor.extract("Вход: sberbаnk.ru", tlds).single() // Cyrillic а
        assertTrue(lookalike.mixedScript)
        assertEquals("xn--sberbnk-6fg.ru", lookalike.host)
    }

    @Test
    fun `the same host twice is one link`() {
        assertEquals(listOf("evil.top"), hosts("evil.top/a и ещё раз evil.top/b"))
    }

    @Test
    fun `a scheme glued to the word before it is still a link`() {
        // The SMS app links these; a filter-dodging "по ссылкеhttps://" must not hide the host.
        val glued = LinkExtractor.extract("Оплатите по ссылкеhttps://pochta-rf.xyz/track", tlds).single()
        assertEquals("pochta-rf.xyz", glued.host)
        assertEquals("https://pochta-rf.xyz/track", glued.text)
        for (text in listOf("по ссылке-https://evil.top/login", "1.https://evil.top/login", "Details:Clickhttps://evil.top/x", "ahttp://evil.top")) {
            assertEquals(listOf("evil.top"), hosts(text), text)
        }
    }

    @Test
    fun `a scheme link whose host does not parse leaves its names to the bare scan`() {
        assertTrue("evil.top" in hosts("https://gosuslugi.ru,evil.top/login"))
    }

    @Test
    fun `a sentence glued on after the dot is cut off the name`() {
        assertEquals(listOf("gosuslugi-lk.ru"), hosts("Войдите: gosuslugi-lk.ru.Срок 24 часа"))
        assertEquals(listOf("gosuslugi-lk.ru"), hosts("Войдите: gosuslugi-lk.ru.Srok 24 chasa"))
        assertEquals(listOf("gibdd-shtraf.ru"), hosts("Оплатите со скидкой:gibdd-shtraf.ru.Срок до 23:59"))
    }

    @Test
    fun `cheap generic TLDs are links, and any TLD is with a path after it`() {
        assertEquals(listOf("sber-help.homes"), hosts("Войдите: sber-help.homes"))
        assertEquals(listOf("gosuslugi-lk.lat"), hosts("Войдите: gosuslugi-lk.lat"))
        assertEquals(listOf("pay.newgtld"), hosts("Оплата: pay.newgtld/login"))
    }

    @Test
    fun `a link without a scheme is found on any real TLD`() {
        // [message as written, the host that must come out]
        val cases = listOf(
            "Вернём налог: gosuslugi-vozvrat.online/lk" to "gosuslugi-vozvrat.online",
            "Бонусы СберСпасибо: sber-bonus.site" to "sber-bonus.site",
            "Посылка ждёт: pochta-rf.top" to "pochta-rf.top",
            "Ваш приз: wb-prize.xyz" to "wb-prize.xyz",
            "Распродажа ozon-sale.shop до пятницы" to "ozon-sale.shop",
            "Перерасчёт: nalog-vozvrat.info" to "nalog-vozvrat.info",
            "Вход: gosuslugi.pro" to "gosuslugi.pro",
            "Подтвердите: sber-id.click" to "sber-id.click",
            "МТС дарит: mts-bonus.live" to "mts-bonus.live",
            "Скидки wildberries-sale.store" to "wildberries-sale.store",
            "Личный кабинет gosuslugi-lk.su" to "gosuslugi-lk.su",
            "Сбер: sber.ru.com" to "sber.ru.com",
            // Only in the IANA root zone, never in message_rules.json's hand-picked list.
            "Компенсация: gosuslugi-help.claims" to "gosuslugi-help.claims",
            "Возврат налога nalog-vozvrat.tax" to "nalog-vozvrat.tax",
            "Страховка osago-polis.insure сегодня" to "osago-polis.insure",
            "Голосование за конкурс: detsad-konkurs.vote" to "detsad-konkurs.vote",
            "Поддержка: sber-help.chat" to "sber-help.chat",
            "Вознаграждение: mos-bonus.christmas" to "mos-bonus.christmas",
            "Кредит одобрен: alfa-credit.kred" to "alfa-credit.kred",
            "Билеты: rzd-bilet.tokyo" to "rzd-bilet.tokyo",
            "ВНИМАНИЕ: GOSUSLUGI-VOZVRAT.ONLINE" to "gosuslugi-vozvrat.online",
            // Cyrillic names on Cyrillic TLDs, Unicode and punycode.
            "Выплата: госуслуги-выплаты.рф" to "xn----8sbfca4atevpqavec6ke.xn--p1ai",
            "Бонус: сбер-бонус.рус" to "xn----9sbbo6bflfht.xn--p1acf",
            "Пособие: выплаты.онлайн" to "xn--80ad1apr4ce.xn--80asehdb",
            "Штрафы: штрафы-гибдд.москва" to "xn----7sbehgaz4drw4b2b.xn--80adxhks",
            "Оформите на пособие-детям.дети" to "xn----9sbkcco6ajaixt3o.xn--d1acj3b",
            "Кабинет: мои-выплаты.сайт" to "xn----8sbfwrcol3a0ge.xn--80aswg",
            "Сайт: xn--80aswg.xn--p1ai" to "xn--80aswg.xn--p1ai",
            "Проверка: sber-check.xn--p1acf" to "sber-check.xn--p1acf",
            // .zip and .mov are real TLDs sold to anyone; a lowercase name on them is a link.
            "Обновление: microsoft-update.zip" to "microsoft-update.zip",
        )
        assertHosts(cases.map { (text, host) -> text to listOf(host) })
    }

    @Test
    fun `a link on any TLD keeps its punctuation, port and path rules`() {
        assertHosts(listOf(
            "Срочно sber-bonus.site!", "(sber-bonus.site)", "«sber-bonus.site»", "Вход sber-bonus.site, код 1234",
            "Адрес: sber-bonus.site: войдите", "Это sber-bonus.site?", "sber-bonus.site — вход", "sber-bonus.site.",
            "sber-bonus.site;", "\"sber-bonus.site\"", "sber-bonus.site…",
        ).map { it to listOf("sber-bonus.site") })
        val withPort = LinkExtractor.extract("Вход: gosuslugi-help.claims:8443/lk?id=1", tlds).single()
        assertEquals("gosuslugi-help.claims", withPort.host)
        assertEquals("gosuslugi-help.claims:8443/lk?id=1", withPort.text)
        // A look-alike letter does not hide a name on a new TLD.
        val lookalike = LinkExtractor.extract("Вход: sberbаnk.online", tlds).single() // Cyrillic а
        assertTrue(lookalike.mixedScript)
        // A Cyrillic name on a Latin TLD is a link when the path says so.
        assertEquals(listOf("xn--c1aapkosapc.online"), hosts("Вход: госуслуги.online/lk"))
    }

    @Test
    fun `dotted Russian text is not a link`() {
        assertNoLinks(listOf(
            "т.е. перевод уже ушёл", "и т.д.", "и т.п.", "Т.к. офис закрыт", "т.н. страховка",
            "г.Москва, ул.Ленина, д.5", "по ст.275 УК РФ", "100 руб.", "Школа им.Пушкина",
            "коэффициент 1.5", "до 10.10.2026", "в 10.30", "ООО «Ромашка».Срок оплаты до пятницы",
            "Пришлите договор.pdf и скан.jpg", "Заказ оплачено.Спасибо за покупку", "Скачайте наше app.Подробнее в магазине",
            "Ждём вас.Москва ждёт", "Приезжайте в Яндекс.Маркет", "Оплатите через Сбер.Онлайн", "ВТБ.Онлайн доступен",
            "Сервис Яндекс.Плюс продлён", "Закажите в Яндекс.Go", "Мы на связи.Сайт работает", "Отчёт.Дети в лагере",
            "Пишите в чат.Ком. услуги оплачены", "Прислал отчёт.zip и видео.mov", "Скачай сбербанк.com", "Ссылка sber.рф",
        ))
    }

    @Test
    fun `Latin words, initials, brands and file names after a dot are not links`() {
        assertNoLinks(listOf(
            "Подключите Yandex.Pay и Mir.Pay", "Скидка в Yandex.Market", "Ozon.Bank: карта готова", "Играйте в VK.Play",
            "Your order has shipped.Download our app", "Thanks for waiting.Book now", "A.Bond, M.Ford, J.Black",
            "Kod 1234.Ne soobshchayte nikomu", "kod 1234.ne soobshchayte nikomu", "Vhod v Yandex.ID: kod 5521",
            "Sber.ID: kod 1234", "Foto IMG_2931.mov", "Arhiv scan_001.zip gotov", "Our new app.Click below",
            "Вход evil.top+1", "Ставки bet.online=выигрыш", "Скидка 50% на shop.online*",
        ))
    }

    @Test
    fun `the shipped root zone holds every TLD, Cyrillic ones as written`() {
        val zone = MessageTestSupport.rootZone
        assertTrue(zone.size >= 1400, "root zone has ${zone.size} TLDs")
        for (tld in listOf("com", "ru", "su", "online", "site", "claims", "zip", "xn--p1ai", "рф", "рус", "москва", "онлайн", "сайт", "дети")) {
            assertTrue(tld in zone, tld)
        }
        assertTrue(zone.none { it != it.lowercase() || it.isBlank() || it.startsWith("#") })
        assertTrue("pdf" !in zone && "jpg" !in zone && "apk" !in zone)
        assertTrue(tlds.containsAll(zone), "the extractor reads the whole root zone")
        assertEquals(setOf("bonus", "ok", "рф"), RootZone.parse("# IANA header\nBONUS\n\n ok \nРФ\n"))
    }

    @Test
    fun `a scam on a TLD outside the hand-picked list now raises a warning`() {
        val r = MessageTestSupport.analyzer().analyze(
            "Госуслуги: вам начислена компенсация 12 800 руб. Получите до 23:59 на gosuslugi-help.claims",
        )
        assertEquals(listOf("gosuslugi-help.claims"), r.links.map { it.host })
        assertTrue(r.verdict != MessageVerdict.NO_SIGNALS, "verdict ${r.verdict}")
    }

    @Test
    fun `every distinct host is found, however many repeats come first`() {
        val padded = "gosuslugi.ru ".repeat(25) + "evil.top/login"
        assertEquals(listOf("gosuslugi.ru", "evil.top"), hosts(padded))
        val many = (1..30).joinToString(" ") { "site$it.ru" }
        assertEquals(30, hosts(many).size)
    }

    // ── what is NOT a link ────────────────────────────────────────────────

    @Test
    fun `amounts, times, dates and versions are not links`() {
        assertEquals(
            emptyList(),
            hosts("Списано 1.500 руб в 10.30, 24.09.2026. Баланс 12 450.20р, версия 2.0, скидка 3.5%"),
        )
    }

    @Test
    fun `abbreviations are not links`() {
        assertEquals(emptyList(), hosts("г.Москва, ул.Ленина, д.5, т.е. и т.д., e.g. a.m. U.S.A."))
    }

    @Test
    fun `a word after a dot with no space is a new sentence, not a TLD`() {
        // These would otherwise leave the phone as "website names".
        for (text in listOf("Жду у метро.Ok?", "Буду в 7.Ok", "Call me.Today", "Я дома.No", "Спасибо.Hi", "Иду.One минуту", "Hello.Ok")) {
            assertEquals(emptyList(), hosts(text), text)
        }
        // A real TLD in capitals is still one.
        assertEquals(listOf("sber-help.ru"), hosts("Вход: SBER-HELP.RU"))
        assertEquals(listOf("gosuslugi-lk.ru"), hosts("Вход: gosuslugi-lk.Ru"))
    }

    @Test
    fun `e-mail addresses are not links`() {
        assertEquals(emptyList(), hosts("Пишите на support@sberbank.ru или ivan.petrov@mail.ru"))
    }

    @Test
    fun `non-web schemes are skipped whole`() {
        assertEquals(emptyList(), hosts("ftp://files.example/x intent://scan/#Intent;end"))
    }

    // ── host normalisation ────────────────────────────────────────────────

    @Test
    fun `host normalisation lowercases, punycodes and rejects junk`() {
        assertEquals("xn--c1aapkosapc.xn--p1ai", HostNames.normalize("ГОСУСЛУГИ.РФ."))
        assertEquals("evil.example", HostNames.normalize(" Evil.Example "))
        assertNull(HostNames.normalize("localhost"))
        assertNull(HostNames.normalize("a..b"))
        assertNull(HostNames.normalize("bad host.com"))
        assertNull(HostNames.normalize(""))
    }

    // ── phones ────────────────────────────────────────────────────────────

    @Test
    fun `phone numbers in every common Russian spelling normalise to +7`() {
        val phones = PhoneExtractor.extract(
            "+7 916 482-15-37, 8 (495) 123-45-67, 8-958-111-22-33, +79035557788, 8 800 555-55-50, тел.+7 999 204 18 55",
        )
        assertEquals(
            listOf("+79164821537", "+74951234567", "+79581112233", "+79035557788", "+78005555550", "+79992041855"),
            phones.map { it.number },
        )
        assertEquals(PhoneExtractor.Kind.TOLL_FREE, phones[4].kind)
        assertEquals(PhoneExtractor.Kind.CITY, phones[1].kind)
    }

    @Test
    fun `two numbers side by side stay two numbers`() {
        val phones = PhoneExtractor.extract("звоните +7 916 111-22-33 8 800 555-55-50")
        assertEquals(listOf("+79161112233", "+78005555550"), phones.map { it.number })
    }

    @Test
    fun `amounts, card numbers, codes, tracking and account numbers are not phones`() {
        val text = "Списано 250 000 р, карта 2202 2063 1234 5678, код 482193, трек 80082396123456, " +
            "счёт 40817810099910004312, заказ 1234567890, *1234, 12 450.20р"
        assertEquals(emptyList(), PhoneExtractor.extract(text).map { it.number })
    }

    @Test
    fun `foreign numbers keep their country code, service numbers normalise as digits`() {
        assertEquals(listOf("+447700900123"), PhoneExtractor.extract("Call +44 7700 900123 now").map { it.number })
        assertEquals("900", PhoneExtractor.normalize("900"))
        assertEquals("+78001007010", PhoneExtractor.normalize("8 800 100-70-10"))
        assertFalse(PhoneExtractor.extract("Позвоните на 900").isNotEmpty())
    }
}
