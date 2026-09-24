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
