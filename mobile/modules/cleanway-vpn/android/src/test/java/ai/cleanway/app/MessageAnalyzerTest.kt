package ai.cleanway.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The combination rules one at a time: what turns a word into a warning, and
 * — more often — what keeps it from becoming one.
 */
class MessageAnalyzerTest {

    private val analyzer = MessageTestSupport.analyzer()

    private fun verdict(text: String, sender: String? = null) = analyzer.analyze(text, sender).verdict

    // ── the shipped vocabulary ────────────────────────────────────────────

    @Test
    fun `the shipped rules parse and carry every group the analyzer reads`() {
        val rules = MessageTestSupport.rules
        for (g in MessageRules.REQUIRED_GROUPS) {
            assertTrue(rules.group(g).isNotEmpty(), "message_rules.json lacks group '$g'")
        }
        assertTrue(rules.organisations.any { it.id == "gosuslugi" && "115" in it.phones && "gosuslugi.ru" in it.domains })
        assertTrue("clck.ru" in rules.shorteners && "t.me" in rules.messengers)
        assertTrue("рф" in rules.bareTlds)
    }

    @Test
    fun `reason codes and shapes match the TypeScript contract`() {
        // The UI translates these codes; a code missing on either side is a
        // warning the person sees without an explanation.
        val ts = listOf(File("../src/MessageAnalysis.ts"), File("src/MessageAnalysis.ts")).first { it.exists() }.readText()
        fun tsList(name: String): List<String> {
            val body = Regex("const $name[^=]*=\\s*\\[(.*?)\\];", RegexOption.DOT_MATCHES_ALL).find(ts)?.groupValues?.get(1)
                ?: error("$name not found in MessageAnalysis.ts")
            return Regex("'([a-z_]+)'").findAll(body).map { it.groupValues[1] }.toList()
        }
        assertEquals(MessageAnalyzer.ALL_REASONS, tsList("MESSAGE_REASONS"))
        val shapes = listOf(
            MessageAnalyzer.SHAPE_LOGIN_CODE, MessageAnalyzer.SHAPE_PAYMENT_ALERT, MessageAnalyzer.SHAPE_PICKUP_CODE,
            MessageAnalyzer.SHAPE_PUBLIC_ALERT, MessageAnalyzer.SHAPE_SAFETY_NOTICE,
        )
        assertEquals(shapes, tsList("LEGIT_SHAPES"))
        assertEquals(MessageVerdict.entries.map { it.wire }, tsList("VERDICTS"))
        assertEquals(LinkStatus.entries.map { it.wire }, tsList("LINK_STATUSES"))
    }

    @Test
    fun `no single word is ever a warning`() {
        for (word in listOf("Госуслуги", "срочно", "заблокирована", "безопасный счёт", "позвоните", "код", "выигрыш", "штраф")) {
            assertEquals(MessageVerdict.NO_SIGNALS, verdict(word), "one word warned: $word")
        }
    }

    @Test
    fun `no vocabulary still checks links against the list`() {
        val bare = MessageAnalyzer(MessageRules.empty()) { h -> LinkPolicy.classify(h, MessageTestSupport.list("evil.example"), emptySet()) }
        val r = bare.analyze("Срочно: https://evil.example/x")
        assertEquals(MessageVerdict.DANGEROUS, r.verdict)
        assertEquals(listOf("link_blocklisted"), r.reasons)
    }

    // ── negation and awareness ────────────────────────────────────────────

    @Test
    fun `a negated instruction is not an instruction`() {
        assertEquals(MessageVerdict.NO_SIGNALS, verdict("Никому не сообщайте код из СМС, даже оператору банка"))
        assertEquals(MessageVerdict.NO_SIGNALS, verdict("Банк никогда не просит переводить деньги на безопасный счёт"))
        assertEquals(MessageVerdict.NO_SIGNALS, verdict("Не переводите деньги на безопасный счёт, даже если звонят из полиции"))
    }

    @Test
    fun `the same words as a live instruction are dangerous`() {
        val code = analyzer.analyze("Оператор ждёт на линии: продиктуйте код из СМС")
        assertEquals(MessageVerdict.DANGEROUS, code.verdict)
        assertTrue("asks_for_code" in code.reasons)
        val safe = analyzer.analyze("Если это не вы, переведите средства на безопасный счёт")
        assertEquals(MessageVerdict.DANGEROUS, safe.verdict)
        assertTrue("safe_account" in safe.reasons)
    }

    @Test
    fun `a live attack described in the same sentence does not disarm the instruction`() {
        // "мошенники просят…" is advice; "мошенники пытаются…" is the pretext of the scam itself.
        val r = analyzer.analyze("Мошенники пытаются похитить ваши деньги, срочно переведите их на безопасный счёт")
        assertEquals(MessageVerdict.DANGEROUS, r.verdict)
        assertTrue("safe_account" in r.reasons)
    }

    @Test
    fun `if-it-was-not-you does not negate the call that follows`() {
        val r = analyzer.analyze("Сбербанк: попытка входа в ваш кабинет. Если это не вы позвоните +7 916 000-11-22")
        assertEquals(MessageVerdict.DANGEROUS, r.verdict)
        assertEquals(listOf("claims_organisation", "threat_or_urgency", "call_unknown_number"), r.reasons.take(3))
    }

    @Test
    fun `calling an official number is not a callback scam`() {
        assertEquals(MessageVerdict.NO_SIGNALS, verdict("Сбербанк: подозрительная операция приостановлена. Позвоните 8 800 555-55-50"))
        assertEquals(MessageVerdict.NO_SIGNALS, verdict("Госуслуги: попытка входа. Срочно позвоните 115"))
    }

    @Test
    fun `an unlisted toll-free number with a threat is caution, not dangerous`() {
        val r = analyzer.analyze("Банк Восток: карта заблокирована. Срочно позвоните 8 800 123-45-67")
        assertEquals(MessageVerdict.CAUTION, r.verdict)
        assertTrue("call_unknown_number" in r.reasons)
    }

    @Test
    fun `scam words borrowed from a bank warning do not make it a safety notice`() {
        val r = analyzer.analyze("Банк Восток: карта заблокирована. Мошенники могут списать деньги. Срочно позвоните 8 800 123-45-67")
        assertEquals(MessageVerdict.CAUTION, r.verdict)
        assertNull(r.legitShape)
    }

    @Test
    fun `a bank's own safe-account warning is not a safe-account instruction`() {
        for (text in listOf(
            "ВТБ: никогда не переводите деньги на «безопасный счёт» — так делают только мошенники",
            "Банк России напоминает: безопасный счёт — уловка мошенников",
            "Сбербанк предупреждает: безопасных счетов не существует",
            "Сбер: не ведитесь на «безопасный счёт»",
        )) {
            assertEquals(MessageVerdict.NO_SIGNALS, verdict(text), text)
        }
    }

    @Test
    fun `a city number from a public office is not a callback lure, a personal one is`() {
        assertEquals(MessageVerdict.NO_SIGNALS, verdict("ФССП: исполнительное производство окончено. Справки по тел. 8 (495) 620-39-95"))
        val r = analyzer.analyze("Ваш родственник попал в ДТП, нужна срочная помощь, звоните следователю +7 925 111-00-99")
        assertEquals(MessageVerdict.CAUTION, r.verdict)
        assertTrue("call_unknown_number" in r.reasons)
    }

    // ── code requests ─────────────────────────────────────────────────────

    @Test
    fun `a code asked for a person is dangerous however it is worded`() {
        for (text in listOf(
            "Вам звонит курьер с подарком от ВТБ. Назовите ему код из СМС для получения",
            "Ваш код 4412. Продиктуйте его оператору, чтобы подтвердить запись к врачу",
            "Код 5521 для отмены операции. Никому не сообщайте код, кроме сотрудника службы безопасности, который вам позвонит",
            "Привет, я случайно отправил тебе код на твой номер, перешли мне его, пожалуйста",
            "Telegram: для подтверждения аккаунта перешлите код из SMS в этот чат",
            "Для подтверждения записи назовите код из СМС",
        )) {
            val r = analyzer.analyze(text)
            assertEquals(MessageVerdict.DANGEROUS, r.verdict, text)
            assertTrue("asks_for_code" in r.reasons, text)
            assertNull(r.legitShape, text)
        }
    }

    @Test
    fun `the legitimate twins of a code request stay quiet`() {
        for (text in listOf(
            "Яндекс Доставка: курьер позвонит за час, назовите ему код из SMS",
            "Код для входа: 4412. Никому не сообщайте его, даже сотруднику банка",
            "Скинь мне код от домофона, я забыла",
            "Пришли мне смс, когда доедешь",
        )) {
            assertEquals(MessageVerdict.NO_SIGNALS, verdict(text), text)
        }
    }

    // ── links ─────────────────────────────────────────────────────────────

    @Test
    fun `an official link under a claimed brand is fine, a foreign one is not`() {
        assertEquals(MessageVerdict.NO_SIGNALS, verdict("Госуслуги: вам назначен штраф. Оплатите: gosuslugi.ru/pay"))
        val r = analyzer.analyze("Госуслуги: вам назначен штраф. Оплатите: gosuslugi-pay.ru")
        assertEquals(MessageVerdict.DANGEROUS, r.verdict)
        assertTrue(r.reasons.containsAll(listOf("claims_organisation", "link_not_official", "link_imitates_brand")))
    }

    @Test
    fun `a brand with an unknown link and no threat is caution`() {
        val r = analyzer.analyze("Сбербанк: новые условия вклада. Подробнее: vklad-plus.site")
        assertEquals(MessageVerdict.CAUTION, r.verdict)
        assertEquals(listOf("claims_organisation", "link_not_official"), r.reasons)
    }

    @Test
    fun `links report shortener and messenger kinds and never leak the path into the host`() {
        val r = analyzer.analyze("Срочно! Подробнее: clck.ru/3Abc и t.me/help_bot")
        assertEquals(listOf("clck.ru", "t.me"), r.links.map { it.host })
        assertTrue(r.links[0].shortener && !r.links[0].messenger)
        assertTrue(r.links[1].messenger && !r.links[1].shortener)
        assertEquals("clck.ru/3Abc", r.links[0].text)
        assertEquals(MessageVerdict.CAUTION, r.verdict)
    }

    @Test
    fun `a blocklisted link is dangerous whatever the text says`() {
        val a = MessageTestSupport.analyzer(MessageTestSupport.list("evil-photos.top"))
        val r = a.analyze("Привет! Вот фото с дачи: evil-photos.top/album")
        assertEquals(MessageVerdict.DANGEROUS, r.verdict)
        assertEquals("link_blocklisted", r.reasons.first())
        assertEquals(LinkStatus.BLOCKED, r.links.single().status)
    }

    @Test
    fun `a link the person allowed is never blocked`() {
        val a = MessageTestSupport.analyzer(MessageTestSupport.list("evil-photos.top"), allowed = setOf("evil-photos.top"))
        val r = a.analyze("Вот ссылка: evil-photos.top/album")
        assertEquals(LinkStatus.ALLOWED_BY_USER, r.links.single().status)
        assertEquals(MessageVerdict.NO_SIGNALS, r.verdict)
    }

    @Test
    fun `a page on a Google host is judged by the text like any other site`() {
        // The shield never blocks google.com so Android keeps working; anyone
        // can still publish a phishing page on sites.google.com.
        val r = analyzer.analyze("Госуслуги: ваша учетная запись заблокирована. Срочно подтвердите данные: https://sites.google.com/view/gosuslugi-vhod")
        assertEquals(MessageVerdict.DANGEROUS, r.verdict)
        assertEquals(LinkStatus.SYSTEM, r.links.single().status)
        assertTrue("link_not_official" in r.reasons)
        assertEquals(MessageVerdict.DANGEROUS, verdict("Мама, это я, вот фото: https://drive.google.com/file/d/1/photo.apk"))
        assertEquals(MessageVerdict.NO_SIGNALS, verdict("Вот анкета для родителей: https://docs.google.com/forms/d/e/abc/viewform"))
    }

    @Test
    fun `repeating a harmless link cannot push a listed one out`() {
        val a = MessageTestSupport.analyzer(MessageTestSupport.list("evil.top"))
        for (text in listOf(
            "gosuslugi.ru ".repeat(20) + "evil.top/login",
            "evil.top/login " + "https://gosuslugi.ru ".repeat(20),
            (1..25).joinToString(" ") { "site$it.ru" } + " evil.top/login",
        )) {
            val r = a.analyze(text)
            assertEquals(MessageVerdict.DANGEROUS, r.verdict)
            assertEquals("link_blocklisted", r.reasons.first())
            assertTrue(r.links.any { it.host == "evil.top" && it.status == LinkStatus.BLOCKED })
            assertTrue(r.links.size <= MessageAnalyzer.MAX_LINKS)
        }
    }

    @Test
    fun `an app file is flagged unless an app store or the named organisation hands it out`() {
        assertEquals(MessageVerdict.DANGEROUS, verdict("Госуслуги: установите приложение для записи: https://disk.yandex.ru/d/abc/gosuslugi.apk"))
        assertEquals(MessageVerdict.DANGEROUS, verdict("Смотри, что про тебя пишут! vk.com/doc123_456/news.apk"))
        assertEquals(MessageVerdict.NO_SIGNALS, verdict("СберБанк: обновите приложение: sberbank.ru/app/sberbank.apk"))
        assertEquals(MessageVerdict.NO_SIGNALS, verdict("RuStore: скачайте установщик static.rustore.ru/rustore.apk"))
    }

    @Test
    fun `a Cyrillic look-alike of a brand is read as written`() {
        val r = analyzer.analyze("Ваш бонус ждёт вас: сбербанк-бонус.рф")
        assertEquals(MessageVerdict.CAUTION, r.verdict)
        assertTrue("link_imitates_brand" in r.reasons)
    }

    @Test
    fun `with no organisation named, a fine, fee or payout through an unknown site is caution`() {
        for (text in listOf(
            "Штраф 1500 р за превышение скорости. Оплатите со скидкой 50% до 20.10: oplata-pdd.ru",
            "Ваша посылка ожидает оплаты доставки 199 р. Оплатить: posylka-oplata.ru",
            "Пенсионерам положена доплата 12 000 р ко Дню пожилого человека. Оформите до 01.10: pensiya-doplata.ru",
        )) {
            assertTrue(verdict(text) != MessageVerdict.NO_SIGNALS, text)
        }
        // A shop's own cashback with a deadline is not a payout.
        assertEquals(MessageVerdict.NO_SIGNALS, verdict("Кешбэк 500 р зачислен. Потратьте до 30.09: shop-mebel.ru"))
    }

    // ── shapes and sender ─────────────────────────────────────────────────

    @Test
    fun `legitimate shapes are reported`() {
        assertEquals("login_code", analyzer.analyze("Вход в СберБанк Онлайн. Никому не сообщайте код: 48213").legitShape)
        assertEquals("payment_alert", analyzer.analyze("СЧЁТ1234 10:15 Покупка 356р Баланс: 12 450.20р").legitShape)
        assertEquals("pickup_code", analyzer.analyze("СДЭК: курьер привезёт заказ. Назовите курьеру код 5930").legitShape)
        assertEquals("public_alert", analyzer.analyze("МЧС: беспилотная опасность, укройтесь").legitShape)
        assertNull(analyzer.analyze("Привет, как дела?").legitShape)
    }

    @Test
    fun `a code shape with a foreign link or an unknown callback is not excluded`() {
        val r = analyzer.analyze("Госуслуги: код 482193. Аккаунт взломан, срочно позвоните +7 916 555-00-11")
        assertNull(r.legitShape)
        assertEquals(MessageVerdict.DANGEROUS, r.verdict)
    }

    @Test
    fun `the sender only ever adds suspicion`() {
        val text = "Госуслуги: у вас новое уведомление в личном кабинете"
        assertEquals(MessageVerdict.NO_SIGNALS, verdict(text, sender = "gosuslugi"))
        assertEquals(MessageVerdict.NO_SIGNALS, verdict(text))
        assertEquals(MessageVerdict.CAUTION, verdict(text, sender = "GosUslugi-Info"))
        assertTrue("sender_personal_number" in analyzer.analyze(text, sender = "+7 916 123-45-67").reasons)
        // A trusted-looking sender never clears a dangerous text.
        val scam = "Госуслуги: ваш аккаунт взломан. Срочно позвоните +7 916 482-15-37"
        assertEquals(MessageVerdict.DANGEROUS, verdict(scam, sender = "gosuslugi"))
    }

    // ── output ────────────────────────────────────────────────────────────

    @Test
    fun `the wire map is plain data with every field the bridge promises`() {
        val wire = analyzer.analyze("Госуслуги взломаны, срочно: clck.ru/x. Звоните +7 916 482-15-37").toWire()
        assertEquals(
            setOf("verdict", "reasons", "links", "phones", "legitShape", "organisations", "truncated"),
            wire.keys,
        )
        assertEquals("dangerous", wire["verdict"])
        assertEquals(listOf("+79164821537"), wire["phones"])
        @Suppress("UNCHECKED_CAST")
        val link = (wire["links"] as List<Map<String, Any?>>).single()
        assertEquals(setOf("text", "host", "status", "shortener", "messenger"), link.keys)
        assertEquals("unknown", link["status"])
        assertEquals(listOf("gosuslugi"), wire["organisations"])
    }

    @Test
    fun `very long input is cut and says so`() {
        val long = "Привет! ".repeat(3_000) + "Госуслуги взломаны, срочно позвоните +7 916 482-15-37"
        val r = analyzer.analyze(long)
        assertTrue(r.truncated)
        assertFalse(analyzer.analyze("Привет").truncated)
    }

    // ── performance ───────────────────────────────────────────────────────

    @Test
    fun `a 1000-character message is analysed far below the 50 ms budget`() {
        val chunk = "Госуслуги: зафиксирован вход с нового устройства. Если это не вы, срочно позвоните +7 916 482-15-37 " +
            "или проверьте gosuslugi-help.ru/login. Код 4821 никому не сообщайте. Оплатите пошлину 349 р до 23:59. "
        val text = chunk.repeat(1_000 / chunk.length + 1).take(1_000)
        repeat(30) { analyzer.analyze(text) } // warm up the JIT
        val runs = 200
        val start = System.nanoTime()
        repeat(runs) { analyzer.analyze(text) }
        val avgMs = (System.nanoTime() - start) / 1e6 / runs
        println("MESSAGE_PERF 1000 chars: %.3f ms/analysis (JVM)".format(avgMs))
        // A phone is ~5-10x slower than a dev JVM; 5 ms here keeps it well under 50 ms there.
        assertTrue(avgMs < 5.0, "analysis took $avgMs ms")
    }

    @Test
    fun `pathological input cannot stall the scan`() {
        val dots = "a.".repeat(5_000)
        val digits = "1-".repeat(5_000)
        val letters = "ж".repeat(10_000)
        for (text in listOf(dots, digits, letters)) {
            val start = System.nanoTime()
            analyzer.analyze(text)
            val ms = (System.nanoTime() - start) / 1e6
            assertTrue(ms < 250.0, "pathological input took $ms ms")
        }
    }
}
