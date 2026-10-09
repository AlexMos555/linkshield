package ai.cleanway.app

import java.io.File
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The iPhone's scam-text filter (mobile/targets/sms-filter, Swift) must give
 * the SAME verdict as this engine for every message. This test writes what
 * Kotlin says about every corpus message — the developer corpora, the
 * held-out and blind sets, the model's parity texts and the edge cases below
 * — to a fixture the Swift tests replay (KotlinParityTests.swift); CI checks
 * with mobile/scripts/check-ios-parity-fixture.mjs that the fixture was made
 * from the current engine, assets and corpora.
 *
 * Run as a normal unit test it COMPARES: the committed fixture must equal what
 * the engine says now. After changing the engine, its assets or a corpus,
 * regenerate it with CLEANWAY_WRITE_IOS_PARITY=1 (docs/IOS.md §4), then run
 * the Swift tests.
 *
 * Every message runs three times, as the iPhone extension can: with the text
 * model (the default), with the model switched off by the server, and with
 * raised thresholds. Link statuses are all UNKNOWN: the extension has no
 * blocklist (it is offline and holds no list).
 */
class MessageIosParityTest {

    @Test
    fun `the iOS parity fixture matches the engine`() {
        val out = render()
        val target = fixtureFile()
        if (System.getenv("CLEANWAY_WRITE_IOS_PARITY") == "1") {
            target.parentFile.mkdirs()
            target.writeText(out)
            println("IOS_PARITY wrote ${target.absolutePath}")
        } else {
            assertTrue(target.exists(), "missing ${target.absolutePath}: run with CLEANWAY_WRITE_IOS_PARITY=1")
            assertEquals(target.readText(), out, "iOS parity fixture is stale: run with CLEANWAY_WRITE_IOS_PARITY=1")
        }
        // Extra texts (e.g. ml/sms/data/train_*.tsv) for a local, uncommitted run.
        val extra = System.getenv("CLEANWAY_IOS_PARITY_EXTRA")?.split(File.pathSeparatorChar)?.filter { it.isNotBlank() }
        val extraOut = System.getenv("CLEANWAY_IOS_PARITY_EXTRA_OUT")
        if (!extra.isNullOrEmpty() && extraOut != null) {
            val cases = extra.flatMap { path -> tsvTexts(File(path)).mapIndexed { i, t -> Case("${File(path).name}#$i", t, null) } }
            File(extraOut).writeText(render(cases, emptyMap()))
            println("IOS_PARITY extra ${cases.size} cases → $extraOut")
        }
    }

    private data class Case(val id: String, val text: String, val sender: String?)

    private fun cases(): List<Case> = buildList {
        for ((name, pair) in MessageTestSupport.corpora) {
            pair.second.forEachIndexed { i, t -> add(Case("$name#$i", t, null)) }
        }
        for (name in TSVS) tsvTexts(resource(name)).forEachIndexed { i, t -> add(Case("$name#$i", t, null)) }
        // The sender only ever adds suspicion; the extension passes it (ILMessageFilterQueryRequest.sender).
        for ((i, t) in MessageCorpus.SCAMS_RU.take(20).withIndex()) for (s in SENDERS) add(Case("sender:SCAMS_RU#$i:$s", t, s))
        for ((i, t) in MessageCorpus.LEGIT_RU.take(20).withIndex()) for (s in SENDERS) add(Case("sender:LEGIT_RU#$i:$s", t, s))
        EDGE_CASES.forEachIndexed { i, t -> add(Case("edge#$i", t, null)) }
        add(Case("edge:long", "Госуслуги: ваш аккаунт взломан, срочно позвоните +7 916 482-15-37. ".repeat(200), null))
        add(Case("edge:long-tail", "a".repeat(9_990) + " sberbank-bonus.ru/login срочно", null))
    }

    private fun render(list: List<Case> = cases(), inputs: Map<String, String> = inputHashes()): String {
        val on = MessageAnalyzer(MessageTestSupport.rules, MessageTestSupport.model, RemoteConfig.DEFAULT) { LinkStatus.UNKNOWN }
        val off = MessageAnalyzer(MessageTestSupport.rules, MessageTestSupport.model, RemoteConfig(false)) { LinkStatus.UNKNOWN }
        val raised = MessageAnalyzer(MessageTestSupport.rules, MessageTestSupport.model, RAISED) { LinkStatus.UNKNOWN }
        val sb = StringBuilder()
        sb.append("{\n\"format\": 1,\n")
        sb.append("\"generator\": \"mobile/modules/cleanway-vpn/android/src/test/java/ai/cleanway/app/MessageIosParityTest.kt\",\n")
        sb.append("\"raised\": {\"caution\": ${RAISED.smsTextModelCautionThresholdOverride}, \"danger\": ${RAISED.smsTextModelDangerThresholdOverride}},\n")
        sb.append("\"inputs\": {")
        sb.append(inputs.entries.joinToString(",") { "\n  ${q(it.key)}: ${q(it.value)}" })
        sb.append("\n},\n\"cases\": [\n")
        list.forEachIndexed { n, c ->
            val a = on.analyze(c.text, c.sender)
            val b = off.analyze(c.text, c.sender)
            val r = raised.analyze(c.text, c.sender)
            val ra = result(a)
            sb.append("{\"id\":").append(q(c.id)).append(",\"text\":").append(q(c.text))
            if (c.sender != null) sb.append(",\"sender\":").append(q(c.sender))
            sb.append(",\"p\":").append(MessageTestSupport.model.probability(c.text).toString())
            sb.append(",\"on\":").append(ra)
            result(b).takeIf { it != ra }?.let { sb.append(",\"off\":").append(it) }
            result(r).takeIf { it != ra }?.let { sb.append(",\"raised\":").append(it) }
            sb.append("}").append(if (n == list.size - 1) "\n" else ",\n")
        }
        sb.append("]\n}\n")
        return sb.toString()
    }

    /** verdict, reasons, legit shape, organisations, phones, links [host, text, shortener, messenger], truncated. */
    private fun result(a: MessageAnalysis): String = buildString {
        append("[").append(q(a.verdict.wire)).append(",")
        append(a.reasons.joinToString(",", "[", "]") { q(it) }).append(",")
        append(a.legitShape?.let { q(it) } ?: "null").append(",")
        append(a.organisations.joinToString(",", "[", "]") { q(it) }).append(",")
        append(a.phones.joinToString(",", "[", "]") { q(it) }).append(",")
        append(a.links.joinToString(",", "[", "]") { "[${q(it.host)},${q(it.text)},${it.shortener},${it.messenger}]" }).append(",")
        append(a.truncated).append("]")
    }

    private fun inputHashes(): Map<String, String> {
        val root = repoRoot()
        return INPUTS.associateWith { path ->
            val bytes = File(root, path).readBytes()
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        }
    }

    private fun tsvTexts(file: File): List<String> =
        file.readLines(Charsets.UTF_8).filter { it.isNotBlank() && !it.startsWith("#") }.map { it.substringAfterLast('\t') }

    private fun resource(name: String): File =
        listOf(File("src/test/resources/$name"), File("android/src/test/resources/$name")).firstOrNull { it.exists() }
            ?: error("$name not found from ${File(".").absolutePath}")

    /** The repository root: the env override, or up from the module's android/ dir. */
    private fun repoRoot(): File {
        System.getenv("CLEANWAY_REPO_ROOT")?.let { return File(it) }
        var d: File? = File(".").absoluteFile
        while (d != null) {
            if (File(d, "mobile/modules/cleanway-vpn").isDirectory) return d
            d = d.parentFile
        }
        error("repository root not found from ${File(".").absolutePath}; set CLEANWAY_REPO_ROOT")
    }

    private fun fixtureFile(): File = File(repoRoot(), FIXTURE)

    private companion object {
        const val FIXTURE = "mobile/targets/sms-filter/Tests/CleanwayMessageEngineTests/Fixtures/kotlin_parity.json"
        val RAISED = RemoteConfig(true, 0.97, 0.95)
        val TSVS = listOf(
            "message_heldout_2026-10.tsv",
            "message_blind_2026-10b.tsv",
            "message_blind_2026-10c.tsv",
            "message_blind_2026-10d.tsv",
            "message_blind_2026-10e.tsv",
            "message_model_parity.tsv",
        )
        val SENDERS = listOf("+79161234567", "Gosuslugi", "900", "VTB", "+447700900123")

        private const val M = "mobile/modules/cleanway-vpn/android/src"
        /** What the fixture is made from; mobile/scripts/check-ios-parity-fixture.mjs hashes the same files. */
        val INPUTS = listOf(
            "$M/main/java/ai/cleanway/app/MessageAnalyzer.kt",
            "$M/main/java/ai/cleanway/app/MessageGeneric.kt",
            "$M/main/java/ai/cleanway/app/MessageLinks.kt",
            "$M/main/java/ai/cleanway/app/MessageModel.kt",
            "$M/main/java/ai/cleanway/app/MessageRules.kt",
            "$M/main/java/ai/cleanway/app/MessageSignals.kt",
            "$M/main/java/ai/cleanway/app/MessageText.kt",
            "$M/main/java/ai/cleanway/app/RemoteConfig.kt",
            "$M/main/assets/message_rules.json",
            "$M/main/assets/root_zone_tlds.txt",
            "$M/main/assets/message_model.json",
            "$M/main/assets/message_model.bin",
            "$M/test/java/ai/cleanway/app/MessageCorpus.kt",
            "$M/test/java/ai/cleanway/app/MessageSchemeCorpus.kt",
            "$M/test/java/ai/cleanway/app/MessageGenericCorpus.kt",
            "$M/test/java/ai/cleanway/app/MessageIosParityTest.kt",
        ) + TSVS.map { "$M/test/resources/$it" }

        fun q(s: String): String {
            val sb = StringBuilder(s.length + 2).append('"')
            for (c in s) {
                when {
                    c == '"' -> sb.append("\\\"")
                    c == '\\' -> sb.append("\\\\")
                    c == '\n' -> sb.append("\\n")
                    c == '\r' -> sb.append("\\r")
                    c == '\t' -> sb.append("\\t")
                    c < ' ' || c == ' ' || c == ' ' || c.isSurrogate() -> sb.append("\\u%04x".format(c.code))
                    else -> sb.append(c)
                }
            }
            return sb.append('"').toString()
        }

        /**
         * Where Kotlin's and Swift's string handling could part: invisible and
         * bidi characters, mixed scripts, IDN and punycode hosts, case mapping
         * beyond ASCII, digits of other scripts, emoji, fullwidth dots, transliteration.
         */
        val EDGE_CASES = listOf(
            "Гос​услуги: ваш аккаунт взломан. Срочно позвоните +7 916 482-15-37",
            "﻿Сбербанк: подозрительная операция. Подтвердите данные: sberbank-bonus.ru/login",
            "Гoсуслуги (Latin o): вход с нового устройства, позвоните 89161234567",
            "Ваш аккаунт заблокирован, перейдите: госуслуги-выплаты.рф/вход",
            "Перейдите по ссылке xn--80aesfpebagmfblc0a.xn--p1ai/lk и подтвердите данные карты",
            "Перейдите: sbеrbank.ru/login (кириллическая е) срочно, карта заблокирована",
            "İSTANBUL: Your card is BLOCKED. Verify now at verify-card.top/login within 24 hours",
            "STRAßE.de bonus: Sie haben gewonnen! Jetzt abholen: gewinn-straße.de/claim",
            "ΣΩΣΤΟΣ ΚΩΔΙΚΟΣ ΑΠΟΣΤΟΛΗΣ. Πληρώστε 2€ στο delivery-gr.top/pay",
            "مصرف: تم إيقاف بطاقتك. اتصل ٠٥٠١٢٣٤٥٦٧ أو زر bank-verify.top/ar",
            "Mama, eto ya, pishu s novogo nomera. Srochno nuzhny dengi, perevedi 15000 na kartu 2202 2002 1234 5678, nikomu ne govori",
            "vash akkaunt vzloman, srochno pozvonite +79161234567 dlya otmeny",
            "😀🎁 Вы выиграли iPhone! 🎉 Заберите приз: priz-iphone.online, оплатите доставку 299₽",
            "ВТБ：карта заблокирована。Подробности vtb-online．site／help срочно",
            "Ваш код: 4821. Никому не сообщайте код, даже сотруднику банка.",
            "Оплата 1 500 р. Карта *1234. Баланс: 12 300 р",
            "Штраф ГИБДД 1500 руб. Оплатите до 23:59 сегодня: gibdd-shtraf.site",
            "Привет! Как дела? Встретимся завтра в 10:00 у метро.",
            "Ваша посылка ожидает. Код получения: 4821. Пункт выдачи: ул. Ленина 5",
            "Сбербанк: перевод 5 000 ₽ на безопасный счёт по указанию сотрудника СБ, никому не говорите",
            "Click https://bit.ly/3xYz to claim your $500 refund before midnight! Reply STOP to opt out",
            "Подработка на Ozon: оценка товаров 3000₽/день, пишите t.me/ozon_rabota_bot",
            "Your Amazon account is locked. Verify at http://192.168.13.7/amazon/login now",
            "Установите приложение по ссылке vozvrat-sredstv.top/app.apk, чтобы вернуть деньги",
            "Тест­овое сообщение без смысла: www.пример.испытание/путь",
            "ⅯⅠⅩ roman numerals and ﬁ ligature: ﬁnance-help.top/verify — срочно подтвердите данные",
            "Номер ９１６ полноширинными цифрами и ٣ арабскими: позвоните ８９１６１２３４５６７",
            "a😀b суррогатная пара внутри слова, Госуслуги, позвоните +7 916 000 00 00",
            "Вход в Госуслуги‍ с нового устройства⁠ — если это не вы, позвоните 8 (495) 123-45-67",
        )
    }
}
