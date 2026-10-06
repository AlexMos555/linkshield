package ai.cleanway.app

import org.json.JSONObject
import java.io.File
import kotlin.math.abs
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The text model (MessageModel.kt) against its Python twin, its speed, and
 * what MessageAnalyzer lets a score add to the rules.
 *
 * message_model_parity.tsv is written by ml/sms/train.py with the
 * probabilities ml/sms/features.py computes; a mismatch means the two
 * normalisers drifted apart — fix the code, never the fixture.
 */
class MessageModelTest {

    private val model = MessageTestSupport.model

    private fun resource(name: String): File =
        listOf(File("src/test/resources/$name"), File("android/src/test/resources/$name")).firstOrNull { it.exists() }
            ?: error("$name not found from ${File(".").absolutePath}")

    private fun asset(name: String): File =
        listOf(File("src/main/assets/$name"), File("android/src/main/assets/$name")).firstOrNull { it.exists() }
            ?: error("$name not found from ${File(".").absolutePath}")

    @Test
    fun `every probability matches the Python twin to 1e-4`() {
        val cases = resource("message_model_parity.tsv").readLines(Charsets.UTF_8)
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .map { line -> line.substringBefore('\t').toDouble() to line.substringAfter('\t') }
        assertTrue(cases.size >= 250, "parity fixture has ${cases.size} texts")
        var worst = 0.0
        for ((expected, text) in cases) {
            val p = model.probability(text)
            val diff = abs(p - expected)
            worst = maxOf(worst, diff)
            assertTrue(diff < 1e-4, "p=$p, Python $expected for: ${text.take(120)}")
        }
        println("MESSAGE_MODEL parity: ${cases.size} texts, max |diff| ${"%.2e".format(worst)}")
    }

    @Test
    fun `the shipped assets are small, versioned and carry thresholds in range`() {
        val bin = asset(MessageModel.ASSET_WEIGHTS)
        val meta = JSONObject(asset(MessageModel.ASSET_JSON).readText())
        assertTrue(bin.length() + asset(MessageModel.ASSET_JSON).length() <= 1_500_000, "assets ${bin.length()} bytes")
        assertTrue(model.cautionThreshold in 0.5..1.0 && model.dangerThreshold in 0.5..1.0)
        for (key in listOf("official", "shorteners", "messengers", "cyrillic_tlds", "translit_markers")) {
            assertTrue(meta.getJSONObject("normaliser").getJSONArray(key).length() > 0, "normaliser.$key")
        }
        assertTrue(meta.getJSONObject("data_sha256").length() >= 4)
    }

    @Test
    fun `half floats decode exactly`() {
        assertEquals(0f, MessageModel.halfToFloat(0x0000))
        assertEquals(1f, MessageModel.halfToFloat(0x3C00))
        assertEquals(-2f, MessageModel.halfToFloat(0xC000))
        assertEquals(65504f, MessageModel.halfToFloat(0x7BFF))
        assertEquals(5.9604645E-8f, MessageModel.halfToFloat(0x0001))
        assertEquals(0.33325195f, MessageModel.halfToFloat(0x3555))
    }

    @Test
    fun `the Latin reading is the first reading of MessageText's Translit`() {
        for (w in listOf("vzloman", "soobshchayte", "schet", "svyazhetsya", "pozhaluysta", "eto", "dengi", "moy", "vy")) {
            assertEquals(Translit.readings(w).first(), MessageModel.reading(w), w)
        }
    }

    @Test
    fun `a 1000-character message is scored in under 2 ms`() {
        val text = ("Уважаемый клиент! Ваша карта *4821 заблокирована, срочно позвоните +7 900 000-00-47 или " +
            "перейдите sber-razblokirovka.online, vash kod 1234. ").repeat(9).take(1000)
        repeat(300) { model.probability(text) }
        val runs = 1000
        val start = System.nanoTime()
        repeat(runs) { model.probability(text) }
        val ms = (System.nanoTime() - start) / 1e6 / runs
        println("MESSAGE_MODEL perf 1000 chars: ${"%.3f".format(ms)} ms/score (JVM)")
        assertTrue(ms < 2.0, "model took $ms ms per 1000-char message")
    }

    // ── what a score may add ──────────────────────────────────────────────

    /** The shipped model with its thresholds replaced, to pin the integration whatever the scores are. */
    private fun withThresholds(caution: Double, danger: Double): MessageAnalyzer {
        val meta = JSONObject(asset(MessageModel.ASSET_JSON).readText())
        meta.getJSONObject("thresholds").put("caution", caution).put("dangerous_with_ingredient", danger)
        val m = MessageModel.parse(meta.toString(), asset(MessageModel.ASSET_WEIGHTS).readBytes())
        return MessageAnalyzer(MessageTestSupport.rules, m) { host -> LinkPolicy.classify(host, null, emptySet()) }
    }

    @Test
    fun `a score raises a quiet message to caution and names the model`() {
        val always = withThresholds(caution = 0.0, danger = 2.0)
        val r = always.analyze("Привет, как дела? Вечером созвонимся")
        assertEquals(MessageVerdict.CAUTION, r.verdict)
        assertEquals(MessageAnalyzer.R_TEXT_RESEMBLES_SCAM, r.reasons.first())
    }

    @Test
    fun `a score with an ingredient is dangerous, without one it stays a caution`() {
        val always = withThresholds(caution = 2.0, danger = 0.0)
        val withLink = always.analyze("Посмотри, что я нашла вчера вечером: kotiki-foto.site")
        assertEquals(MessageVerdict.DANGEROUS, withLink.verdict)
        assertEquals(MessageAnalyzer.R_TEXT_RESEMBLES_SCAM, withLink.reasons.first())
        assertTrue(MessageAnalyzer.R_LINK_NOT_OFFICIAL in withLink.reasons)
        assertEquals(MessageVerdict.NO_SIGNALS, always.analyze("Привет, как дела? Вечером созвонимся").verdict)
    }

    @Test
    fun `a few words, or only official links and numbers, are left to the rules`() {
        val always = withThresholds(caution = 0.0, danger = 0.0)
        val rulesOnly = MessageTestSupport.analyzer(withModel = false)
        for (text in listOf(
            "срочно",
            "Штраф! Срочно оплатите",
            "Вот ссылка: evil-photos.top/album",
            "Сбербанк: подозрительная операция приостановлена. Позвоните 8 800 555-55-50",
            "Госуслуги: вам назначен штраф. Оплатите на портале: gosuslugi.ru/pay",
        )) {
            assertEquals(rulesOnly.analyze(text), always.analyze(text), text)
        }
        assertEquals(null, MessageTestSupport.model.score("Штраф! Срочно оплатите"))
    }

    /**
     * MessageAnalyzerTest's legitimate twins, written to sit next to a scam
     * pattern, stay quiet with the shipped model and thresholds. Two are not
     * here because the model does flag them, and the evaluation says why
     * (docs/EVALUATION_2026-10.md §3.14): "Отчёт за сентябрь выложил сюда:
     * inn-proverka.online" (a link alone on a cheap TLD) and "Надзорный орган:
     * … чтобы избежать изъятия имущества, наберите 8 (843) …" (a threat and a
     * call, which the rules let pass only for the city number).
     */
    @Test
    fun `the rules' legitimate twins stay quiet with the model`() {
        val analyzer = MessageTestSupport.analyzer()
        for (text in TWINS) assertEquals(MessageVerdict.NO_SIGNALS, analyzer.analyze(text).verdict, text)
        for (word in listOf("Госуслуги", "срочно", "заблокирована", "безопасный счёт", "позвоните", "код", "выигрыш", "штраф")) {
            assertEquals(MessageVerdict.NO_SIGNALS, analyzer.analyze(word).verdict, word)
        }
    }

    @Test
    fun `a score never touches a legitimate shape or a dangerous verdict`() {
        val always = withThresholds(caution = 0.0, danger = 0.0)
        val rulesOnly = MessageTestSupport.analyzer(withModel = false)
        for (shape in listOf("Вход в СберБанк Онлайн. Никому не сообщайте код: 48213", "МЧС: беспилотная опасность, укройтесь")) {
            assertTrue(rulesOnly.analyze(shape).legitShape != null)
            assertEquals(rulesOnly.analyze(shape), always.analyze(shape))
        }
        val scam = "Госуслуги: ваш аккаунт взломан. Срочно позвоните +7 916 482-15-37"
        assertEquals(MessageVerdict.DANGEROUS, rulesOnly.analyze(scam).verdict)
        assertEquals(rulesOnly.analyze(scam), always.analyze(scam))
    }

    @Test
    fun `an already cautious message keeps its reasons and gains the model's`() {
        val always = withThresholds(caution = 0.0, danger = 2.0)
        val text = "Сбербанк: информация по вашей заявке sber-info.site"
        val before = MessageTestSupport.analyzer(withModel = false).analyze(text)
        assertEquals(MessageVerdict.CAUTION, before.verdict)
        val after = always.analyze(text)
        assertEquals(MessageVerdict.CAUTION, after.verdict)
        assertEquals(before.reasons + MessageAnalyzer.R_TEXT_RESEMBLES_SCAM, after.reasons)
    }

    /**
     * Input for ml/sms/thresholds.py: the rules' verdict (no model), whether a
     * legitimate shape excluded the message, and the ingredients, for every
     * validation and Kotlin-corpus message. Written to build/, never committed.
     */
    @Test
    fun `writes the rules dump for threshold selection`() {
        val rules = MessageTestSupport.analyzer(withModel = false)
        val groups = LinkedHashMap<String, List<Triple<String, String, String>>>()
        fun tsv(name: String) = resource(name).readLines().filter { it.isNotBlank() && !it.startsWith("#") }.map {
            val p = it.split('\t')
            Triple(p[0], p[1], p[2])
        }
        groups["heldout"] = tsv("message_heldout_2026-10.tsv")
        for (n in listOf("b", "c", "d")) groups["blind_$n"] = tsv("message_blind_2026-10$n.tsv")
        for ((name, list) in MessageTestSupport.corpora) {
            groups["corpus_$name"] = list.second.map { Triple(list.first, name, it) }
        }
        val out = StringBuilder(
            "# group\tlabel\tfamily\trules_verdict\tlegit_shape\tofficial_only\tingredients\ttext (\\\\ \\t \\n escaped)\n",
        )
        for ((group, cases) in groups) for ((label, family, text) in cases) {
            val r = rules.analyze(text)
            val s = rules.read(text.take(MessageAnalyzer.MAX_CHARS))
            val g = GenericSignals(s)
            val row = listOf(
                group, label, family, r.verdict.wire,
                (rules.legitShape(s) != null).toString(),
                MessageAnalyzer.officialChannelsOnly(s, g).toString(),
                MessageAnalyzer.modelIngredients(s, g).joinToString(","),
                text.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n").replace("\r", "\\r"),
            )
            out.append(row.joinToString("\t")).append('\n')
        }
        File("build").mkdirs()
        File("build/message-rules-dump.tsv").writeText(out.toString())
        println("MESSAGE_MODEL rules dump: ${out.count { it == '\n' } - 1} rows → build/message-rules-dump.tsv")
    }

    private companion object {
        /** The NO_SIGNALS texts of MessageAnalyzerTest (two left out, see above). */
        val TWINS = listOf(
            "Vash kod dlya vhoda: 4821. Nikomu ne soobshchayte etot kod",
            "Никому не сообщайте код из СМС, даже оператору банка",
            "Банк никогда не просит переводить деньги на безопасный счёт",
            "Не переводите деньги на безопасный счёт, даже если звонят из полиции",
            "Сбербанк: подозрительная операция приостановлена. Позвоните 8 800 555-55-50",
            "Госуслуги: попытка входа. Срочно позвоните 115",
            "ВТБ: никогда не переводите деньги на «безопасный счёт» — так делают только мошенники",
            "Банк России напоминает: безопасный счёт — уловка мошенников",
            "Сбербанк предупреждает: безопасных счетов не существует",
            "Сбер: не ведитесь на «безопасный счёт»",
            "ФССП: исполнительное производство окончено. Справки по тел. 8 (495) 620-39-95",
            "Яндекс Доставка: курьер позвонит за час, назовите ему код из SMS",
            "Код для входа: 4412. Никому не сообщайте его, даже сотруднику банка",
            "Скинь мне код от домофона, я забыла",
            "Пришли мне смс, когда доедешь",
            "Госуслуги: вам назначен штраф. Оплатите: gosuslugi.ru/pay",
            "Вот анкета для родителей: https://docs.google.com/forms/d/e/abc/viewform",
            "СберБанк: обновите приложение: sberbank.ru/app/sberbank.apk",
            "RuStore: скачайте установщик static.rustore.ru/rustore.apk",
            "Кешбэк 500 р зачислен. Потратьте до 30.09: shop-mebel.ru",
            "Госуслуги: у вас новое уведомление в личном кабинете",
            "В пятницу сюрприз для Марины, никому не говорите! С вами свяжется Оля",
            "Код для входа: 482913. Никому не сообщайте этот код. litres.ru",
            "Код 7730 для входа в приложение. Никому его не говорите. lenta.com",
            "Банк никогда не попросит вас назвать код из SMS",
            "Ivi: не удалось продлить подписку. Обновите данные карты, иначе подписка будет приостановлена: ivi.ru/profile",
            "Mail.ru: в аккаунт выполнен вход с нового устройства. Если это не вы, смените пароль: id.mail.ru",
            "Ваш автомобиль готов. К оплате 18 400 р, оплатить можно на месте. autoservis.ru",
            "Заказ ожидает оплаты. Оплатите в течение 30 минут, иначе бронь будет отменена: aviasales.ru",
            "Энергосбыт: долга за сентябрь нет, спасибо! Передать показания: energo-pokazaniya.ru",
            "Поздравляем! Вы выиграли два билета на концерт. Заберите их в кассе: concert-hall.ru",
            "Кешбэк-сервис: на ваш счёт поступило 540 р. Вывести: letyshops.com",
        )
    }
}
