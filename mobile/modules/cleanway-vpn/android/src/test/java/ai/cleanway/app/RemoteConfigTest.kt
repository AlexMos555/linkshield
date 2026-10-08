package ai.cleanway.app

import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The server's switches for the SMS text model (RemoteConfig.kt): what a
 * stored answer may say, the fail-safe order, and what MessageAnalyzer does
 * with them — off is exactly the rules, a raised threshold is quieter, and no
 * override can make the model louder than it ships.
 */
class RemoteConfigTest {

    // ── parsing: a bad answer never replaces a good one ──────────────────

    @Test
    fun `the default is the model on with the shipped thresholds`() {
        assertEquals(RemoteConfig(true, null, null), RemoteConfig.DEFAULT)
    }

    @Test
    fun `the server's answer is read`() {
        val c = RemoteConfig.parse(
            """{"sms_text_model_enabled":false,"sms_text_model_caution_threshold_override":0.9,""" +
                """"sms_text_model_danger_threshold_override":null}""",
        )
        assertEquals(RemoteConfig(false, 0.9, null), c)
    }

    @Test
    fun `what is not a config is null, so the caller keeps what it had`() {
        for (raw in listOf(
            null, "", "  ", "nope", "[]", "{}", "null",
            """{"sms_text_model_enabled":"false"}""",
            """{"sms_text_model_enabled":0}""",
            """{"sms_text_model_caution_threshold_override":0.9}""",
        )) {
            assertNull(RemoteConfig.parse(raw), "parse($raw)")
        }
    }

    @Test
    fun `a threshold outside (0, 1) is dropped on its own, the switch still counts`() {
        for (bad in listOf("0", "1", "1.5", "-0.1", "\"0.9\"", "true")) {
            val c = RemoteConfig.parse("""{"sms_text_model_enabled":false,"sms_text_model_danger_threshold_override":$bad}""")
            assertEquals(RemoteConfig(false, null, null), c, "override $bad")
        }
        assertNull(RemoteConfig.threshold(Double.NaN))
        assertNull(RemoteConfig.threshold(Double.POSITIVE_INFINITY))
        assertEquals(0.5, RemoteConfig.threshold(0.5))
    }

    @Test
    fun `the stored form reads back the same`() {
        for (c in listOf(RemoteConfig.DEFAULT, RemoteConfig(false, 0.91, 0.97), RemoteConfig(true, null, 0.99))) {
            assertEquals(c, RemoteConfig.parse(c.toJson()))
        }
        val keys = JSONObject(RemoteConfig.DEFAULT.toJson()).keys().asSequence().toSet()
        assertEquals(setOf(RemoteConfig.K_ENABLED, RemoteConfig.K_CAUTION, RemoteConfig.K_DANGER), keys)
    }

    @Test
    fun `an override only ever raises a threshold`() {
        val c = RemoteConfig(true, smsTextModelCautionThresholdOverride = 0.7, smsTextModelDangerThresholdOverride = 0.95)
        assertEquals(0.8, c.cautionThreshold(0.8), "lower than shipped: ignored")
        assertEquals(0.95, c.dangerThreshold(0.85), "higher than shipped: used")
        assertEquals(0.85, RemoteConfig.DEFAULT.dangerThreshold(0.85))
    }

    // ── what the analyzer does with them ─────────────────────────────────

    private val rulesOnly = MessageTestSupport.analyzer(withModel = false)

    private fun analyzer(remote: RemoteConfig, model: MessageModel = MessageTestSupport.model) =
        MessageAnalyzer(MessageTestSupport.rules, model, remote) { host -> LinkPolicy.classify(host, null, emptySet()) }

    private val allTexts: List<String> by lazy {
        MessageTestSupport.corpora.values.flatMap { it.second }
    }

    @Test
    fun `switched off, every corpus text gets exactly the rules' verdict`() {
        val off = analyzer(RemoteConfig(smsTextModelEnabled = false))
        val on = analyzer(RemoteConfig.DEFAULT)
        var modelChanged = 0
        for (text in allTexts) {
            val rules = rulesOnly.analyze(text)
            assertEquals(rules, off.analyze(text), text.take(120))
            if (on.analyze(text) != rules) modelChanged++
        }
        // Otherwise the switch would be pinned against a model that adds nothing.
        assertTrue(modelChanged > 0, "the shipped model changed no verdict in ${allTexts.size} texts")
        println("REMOTE_CONFIG: model off restores the rules on ${allTexts.size} texts; on, it changes $modelChanged")
    }

    /** The shipped model with its thresholds replaced (as MessageModelTest does). */
    private fun modelWith(caution: Double, danger: Double): MessageModel {
        val meta = JSONObject(asset(MessageModel.ASSET_JSON).readText())
        meta.getJSONObject("thresholds").put("caution", caution).put("dangerous_with_ingredient", danger)
        return MessageModel.parse(meta.toString(), asset(MessageModel.ASSET_WEIGHTS).readBytes())
    }

    private fun asset(name: String): File =
        listOf(File("src/main/assets/$name"), File("android/src/main/assets/$name")).firstOrNull { it.exists() }
            ?: error("$name not found from ${File(".").absolutePath}")

    @Test
    fun `switched off, even a model that flags everything says nothing`() {
        val loud = modelWith(caution = 0.0, danger = 0.0)
        val text = "Посмотри, что я нашла вчера вечером: kotiki-foto.site"
        assertEquals(MessageVerdict.DANGEROUS, analyzer(RemoteConfig.DEFAULT, loud).analyze(text).verdict)
        val off = analyzer(RemoteConfig(smsTextModelEnabled = false), loud).analyze(text)
        assertEquals(rulesOnly.analyze(text), off)
        assertTrue(MessageAnalyzer.R_TEXT_RESEMBLES_SCAM !in off.reasons)
    }

    @Test
    fun `a raised danger threshold keeps a high score at caution`() {
        val text = "Посмотри, что я нашла вчера вечером: kotiki-foto.site"
        val p = requireNotNull(MessageTestSupport.model.score(text))
        // Thresholds set so the shipped-model score is dangerous; then the server raises danger above it.
        val m = modelWith(caution = p / 2, danger = p / 2)
        assertEquals(MessageVerdict.DANGEROUS, analyzer(RemoteConfig.DEFAULT, m).analyze(text).verdict)
        val raised = analyzer(RemoteConfig(true, null, (p + 1.0) / 2), m).analyze(text)
        assertEquals(MessageVerdict.CAUTION, raised.verdict)
        assertTrue(MessageAnalyzer.R_TEXT_RESEMBLES_SCAM in raised.reasons)
        // And raising caution above the score too leaves the rules' verdict.
        val both = analyzer(RemoteConfig(true, (p + 1.0) / 2, (p + 1.0) / 2), m).analyze(text)
        assertEquals(rulesOnly.analyze(text), both)
    }

    @Test
    fun `an override below the shipped threshold cannot make the model louder`() {
        val shipped = MessageTestSupport.model
        val lowered = RemoteConfig(true, smsTextModelCautionThresholdOverride = 0.01, smsTextModelDangerThresholdOverride = 0.01)
        val on = analyzer(RemoteConfig.DEFAULT, shipped)
        val tried = analyzer(lowered, shipped)
        for (text in allTexts) assertEquals(on.analyze(text), tried.analyze(text), text.take(120))
        assertNotEquals(0.01, lowered.cautionThreshold(shipped.cautionThreshold))
    }
}
