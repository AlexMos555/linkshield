package ai.cleanway.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The 2026-10 held-out set: 60 legitimate and 60 scam messages written after
 * the rules and after MessageCorpus, and scored before any tuning
 * (src/test/resources/message_heldout_2026-10.tsv; first pass in
 * docs/EVALUATION_2026-10.md).
 *
 * This is a measurement, not a contract: every miss and every false alarm is
 * printed with its reasons and written to build/message-heldout-report.md,
 * and the numbers measured on 2026-10-04 are pinned as floors so a later rule
 * change cannot quietly make the set worse. Raise the floors when the rules
 * improve; never edit a message to pass.
 */
class MessageHeldOutTest {

    private val analyzer = MessageTestSupport.analyzer()

    private data class Case(val label: String, val family: String, val text: String)

    private data class Scored(val case: Case, val result: MessageAnalysis) {
        val flagged: Boolean get() = result.verdict != MessageVerdict.NO_SIGNALS
    }

    private val cases: List<Case> by lazy { load() }
    private val scored: List<Scored> by lazy { cases.map { Scored(it, analyzer.analyze(it.text)) } }

    @Test
    fun `the set is 60 legit and 60 scam, unique, and none of it is in the tuning corpus`() {
        assertEquals(60, cases.count { it.label == "legit" }, "legit messages")
        assertEquals(60, cases.count { it.label == "scam" }, "scam messages")
        assertEquals(cases.size, cases.map { it.text }.toSet().size, "duplicate message in the held-out set")
        val corpus = (MessageCorpus.SCAMS_RU + MessageCorpus.SCAMS_EN + MessageCorpus.SCAM_VARIANTS +
            MessageCorpus.SCAM_REVIEW + MessageCorpus.LEGIT_RU + MessageCorpus.LEGIT_EN + MessageCorpus.LEGIT_VARIANTS +
            MessageCorpus.SCAM_2026_10_DANGEROUS + MessageCorpus.SCAM_2026_10_CAUTION + MessageCorpus.LEGIT_2026_10).toSet()
        assertEquals(emptyList(), cases.map { it.text }.filter { it in corpus }, "held-out message also in MessageCorpus")
        assertTrue(cases.map { it.family }.toSet().size >= 20, "families")
    }

    @Test
    fun `report every miss and every false alarm`() {
        val legit = scored.filter { it.case.label == "legit" }
        val scams = scored.filter { it.case.label == "scam" }
        val falseAlarms = legit.filter { it.flagged }
        val misses = scams.filter { !it.flagged }
        val lines = buildList {
            add("# Held-out message set 2026-10 — first pass")
            add("")
            add("legit: ${legit.size}, false alarms: ${falseAlarms.size} " +
                "(dangerous ${falseAlarms.count { it.result.verdict == MessageVerdict.DANGEROUS }}, " +
                "caution ${falseAlarms.count { it.result.verdict == MessageVerdict.CAUTION }})")
            add("scam: ${scams.size}, flagged: ${scams.count { it.flagged }}, " +
                "dangerous: ${scams.count { it.result.verdict == MessageVerdict.DANGEROUS }}, " +
                "caution: ${scams.count { it.result.verdict == MessageVerdict.CAUTION }}, missed: ${misses.size}")
            add("")
            add("## By family (flagged / total, dangerous)")
            for ((family, group) in scored.groupBy { it.case.label + "/" + it.case.family }.toSortedMap()) {
                add("- $family: ${group.count { it.flagged }}/${group.size}, dangerous ${group.count { it.result.verdict == MessageVerdict.DANGEROUS }}")
            }
            add("")
            add("## False alarms (legit flagged)")
            falseAlarms.forEach { add("- [${it.case.family}] ${it.result.verdict} ${it.result.reasons}: ${it.case.text}") }
            add("")
            add("## Misses (scam with no signals)")
            misses.forEach { add("- [${it.case.family}] ${it.case.text}") }
            add("")
            add("## Scams flagged only as caution")
            scams.filter { it.result.verdict == MessageVerdict.CAUTION }.forEach {
                add("- [${it.case.family}] ${it.result.reasons}: ${it.case.text}")
            }
            add("")
            add("## Legit shapes recognised on the legit half")
            for ((shape, n) in legit.groupingBy { it.result.legitShape ?: "none" }.eachCount().toSortedMap()) add("- $shape: $n")
        }
        lines.forEach { println("HELDOUT $it") }
        File("build").mkdirs()
        File("build/message-heldout-report.md").writeText(lines.joinToString("\n") + "\n")
        for (s in scored) {
            if (!s.flagged) continue
            assertTrue(s.result.reasons.isNotEmpty(), "no reasons for: ${s.case.text}")
            assertTrue(MessageAnalyzer.ALL_REASONS.containsAll(s.result.reasons), "unknown reason in ${s.result.reasons}")
        }
    }

    @Test
    fun `the first-pass numbers do not regress`() {
        val legit = scored.filter { it.case.label == "legit" }
        val scams = scored.filter { it.case.label == "scam" }
        val falseAlarms = legit.count { it.flagged }
        val flagged = scams.count { it.flagged }
        val dangerous = scams.count { it.result.verdict == MessageVerdict.DANGEROUS }
        // Measured 2026-10-04 on the untuned rules. A fix may lower the first
        // cap and raise the two floors; nothing may move them the other way.
        assertTrue(falseAlarms <= MAX_FALSE_ALARMS, "false alarms rose to $falseAlarms (cap $MAX_FALSE_ALARMS)")
        assertTrue(flagged >= MIN_FLAGGED, "flagged scams fell to $flagged (floor $MIN_FLAGGED)")
        assertTrue(dangerous >= MIN_DANGEROUS, "dangerous scams fell to $dangerous (floor $MIN_DANGEROUS)")
    }

    private fun load(): List<Case> {
        val file = listOf(File("src/test/resources/$FILE"), File("android/src/test/resources/$FILE"))
            .firstOrNull { it.exists() } ?: error("$FILE not found from ${File(".").absolutePath}")
        return file.readLines().filter { it.isNotBlank() && !it.startsWith("#") }.map { line ->
            val parts = line.split('\t')
            require(parts.size == 3 && parts[0] in setOf("legit", "scam") && parts[2].isNotBlank()) { "bad line: $line" }
            Case(parts[0], parts[1], parts[2])
        }
    }

    private companion object {
        const val FILE = "message_heldout_2026-10.tsv"
        // First pass, 2026-10-04: 0 false alarms, 50/60 scams flagged, 40/60 dangerous.
        // Raised 2026-10-05 by the commit that changed the rules for the ten
        // blind-spot families (tuned on new MessageCorpus phrasings, not on this
        // set): 0 false alarms, 60/60 flagged, 45/60 dangerous. The false-alarm
        // cap stays 0 — a hard requirement, not a floor to trade against.
        const val MAX_FALSE_ALARMS = 0
        const val MIN_FLAGGED = 60
        const val MIN_DANGEROUS = 45
    }
}
