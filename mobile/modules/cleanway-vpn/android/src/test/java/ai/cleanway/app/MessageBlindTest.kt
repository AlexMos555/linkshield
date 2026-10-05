package ai.cleanway.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The 2026-10b blind set: 107 legitimate and 110 scam messages written by
 * someone who never saw the rules, the analyzer, MessageCorpus, the 2026-10
 * held-out set or the evaluation's miss lists
 * (src/test/resources/message_blind_2026-10b.tsv; numbers in
 * docs/EVALUATION_2026-10.md §3.9).
 *
 * This is a measurement, not a contract and not a tuning set. Every miss and
 * every false alarm is printed and written to build/message-blind-report.md.
 * The numbers pinned below are the FIRST blind measurement, taken on the
 * rules of PR #86 after they were frozen. They are floors and a cap only so
 * a later change cannot quietly make the set worse — never tune a rule on
 * these texts, and never edit a message to pass. Once rules are changed
 * because of what this set showed, it is no longer blind for those families.
 */
class MessageBlindTest {

    private val analyzer = MessageTestSupport.analyzer()

    private data class Case(val label: String, val family: String, val text: String)

    private data class Scored(val case: Case, val result: MessageAnalysis) {
        val flagged: Boolean get() = result.verdict != MessageVerdict.NO_SIGNALS
    }

    private val cases: List<Case> by lazy { load() }
    private val scored: List<Scored> by lazy { cases.map { Scored(it, analyzer.analyze(it.text)) } }

    @Test
    fun `the set is 107 legit and 110 scam, unique, and none of it is in the tuning corpus`() {
        assertEquals(107, cases.count { it.label == "legit" }, "legit messages")
        assertEquals(110, cases.count { it.label == "scam" }, "scam messages")
        assertEquals(cases.size, cases.map { it.text }.toSet().size, "duplicate message in the blind set")
        val corpus = (MessageCorpus.SCAMS_RU + MessageCorpus.SCAMS_EN + MessageCorpus.SCAM_VARIANTS +
            MessageCorpus.SCAM_REVIEW + MessageCorpus.LEGIT_RU + MessageCorpus.LEGIT_EN + MessageCorpus.LEGIT_VARIANTS +
            MessageCorpus.SCAM_2026_10_DANGEROUS + MessageCorpus.SCAM_2026_10_CAUTION + MessageCorpus.LEGIT_2026_10 +
            MessageCorpus.SCAM_2026_10_UPGRADES + MessageCorpus.LEGIT_2026_10_UPGRADES + MessageSchemeCorpus.SCAM_DANGEROUS +
            MessageSchemeCorpus.SCAM_CAUTION + MessageSchemeCorpus.LEGIT).toSet()
        assertEquals(emptyList(), cases.map { it.text }.filter { it in corpus }, "blind message also in MessageCorpus")
    }

    @Test
    fun `report every miss and every false alarm`() {
        val legit = scored.filter { it.case.label == "legit" }
        val scams = scored.filter { it.case.label == "scam" }
        val falseAlarms = legit.filter { it.flagged }
        val lines = buildList {
            add("# Blind message set 2026-10b")
            add("")
            add("legit: ${legit.size}, false alarms: ${falseAlarms.size} " +
                "(dangerous ${falseAlarms.count { it.result.verdict == MessageVerdict.DANGEROUS }}, " +
                "caution ${falseAlarms.count { it.result.verdict == MessageVerdict.CAUTION }})")
            add("scam: ${scams.size}, flagged: ${scams.count { it.flagged }}, " +
                "dangerous: ${scams.count { it.result.verdict == MessageVerdict.DANGEROUS }}, " +
                "caution: ${scams.count { it.result.verdict == MessageVerdict.CAUTION }}, " +
                "missed: ${scams.count { !it.flagged }}")
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
            scams.filter { !it.flagged }.forEach { add("- [${it.case.family}] ${it.case.text}") }
            add("")
            add("## Scams flagged only as caution")
            scams.filter { it.result.verdict == MessageVerdict.CAUTION }.forEach {
                add("- [${it.case.family}] ${it.result.reasons}: ${it.case.text}")
            }
        }
        lines.forEach { println("BLIND $it") }
        File("build").mkdirs()
        File("build/message-blind-report.md").writeText(lines.joinToString("\n") + "\n")
        for (s in scored) {
            if (!s.flagged) continue
            assertTrue(s.result.reasons.isNotEmpty(), "no reasons for: ${s.case.text}")
            assertTrue(MessageAnalyzer.ALL_REASONS.containsAll(s.result.reasons), "unknown reason in ${s.result.reasons}")
        }
    }

    @Test
    fun `the first blind numbers do not regress`() {
        val legit = scored.filter { it.case.label == "legit" }
        val scams = scored.filter { it.case.label == "scam" }
        val falseAlarms = legit.count { it.flagged }
        val flagged = scams.count { it.flagged }
        val dangerous = scams.count { it.result.verdict == MessageVerdict.DANGEROUS }
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
        const val FILE = "message_blind_2026-10b.tsv"
        // First blind measurement, 2026-10-05, on the frozen rules of PR #86
        // (origin/main's rules scored the same): 0/107 false alarms, 26/110
        // scams flagged, 20/110 dangerous. 42 of the 84 misses carry a link
        // with a reserved TLD (.test/.example/.invalid) that the bare-link
        // extractor does not accept — see §3.9. These are floors against
        // regression, NOT targets: do not tune rules on these texts.
        const val MAX_FALSE_ALARMS = 0
        const val MIN_FLAGGED = 26
        const val MIN_DANGEROUS = 20
    }
}
