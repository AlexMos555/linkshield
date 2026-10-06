package ai.cleanway.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The blind sets: messages written by someone who never saw the rules, the
 * analyzer, MessageCorpus, the 2026-10 held-out set or the evaluation's miss
 * lists (src/test/resources/message_blind_*.tsv; numbers in
 * docs/EVALUATION_2026-10.md §3.9, §3.11, §3.13, §3.14 and §3.15).
 *  - 2026-10b: 107 legitimate and 110 scam messages.
 *  - 2026-10c: 112 legitimate and 112 scam messages, written by a second
 *    agent that saw only the column format of 2026-10b.
 *  - 2026-10d: 125 legitimate and 137 scam messages, written by a third agent
 *    with no access to the rules, the code, the docs or the earlier sets
 *    (only the label and family columns of two rows of 2026-10c), with the
 *    emphasis on paraphrase.
 *  - 2026-10e: 155 legitimate and 158 scam messages, written by a fourth agent
 *    with no access to the rules, models, training data or other sets, and
 *    opened only after the text model of §3.14 was frozen (§3.15).
 *
 * This is a measurement, not a contract and not a tuning set. Every miss and
 * every false alarm is printed and written to build/message-blind-report-<set>.md.
 * The numbers pinned below are MEASUREMENTS of the rules as they stood, kept
 * as floors and a cap only so a later change cannot quietly make a set worse.
 * Never tune a rule on these texts, and never edit a message to pass. Once
 * rules are changed because of what a set showed, it is no longer blind for
 * those families.
 */
class MessageBlindTest {

    private val analyzer = MessageTestSupport.analyzer()

    private data class Case(val label: String, val family: String, val text: String)

    private data class Scored(val case: Case, val result: MessageAnalysis) {
        val flagged: Boolean get() = result.verdict != MessageVerdict.NO_SIGNALS
    }

    /** One blind file, its expected size, and the floors measured on it. */
    private data class BlindSet(
        val name: String,
        val legit: Int,
        val scam: Int,
        val maxFalseAlarms: Int,
        val minFlagged: Int,
        val minDangerous: Int,
        /** Rows that happen to match a corpus line word for word, written independently; reported, not hidden. */
        val alsoInCorpus: Set<String> = emptySet(),
        /** The same, for a row of an earlier set. */
        val alsoInEarlierSet: Set<String> = emptySet(),
    ) {
        val file: String get() = "message_blind_$name.tsv"
    }

    private val loaded: Map<BlindSet, List<Scored>> by lazy {
        SETS.associateWith { set -> load(set).map { Scored(it, analyzer.analyze(it.text)) } }
    }

    @Test
    fun `each set has its size, is unique, and none of it is in the tuning corpus`() {
        val corpus = (MessageCorpus.SCAMS_RU + MessageCorpus.SCAMS_EN + MessageCorpus.SCAM_VARIANTS +
            MessageCorpus.SCAM_REVIEW + MessageCorpus.LEGIT_RU + MessageCorpus.LEGIT_EN + MessageCorpus.LEGIT_VARIANTS +
            MessageCorpus.SCAM_2026_10_DANGEROUS + MessageCorpus.SCAM_2026_10_CAUTION + MessageCorpus.LEGIT_2026_10 +
            MessageCorpus.SCAM_2026_10_UPGRADES + MessageCorpus.LEGIT_2026_10_UPGRADES + MessageSchemeCorpus.SCAM_DANGEROUS +
            MessageSchemeCorpus.SCAM_CAUTION + MessageSchemeCorpus.LEGIT + MessageGenericCorpus.SCAM_DANGEROUS +
            MessageGenericCorpus.SCAM_CAUTION + MessageGenericCorpus.LEGIT).toSet()
        for ((set, scored) in loaded) {
            val cases = scored.map { it.case }
            assertEquals(set.legit, cases.count { it.label == "legit" }, "${set.name}: legit messages")
            assertEquals(set.scam, cases.count { it.label == "scam" }, "${set.name}: scam messages")
            assertEquals(cases.size, cases.map { it.text }.toSet().size, "${set.name}: duplicate message")
            assertEquals(set.alsoInCorpus, cases.map { it.text }.filter { it in corpus }.toSet(), "${set.name}: message also in MessageCorpus")
        }
        val texts = SETS.map { set -> set to loaded.getValue(set).map { it.case.text }.toSet() }
        for ((i, first) in texts.withIndex()) {
            for (second in texts.drop(i + 1)) {
                val shared = first.second intersect second.second
                val known = (first.first.alsoInEarlierSet + second.first.alsoInEarlierSet) intersect shared
                assertEquals(known, shared, "the same message in ${first.first.name} and ${second.first.name}")
            }
        }
    }

    @Test
    fun `report every miss and every false alarm`() {
        for ((set, scored) in loaded) {
            val lines = report(set, scored)
            lines.forEach { println("BLIND[${set.name}] $it") }
            File("build").mkdirs()
            File("build/message-blind-report-${set.name}.md").writeText(lines.joinToString("\n") + "\n")
            for (s in scored) {
                if (!s.flagged) continue
                assertTrue(s.result.reasons.isNotEmpty(), "no reasons for: ${s.case.text}")
                assertTrue(MessageAnalyzer.ALL_REASONS.containsAll(s.result.reasons), "unknown reason in ${s.result.reasons}")
            }
        }
    }

    @Test
    fun `the measured blind numbers do not regress`() {
        for ((set, scored) in loaded) {
            val legit = scored.filter { it.case.label == "legit" }
            val scams = scored.filter { it.case.label == "scam" }
            val falseAlarms = legit.count { it.flagged }
            val flagged = scams.count { it.flagged }
            val dangerous = scams.count { it.result.verdict == MessageVerdict.DANGEROUS }
            assertTrue(falseAlarms <= set.maxFalseAlarms, "${set.name}: false alarms rose to $falseAlarms (cap ${set.maxFalseAlarms})")
            assertTrue(flagged >= set.minFlagged, "${set.name}: flagged scams fell to $flagged (floor ${set.minFlagged})")
            assertTrue(dangerous >= set.minDangerous, "${set.name}: dangerous scams fell to $dangerous (floor ${set.minDangerous})")
        }
    }

    private fun report(set: BlindSet, scored: List<Scored>): List<String> = buildList {
        val legit = scored.filter { it.case.label == "legit" }
        val scams = scored.filter { it.case.label == "scam" }
        val falseAlarms = legit.filter { it.flagged }
        add("# Blind message set ${set.name}")
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

    private fun load(set: BlindSet): List<Case> {
        val file = listOf(File("src/test/resources/${set.file}"), File("android/src/test/resources/${set.file}"))
            .firstOrNull { it.exists() } ?: error("${set.file} not found from ${File(".").absolutePath}")
        return file.readLines().filter { it.isNotBlank() && !it.startsWith("#") }.map { line ->
            val parts = line.split('\t')
            require(parts.size == 3 && parts[0] in setOf("legit", "scam") && parts[2].isNotBlank()) { "bad line: $line" }
            Case(parts[0], parts[1], parts[2])
        }
    }

    private companion object {
        // MEASUREMENTS, not targets. Do not tune rules on these texts.
        //
        // 2026-10b. First measured 2026-10-05 on the frozen rules of PR #86:
        // 0/107 false alarms, 26/110 scams flagged, 20/110 dangerous (§3.9).
        // Re-measured 2026-10-05 on origin/main after #91 (any-TLD links) and
        // #92 (ten new schemes, written without opening this set): 0/107,
        // 33/110 flagged, 26/110 dangerous (§3.11). #91 alone changed no verdict
        // on either set.
        //
        // 2026-10c. First measured 2026-10-05 on the same origin/main rules,
        // after #91 and #92 were merged: 0/112 false alarms, 65/112 scams
        // flagged, 47/112 dangerous (§3.11). The rules before #91 and #92
        // scored 60/42/0.
        //
        // 2026-10d. First measured 2026-10-06, on origin/main (8682a9d) and on
        // the generic layer (PR #96, rules frozen before this set was opened):
        // main 1/125 false alarms, 55/137 flagged, 43/137 dangerous; #96 1/125,
        // 64/137, 48/137. The one false alarm is the same on both, from a scheme
        // rule older than #96 (§3.13); it is pinned as measured, not fixed.
        //
        // PR #96 measured 2026-10b 0/107, 35/110, 29/110; 2026-10c 0/112,
        // 75/112, 54/112 (§3.13).
        //
        // 2026-10-06, the text model (MessageModel.kt, ml/sms; §3.14). The model
        // never trained on these sets, but its two thresholds were CHOSEN on
        // them (with the held-out set and the Kotlin corpora), so from here on
        // the three sets measure the rules + model with tuned thresholds, not
        // blind: 2026-10b 0/107, 100/110, 79/110; 2026-10c 0/112, 110/112,
        // 102/112; 2026-10d 1/125 (the same rule false alarm), 114/137, 102/137.
        // The floors below are those measurements.
        val SETS = listOf(
            BlindSet("2026-10b", legit = 107, scam = 110, maxFalseAlarms = 0, minFlagged = 100, minDangerous = 79),
            BlindSet("2026-10c", legit = 112, scam = 112, maxFalseAlarms = 0, minFlagged = 110, minDangerous = 102),
            BlindSet("2026-10d", legit = 125, scam = 137, maxFalseAlarms = 1, minFlagged = 114, minDangerous = 102),
            // 2026-10e. First measured 2026-10-06, after the text model and its
            // thresholds were frozen in PR #99: set e was never used to choose
            // anything — no rule, weight, feature, threshold or corpus line.
            // origin/main rules: 0/155 false alarms, 82/158 flagged, 59/158
            // dangerous; rules + model (PR #99): 0/155, 141/158, 119/158 (§3.15).
            // The floors and the cap are that MEASUREMENT, not a target. One legit
            // row equals a MessageCorpus.LEGIT_VARIANTS line word for word, and
            // another a 2026-10b legit row (stock notices the author wrote
            // independently); both are counted, not removed.
            BlindSet(
                "2026-10e", legit = 155, scam = 158, maxFalseAlarms = 0, minFlagged = 141, minDangerous = 119,
                alsoInCorpus = setOf("Госуслуги: по вашему заявлению принято решение. Посмотреть: gosuslugi.ru"),
                alsoInEarlierSet = setOf("Самокат: курьер уже в пути, будет через 12 минут"),
            ),
        )
    }
}
