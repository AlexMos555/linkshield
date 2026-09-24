package ai.cleanway.app

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The message check against realistic traffic.
 *
 * Two corpora, both paraphrased from the 2025–26 patterns (research notes in
 * the SMS-check scouting pass; no text copied from sources):
 *  - SCAMS: the Russian families by volume — Госуслуги "взломан, позвоните",
 *    bank security callbacks, safe account, code harvesting, delivery fees,
 *    fines and taxes, compensation, relative in trouble, malware lures,
 *    operator/SIM, prizes, investment — plus English equivalents.
 *  - LEGIT: what a Tele2 subscriber really receives and what uses the same
 *    words on purpose — Сбер/Т-Банк/ВТБ/Альфа login codes ("никому не
 *    сообщайте код… позвоните на 900"), Госуслуги codes and notices, pickup
 *    codes you ARE supposed to tell the courier, payment alerts, bank
 *    safe-account warnings, t2 "период охлаждения", МЧС alerts, reminders.
 *
 * The contract: ZERO warnings on the legitimate corpus (a false alarm on a
 * real bank code teaches a grandmother to ignore us), and recall on the scam
 * corpus reported and held above a floor. A legit message may only be
 * flagged for a blocklisted link — pinned separately below.
 *
 * The messages live in MessageCorpus.kt.
 */
class MessageCorpusTest {

    private val analyzer = MessageTestSupport.analyzer()

    @Test
    fun `zero warnings on the legitimate corpus`() {
        assertTrue(MessageCorpus.LEGIT_RU.size >= 40, "the Russian legit corpus must stay at 40+ messages")
        val legit = MessageCorpus.LEGIT_RU + MessageCorpus.LEGIT_EN + MessageCorpus.LEGIT_VARIANTS
        val flagged = legit.map { it to analyzer.analyze(it) }.filter { it.second.verdict != MessageVerdict.NO_SIGNALS }
        flagged.forEach { (text, r) -> println("LEGIT FLAGGED ${r.verdict} ${r.reasons}: $text") }
        println("MESSAGE_CORPUS legit: ${legit.size - flagged.size}/${legit.size} with no signals")
        assertEquals(emptyList(), flagged.map { it.first }, "legitimate messages raised a warning")
    }

    @Test
    fun `recall on the scam corpus stays above the floor`() {
        assertTrue(MessageCorpus.SCAMS_RU.size >= 40, "the Russian scam corpus must stay at 40+ messages")
        val primary = recall("primary", MessageCorpus.SCAMS_RU + MessageCorpus.SCAMS_EN)
        val variants = recall("variants", MessageCorpus.SCAM_VARIANTS)
        // Floors, not targets: raise them when the rules improve, never lower them silently.
        assertTrue(primary.flagged * 100 >= primary.total * 98, "primary flagged recall fell: $primary")
        assertTrue(primary.dangerous * 100 >= primary.total * 90, "primary dangerous recall fell: $primary")
        assertTrue(variants.flagged * 100 >= variants.total * 85, "variant flagged recall fell: $variants")
        assertTrue(variants.dangerous * 100 >= variants.total * 75, "variant dangerous recall fell: $variants")
    }

    @Test
    fun `every scam the review found is flagged`() {
        val review = recall("review", MessageCorpus.SCAM_REVIEW)
        assertEquals(review.total, review.flagged, "a review-found scam slipped through again: $review")
    }

    private data class Recall(val flagged: Int, val dangerous: Int, val total: Int)

    private fun recall(label: String, scams: List<String>): Recall {
        val results = scams.map { it to analyzer.analyze(it) }
        results.filter { it.second.verdict != MessageVerdict.DANGEROUS }.forEach { (text, r) ->
            println("SCAM[$label] ${r.verdict} ${r.reasons}: $text")
        }
        val out = Recall(
            flagged = results.count { it.second.verdict != MessageVerdict.NO_SIGNALS },
            dangerous = results.count { it.second.verdict == MessageVerdict.DANGEROUS },
            total = scams.size,
        )
        println("MESSAGE_CORPUS recall[$label]: flagged ${out.flagged}/${out.total}, dangerous ${out.dangerous}/${out.total}")
        return out
    }

    @Test
    fun `every scam warning carries reasons the UI knows`() {
        for (text in MessageCorpus.SCAMS_RU + MessageCorpus.SCAMS_EN + MessageCorpus.SCAM_VARIANTS + MessageCorpus.SCAM_REVIEW) {
            val r = analyzer.analyze(text)
            if (r.verdict == MessageVerdict.NO_SIGNALS) continue
            assertTrue(r.reasons.isNotEmpty(), "no reasons for: $text")
            assertTrue(MessageAnalyzer.ALL_REASONS.containsAll(r.reasons), "unknown reason in ${r.reasons}")
        }
    }

    @Test
    fun `a legitimate message is flagged only for a blocklisted link`() {
        val code = "Почта России: посылка прибыла в отделение 101000. Код для получения: 482193. Отслеживание: pochta.ru/tracking"
        val clean = MessageTestSupport.analyzer().analyze(code)
        assertEquals(MessageVerdict.NO_SIGNALS, clean.verdict)
        assertEquals("pickup_code", clean.legitShape)
        // Same message, but the tracking host is on the list (a hijacked or
        // look-alike domain): the shape never hides a listed link.
        val listed = MessageTestSupport.analyzer(MessageTestSupport.list("pochta.ru")).analyze(code)
        assertEquals(MessageVerdict.DANGEROUS, listed.verdict)
        assertEquals(listOf("link_blocklisted"), listed.reasons)
        assertEquals(LinkStatus.BLOCKED, listed.links.single().status)
    }
}
