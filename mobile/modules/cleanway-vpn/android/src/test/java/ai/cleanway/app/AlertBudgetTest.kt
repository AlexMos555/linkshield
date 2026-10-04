package ai.cleanway.app

import ai.cleanway.app.AlertBudget.Severity
import ai.cleanway.app.AlertBudget.Verdict
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The pop-up budget (plan №7): 3 an hour, 10 a day, one per site in six
 * hours, "careful" always silent, a burst of lookups is one attempt, and
 * past the cap one collapsed "N more" notice.
 */
class AlertBudgetTest {

    private val t0 = 1_727_600_000_000L
    private val second = 1_000L
    private val minute = 60_000L
    private val hour = 60 * minute

    @Test
    fun `a burst of lookups of one site is one pop-up`() {
        val b = AlertBudget()
        assertEquals(Verdict.HEADS_UP, b.decide(Severity.DANGER, "evil.example", t0))
        // A, AAAA, HTTPS, the browser's retries and auto-reloads: all inside 45 s of the last lookup.
        assertEquals(Verdict.DROP, b.decide(Severity.DANGER, "evil.example", t0 + second))
        assertEquals(Verdict.DROP, b.decide(Severity.DANGER, "evil.example", t0 + 30 * second))
        assertEquals("the window runs from the LAST lookup", Verdict.DROP, b.decide(Severity.DANGER, "evil.example", t0 + 70 * second))
    }

    @Test
    fun `a second try at the same site is shown, silently, for six hours`() {
        val b = AlertBudget()
        assertEquals(Verdict.HEADS_UP, b.decide(Severity.DANGER, "evil.example", t0))
        // 1.0.3: a second try must not look like the shield did nothing —
        // the notification is refreshed, but without a second pop-up.
        assertEquals(Verdict.SILENT, b.decide(Severity.DANGER, "evil.example", t0 + 2 * minute))
        assertEquals(Verdict.SILENT, b.decide(Severity.DANGER, "evil.example", t0 + 5 * hour))
        assertEquals(Verdict.HEADS_UP, b.decide(Severity.DANGER, "evil.example", t0 + 6 * hour + minute))
    }

    @Test
    fun `careful never pops up`() {
        val b = AlertBudget()
        assertEquals(Verdict.SILENT, b.decide(Severity.CAUTION, "meh.example", t0))
        assertEquals(Verdict.SILENT, b.decide(Severity.CAUTION, "meh.example", t0 + 2 * minute))
        assertEquals(Verdict.SILENT, b.decide(Severity.CAUTION, "other.example", t0 + 3 * minute))
        // Warnings take nothing from the danger budget.
        for (i in 1..3) assertEquals(Verdict.HEADS_UP, b.decide(Severity.DANGER, "site$i.example", t0 + 10 * minute + i * minute))
    }

    @Test
    fun `three pop-ups an hour, then one collapsed notice that counts`() {
        val b = AlertBudget()
        for (i in 1..3) assertEquals(Verdict.HEADS_UP, b.decide(Severity.DANGER, "site$i.example", t0 + i * minute))
        assertEquals(Verdict.SUMMARY(1), b.decide(Severity.DANGER, "site4.example", t0 + 4 * minute))
        assertEquals(Verdict.SUMMARY(2), b.decide(Severity.DANGER, "site5.example", t0 + 5 * minute))
        // A repeat of a site that already popped up is a silent refresh, not a fourth pop-up and not "one more".
        assertEquals(Verdict.SILENT, b.decide(Severity.DANGER, "site1.example", t0 + 6 * minute))
        // An hour later the first two pop-ups have aged out of the sliding
        // hour (the one at t0+3 min has not yet): room for two more, and
        // when the cap is hit again the summary count starts over at 1.
        assertEquals(Verdict.HEADS_UP, b.decide(Severity.DANGER, "site6.example", t0 + hour + 2 * minute))
        assertEquals(Verdict.HEADS_UP, b.decide(Severity.DANGER, "site7.example", t0 + hour + 2 * minute + 30 * second))
        assertEquals(Verdict.SUMMARY(1), b.decide(Severity.DANGER, "site8.example", t0 + hour + 2 * minute + 40 * second))
        // Once t0+3 min is a full hour old, it no longer counts either.
        assertEquals(Verdict.HEADS_UP, b.decide(Severity.DANGER, "site9.example", t0 + hour + 3 * minute))
    }

    @Test
    fun `ten pop-ups a day`() {
        val b = AlertBudget()
        var t = t0
        for (i in 1..10) {
            // Spread out so the hourly cap never applies: one every 25 minutes.
            t += 25 * minute
            assertEquals("pop-up $i", Verdict.HEADS_UP, b.decide(Severity.DANGER, "site$i.example", t))
        }
        assertEquals(Verdict.SUMMARY(1), b.decide(Severity.DANGER, "site11.example", t + 25 * minute))
        // A day after the first one, that one no longer counts.
        assertEquals(Verdict.HEADS_UP, b.decide(Severity.DANGER, "site12.example", t0 + 25 * minute + 24 * hour + minute))
    }

    @Test
    fun `the after-call notice shares the budget under its own key`() {
        val b = AlertBudget()
        assertEquals(Verdict.HEADS_UP, b.decide(Severity.DANGER, CallGuard.budgetKey(t0 - 5 * minute), t0))
        assertEquals(Verdict.HEADS_UP, b.decide(Severity.DANGER, "evil.example", t0 + minute))
        assertEquals(Verdict.HEADS_UP, b.decide(Severity.DANGER, "bad.example", t0 + 2 * minute))
        assertEquals(Verdict.SUMMARY(1), b.decide(Severity.DANGER, "worse.example", t0 + 3 * minute))
    }

    @Test
    fun `a second scam call an hour later gets its own pop-up, not the six-hour silence`() {
        val b = AlertBudget()
        // Call 1 (began t0-5min) is noticed at t0; call 2 ("I'll call you back") began at t0+hour.
        assertEquals(Verdict.HEADS_UP, b.decide(Severity.DANGER, CallGuard.budgetKey(t0 - 5 * minute), t0))
        assertEquals(Verdict.HEADS_UP, b.decide(Severity.DANGER, CallGuard.budgetKey(t0 + hour), t0 + hour + 4 * minute))
        // One key per call: the same call cannot be noticed loudly twice.
        assertEquals(Verdict.SILENT, b.decide(Severity.DANGER, CallGuard.budgetKey(t0 + hour), t0 + hour + 10 * minute))
    }

    @Test
    fun `a clock stepped backwards does not silence anything forever`() {
        val b = AlertBudget()
        assertEquals(Verdict.HEADS_UP, b.decide(Severity.DANGER, "evil.example", t0))
        // Now earlier than the last lookup: neither the burst nor the six-hour window applies.
        assertEquals(Verdict.HEADS_UP, b.decide(Severity.DANGER, "evil.example", t0 - hour))
    }

    @Test
    fun `a block is danger, a late warning is danger only on a dangerous verdict`() {
        assertEquals(Severity.DANGER, BlockNotifier.severityOf(BlockLog.KIND_BLOCKED))
        assertEquals("a block is on the list; the level is irrelevant", Severity.DANGER, BlockNotifier.severityOf(BlockLog.KIND_BLOCKED, "caution"))
        assertEquals(Severity.DANGER, BlockNotifier.severityOf(BlockLog.KIND_WARNED, "dangerous"))
        // "caution" with the model sure (LinkVerdictPolicy WARN) is still "Careful": silent.
        assertEquals(Severity.CAUTION, BlockNotifier.severityOf(BlockLog.KIND_WARNED, "caution"))
        assertEquals("no level known: careful", Severity.CAUTION, BlockNotifier.severityOf(BlockLog.KIND_WARNED))
    }
}
