package ai.cleanway.app

import ai.cleanway.app.NotificationCaps.Decision
import ai.cleanway.app.NotificationCaps.Kind
import ai.cleanway.app.NotificationCaps.Shown
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * How many warnings a person gets, and how loud. The limits are the
 * elderly-first notification rules (3 loud an hour, 10 a day, one per
 * sender in 6 hours, "be careful" quietly, the rest folded into one) — a
 * fourth pop-up in an hour is the one that gets the important one swiped
 * away with it.
 */
class NotificationCapsTest {
    private val hour = NotificationCaps.HOUR_MS
    private val now = 100L * hour

    private fun loud(ts: Long, sender: String? = "900") = Shown(ts, Kind.LOUD, sender)
    private fun quiet(ts: Long, sender: String? = "900") = Shown(ts, Kind.QUIET, sender)
    private fun folded(ts: Long, sender: String? = "900") = Shown(ts, Kind.FOLDED, sender)

    /** A run of warnings, each from its own sender, so only the counts decide. */
    private fun distinct(kind: Kind, n: Int, from: Long, step: Long = 60_000L) =
        List(n) { i -> Shown(from + i * step, kind, "sender-$i") }

    @Test
    fun `a dangerous message pops up, a be-careful one arrives quietly`() {
        assertEquals(Decision.Loud, NotificationCaps.decide(dangerous = true, sender = "900", shown = emptyList(), now = now))
        assertEquals(Decision.Quiet, NotificationCaps.decide(dangerous = false, sender = "900", shown = emptyList(), now = now))
    }

    @Test
    fun `the fourth loud one in an hour folds, and an hour later it pops up again`() {
        val three = distinct(Kind.LOUD, 3, from = now - 30 * 60_000L)
        assertEquals(Decision.Folded(1), NotificationCaps.decide(true, "new", three, now))
        // The oldest of the three is now more than an hour ago.
        assertEquals(Decision.Loud, NotificationCaps.decide(true, "new", three, now + hour - 29 * 60_000L))
    }

    @Test
    fun `quiet warnings do not use up the loud budget, but every warning counts toward the day`() {
        val quietOnes = distinct(Kind.QUIET, 5, from = now - 10 * 60_000L)
        assertEquals(Decision.Loud, NotificationCaps.decide(true, "new", quietOnes, now))
        val nine = distinct(Kind.QUIET, 6, from = now - 20 * hour) + distinct(Kind.LOUD, 3, from = now - 5 * hour)
        assertEquals(Decision.Loud, NotificationCaps.decide(true, "new", nine, now))
        val ten = nine + quiet(now - hour, "another")
        assertEquals(Decision.Folded(1), NotificationCaps.decide(true, "new", ten, now))
        assertEquals(Decision.Folded(1), NotificationCaps.decide(false, "new", ten, now))
    }

    @Test
    fun `the day is a rolling 24 hours`() {
        val ten = distinct(Kind.QUIET, 10, from = now - 23 * hour)
        assertEquals(Decision.Folded(1), NotificationCaps.decide(true, "new", ten, now))
        // The first of the ten is now 24 hours old and out of the window.
        assertEquals(Decision.Loud, NotificationCaps.decide(true, "new", ten, now + hour))
    }

    @Test
    fun `one warning per sender in six hours, loud or quiet`() {
        val told = listOf(loud(now - 5 * hour, "900"))
        assertEquals(Decision.Folded(1), NotificationCaps.decide(true, "900", told, now))
        assertEquals(Decision.Folded(1), NotificationCaps.decide(false, "900", told, now))
        assertEquals(Decision.Loud, NotificationCaps.decide(true, "900", told, now + hour + 1))
        assertEquals(Decision.Folded(1), NotificationCaps.decide(true, "900", listOf(quiet(now - hour, "900")), now))
        // Another sender is not held back by it.
        assertEquals(Decision.Loud, NotificationCaps.decide(true, "Sber", told, now))
    }

    @Test
    fun `a folded warning does not count as having told the person about that sender`() {
        val onlyFolded = listOf(folded(now - hour, "900"))
        assertEquals(Decision.Loud, NotificationCaps.decide(true, "900", onlyFolded, now))
    }

    @Test
    fun `messages with no sender are never held back by the sender rule`() {
        val told = listOf(loud(now - hour, null), quiet(now - hour, null))
        assertEquals(Decision.Loud, NotificationCaps.decide(true, null, told, now))
    }

    @Test
    fun `the folded count grows with every message past the limits, over 24 hours`() {
        val full = distinct(Kind.LOUD, 3, from = now - 10 * 60_000L)
        assertEquals(Decision.Folded(1), NotificationCaps.decide(true, "a", full, now))
        val plusTwo = full + folded(now - 5 * hour, "x") + folded(now - 25 * hour, "old")
        // The 25-hour-old one is past the window and not counted.
        assertEquals(Decision.Folded(2), NotificationCaps.decide(true, "b", plusTwo, now))
    }

    @Test
    fun `prune keeps the last 24 hours and a future-stamped entry`() {
        val kept = listOf(loud(now - 23 * hour), loud(now + hour))
        val gone = listOf(loud(now - 24 * hour), loud(now - 48 * hour))
        assertEquals(kept, NotificationCaps.prune(kept + gone, now))
        // A future-stamped warning (the clock was set back) still counts as recent: the cautious reading.
        assertEquals(Decision.Folded(1), NotificationCaps.decide(true, "900", listOf(loud(now + hour, "900")), now))
    }

    @Test
    fun `the wire names are pinned, an unknown one reads as nothing`() {
        assertEquals(listOf("loud", "quiet", "folded"), Kind.values().map { it.wire })
        assertEquals(Kind.QUIET, Kind.ofWire("quiet"))
        assertEquals(null, Kind.ofWire("shout"))
        assertEquals(null, Kind.ofWire(null))
    }

    @Test
    fun `the limits are the plan's`() {
        assertEquals(3, NotificationCaps.MAX_LOUD_PER_HOUR)
        assertEquals(10, NotificationCaps.MAX_PER_DAY)
        assertEquals(6 * hour, NotificationCaps.PER_SENDER_WINDOW_MS)
    }
}
