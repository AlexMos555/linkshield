package ai.cleanway.app

import ai.cleanway.app.CallGuard.Decision
import ai.cleanway.app.CallGuard.Event
import ai.cleanway.app.CallState.Phase
import ai.cleanway.app.CallState.Snapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * When the after-call notice goes out (CallGuard.decide) and what it names.
 * The rule that matters most: no event, no notice — an ordinary call must
 * never produce one, and one call produces at most one.
 */
class CallGuardTest {

    private val t0 = 1_727_600_000_000L
    private val minute = 60_000L

    private fun inCall(since: Long, endedBefore: Long = 0L) = Snapshot(Phase.IN_CALL, since, endedBefore)
    private fun ended(started: Long, ended: Long) = Snapshot(Phase.IDLE, started, ended)

    @Test
    fun `an ordinary call - nothing seen - is no notice`() {
        val call = ended(t0, t0 + 3 * minute)
        assertEquals(Decision.Nothing, CallGuard.decide(emptyList(), 0L, call, t0 + 4 * minute))
        // Events from long before the call do not count either.
        val old = listOf(Event(CallGuard.EVENT_SITE_BLOCKED, t0 - 2 * minute))
        assertEquals(Decision.Nothing, CallGuard.decide(old, 0L, call, t0 + 4 * minute))
    }

    @Test
    fun `a block during the call waits for the call to end`() {
        val events = listOf(Event(CallGuard.EVENT_SITE_BLOCKED, t0 + minute))
        assertEquals(Decision.AfterCall, CallGuard.decide(events, 0L, inCall(t0), t0 + 2 * minute))
        // A minute after the hang-up: the notice, naming the block.
        val call = ended(t0, t0 + 3 * minute)
        assertEquals(Decision.Alert(CallGuard.EVENT_SITE_BLOCKED), CallGuard.decide(events, 0L, call, t0 + 4 * minute))
    }

    @Test
    fun `a block within 30 minutes after the call is named at once`() {
        val call = ended(t0, t0 + 3 * minute)
        val events = listOf(Event(CallGuard.EVENT_SITE_BLOCKED, t0 + 20 * minute))
        assertEquals(Decision.Alert(CallGuard.EVENT_SITE_BLOCKED), CallGuard.decide(events, 0L, call, t0 + 20 * minute))
        // 31 minutes after: the call is not the story any more.
        val late = listOf(Event(CallGuard.EVENT_SITE_BLOCKED, t0 + 35 * minute))
        assertEquals(Decision.Nothing, CallGuard.decide(late, 0L, call, t0 + 35 * minute))
    }

    @Test
    fun `one notice per call, whatever else happens in its window`() {
        val call = ended(t0, t0 + 3 * minute)
        val first = Event(CallGuard.EVENT_SITE_BLOCKED, t0 + minute)
        val alertedAt = t0 + 4 * minute
        // The notice at t0+4min consumed the first event; a site an app keeps
        // polling produces a new event ten minutes later — no second notice.
        val again = listOf(first, Event(CallGuard.EVENT_SITE_BLOCKED, t0 + 14 * minute))
        assertEquals(Decision.Nothing, CallGuard.decide(again, alertedAt, call, t0 + 14 * minute))
        // Nor does a lighter event.
        val lighter = again + Event(CallGuard.EVENT_PROTECTION_OFF_ASKED, t0 + 15 * minute)
        assertEquals(Decision.Nothing, CallGuard.decide(lighter, alertedAt, call, t0 + 15 * minute))
    }

    @Test
    fun `a notice already sent covers its events, a new call gets its own`() {
        // Call 1 was noticed at t0+4min. Call 2 at t0+10..12min with a warning during it.
        val alertedAt = t0 + 4 * minute
        val events = listOf(
            Event(CallGuard.EVENT_SITE_BLOCKED, t0 + minute),
            Event(CallGuard.EVENT_SITE_WARNED, t0 + 11 * minute),
        )
        assertEquals(Decision.AfterCall, CallGuard.decide(events, alertedAt, inCall(t0 + 10 * minute, t0 + 3 * minute), t0 + 11 * minute))
        val call2 = ended(t0 + 10 * minute, t0 + 12 * minute)
        assertEquals(Decision.Alert(CallGuard.EVENT_SITE_WARNED), CallGuard.decide(events, alertedAt, call2, t0 + 13 * minute))
        // And after the second notice, the second call is quiet.
        assertEquals(Decision.Nothing, CallGuard.decide(events, t0 + 13 * minute, call2, t0 + 14 * minute))
    }

    @Test
    fun `the heaviest event of the call is the one named`() {
        val call = ended(t0, t0 + 3 * minute)
        val events = listOf(
            Event(CallGuard.EVENT_PROTECTION_OFF_ASKED, t0 + minute),
            Event(CallGuard.EVENT_MESSAGE_DANGEROUS, t0 + minute + 1),
            Event(CallGuard.EVENT_SITE_WARNED, t0 + minute + 2),
        )
        assertEquals(Decision.Alert(CallGuard.EVENT_SITE_WARNED), CallGuard.decide(events, 0L, call, t0 + 4 * minute))
        val withBlock = events + Event(CallGuard.EVENT_SITE_BLOCKED, t0 + 2 * minute)
        assertEquals(Decision.Alert(CallGuard.EVENT_SITE_BLOCKED), CallGuard.decide(withBlock, 0L, call, t0 + 4 * minute))
    }

    @Test
    fun `a pause request alone, during the call, is reason enough`() {
        val call = ended(t0, t0 + 3 * minute)
        val events = listOf(Event(CallGuard.EVENT_PROTECTION_OFF_ASKED, t0 + 2 * minute))
        assertEquals(Decision.Alert(CallGuard.EVENT_PROTECTION_OFF_ASKED), CallGuard.decide(events, 0L, call, t0 + 4 * minute))
    }

    @Test
    fun `no call ever - no notice, whatever was seen`() {
        val never = Snapshot(Phase.IDLE, 0L, 0L)
        val events = listOf(Event(CallGuard.EVENT_SITE_BLOCKED, t0))
        assertEquals(Decision.Nothing, CallGuard.decide(events, 0L, never, t0))
    }

    @Test
    fun `events survive the round trip newest first, capped, garbage dropped`() {
        var json: String? = null
        for (i in 1..5) json = CallGuard.appendJson(json, Event(CallGuard.EVENT_SITE_BLOCKED, t0 + i), cap = 3)
        assertEquals(listOf(t0 + 5, t0 + 4, t0 + 3), CallGuard.parseEvents(json).map { it.ts })
        assertEquals("unknown kinds are not stored", 3, CallGuard.parseEvents(CallGuard.appendJson(json, Event("exploded", t0 + 9), cap = 3)).size)
        assertTrue(CallGuard.parseEvents("not json").isEmpty())
        assertTrue(CallGuard.parseEvents("""[{"k":"exploded","t":1},{"t":2}]""").isEmpty())
    }

    @Test
    fun `every event kind has its reason line`() {
        val lines = CallGuard.EVENTS.map { CallGuard.reasonRes(it) }
        assertEquals("distinct resources", lines.size, lines.toSet().size)
    }
}
