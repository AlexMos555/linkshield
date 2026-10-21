package ai.cleanway.app

import ai.cleanway.app.ListRefreshPolicy.Action
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The SMS check reads the blocklist with the network shield off — for many
 * people it is the only shield on. Before this job only the running shield
 * refreshed the list, so the SMS check would judge links against whatever
 * was synced the day the shield was last on.
 */
class ListRefreshPolicyTest {
    private val hour = 60L * 60 * 1000

    @Test
    fun `the job exists only while the SMS check is on in a build that has it`() {
        assertTrue(ListRefreshPolicy.shouldSchedule(supported = true, smsCheckOn = true))
        assertFalse(ListRefreshPolicy.shouldSchedule(supported = true, smsCheckOn = false))
        assertFalse(ListRefreshPolicy.shouldSchedule(supported = false, smsCheckOn = true))
    }

    @Test
    fun `a running shield owns the list, whatever its age`() {
        assertEquals(Action.SKIP_SHIELD_OWNS_LIST, ListRefreshPolicy.onRun(shieldRunning = true, storedAgeMs = null))
        assertEquals(Action.SKIP_SHIELD_OWNS_LIST, ListRefreshPolicy.onRun(shieldRunning = true, storedAgeMs = 100 * hour))
    }

    @Test
    fun `with the shield off, a missing or old list is fetched and a fresh one is left alone`() {
        assertEquals(Action.FETCH, ListRefreshPolicy.onRun(shieldRunning = false, storedAgeMs = null))
        assertEquals(Action.FETCH, ListRefreshPolicy.onRun(shieldRunning = false, storedAgeMs = 3 * hour))
        assertEquals(Action.FETCH, ListRefreshPolicy.onRun(shieldRunning = false, storedAgeMs = 30 * hour))
        assertEquals(Action.SKIP_FRESH, ListRefreshPolicy.onRun(shieldRunning = false, storedAgeMs = 2 * hour))
        assertEquals(Action.SKIP_FRESH, ListRefreshPolicy.onRun(shieldRunning = false, storedAgeMs = 0L))
    }

    @Test
    fun `a list stamped in the future is fetched, not trusted as fresh`() {
        assertEquals(Action.FETCH, ListRefreshPolicy.onRun(shieldRunning = false, storedAgeMs = -5 * hour))
        assertTrue(ListRefreshPolicy.fetchNowOnEnable(-1L))
    }

    @Test
    fun `turning the SMS check on fetches at once unless the list is fresh`() {
        assertTrue(ListRefreshPolicy.fetchNowOnEnable(null))
        assertTrue(ListRefreshPolicy.fetchNowOnEnable(3 * hour))
        assertFalse(ListRefreshPolicy.fetchNowOnEnable(1 * hour))
    }

    @Test
    fun `only a failed fetch asks for an early retry, a metered skip does not`() {
        assertTrue(ListRefreshPolicy.wantsRetry(ok = false, consecutiveFailures = 1))
        assertFalse(ListRefreshPolicy.wantsRetry(ok = false, consecutiveFailures = 0))
        assertFalse(ListRefreshPolicy.wantsRetry(ok = true, consecutiveFailures = 0))
    }

    @Test
    fun `only a delta that dropped the base is refetched in full in the same run`() {
        // A delta did not apply: the base is gone, fetch the whole list now.
        assertTrue(ListRefreshPolicy.refetchInFull(ok = false, hadBase = true, hasBaseNow = false))
        // A network failure keeps the base: leave it to the backoff.
        assertFalse(ListRefreshPolicy.refetchInFull(ok = false, hadBase = true, hasBaseNow = true))
        // No list to begin with: the first call already asked for it in full.
        assertFalse(ListRefreshPolicy.refetchInFull(ok = false, hadBase = false, hasBaseNow = false))
        assertFalse(ListRefreshPolicy.refetchInFull(ok = true, hadBase = true, hasBaseNow = true))
    }

    @Test
    fun `the job runs on the shield's cadence`() {
        assertEquals(SyncPolicy.REFRESH_MS, ListRefreshPolicy.PERIOD_MS)
        // JobScheduler's floors: a 15 min period, a 5 min flex, a 10 s backoff.
        assertTrue(ListRefreshPolicy.PERIOD_MS >= 15 * 60_000L)
        assertTrue(ListRefreshPolicy.FLEX_MS in 5 * 60_000L..ListRefreshPolicy.PERIOD_MS)
        assertTrue(ListRefreshPolicy.BACKOFF_MS >= 10_000L)
    }
}
