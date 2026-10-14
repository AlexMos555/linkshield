package ai.cleanway.app

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * LinkGuardActivity is exported and handles every http/https VIEW intent, so a
 * page or app that re-fires the same intent in a loop would make it open the
 * browser (or the warning screen) over and over. The throttle drops a repeat
 * of the same host inside a short window and caps launches per window overall.
 */
class LinkGuardThrottleTest {

    private fun throttle() =
        LinkGuardThrottle(sameHostWindowMs = 2_500, burstWindowMs = 10_000, burstMax = 6, maxHosts = 4)

    @Test
    fun `a single tap is admitted`() {
        assertTrue(throttle().admit("google.com", 1_000))
    }

    @Test
    fun `the same host again inside the window is dropped`() {
        val t = throttle()
        assertTrue(t.admit("google.com", 1_000))
        assertFalse(t.admit("google.com", 1_100))
        assertFalse(t.admit("google.com", 3_400))
        // 2.5 s of quiet since the last attempt: a deliberate new tap opens.
        assertTrue(t.admit("google.com", 6_000))
    }

    @Test
    fun `a sustained loop on one host stays suppressed`() {
        val t = throttle()
        assertTrue(t.admit("evil.tld", 0))
        // Re-fired every second for a minute: every repeat refreshes the window.
        for (s in 1..60) assertFalse(t.admit("evil.tld", s * 1_000L), "re-fire at ${s}s")
    }

    @Test
    fun `different hosts are independent`() {
        val t = throttle()
        assertTrue(t.admit("a.tld", 0))
        assertTrue(t.admit("b.tld", 100))
        assertFalse(t.admit("a.tld", 200))
    }

    @Test
    fun `launches across many hosts are capped per window`() {
        val t = throttle()
        for (i in 0 until 6) assertTrue(t.admit("h$i.tld", i * 100L), "host $i")
        assertFalse(t.admit("h6.tld", 700))
        // A rotating loop keeps the window full and stays capped...
        for (i in 7 until 40) assertFalse(t.admit("h$i.tld", 700L + i * 200L), "rotating host $i")
        // ...and once it has been quiet for a whole window, links open again.
        assertTrue(t.admit("fresh.tld", 700L + 39 * 200L + 10_000))
    }

    @Test
    fun `the per-host memory is bounded`() {
        val t = LinkGuardThrottle(sameHostWindowMs = 2_500, burstWindowMs = 1, burstMax = 1_000, maxHosts = 2)
        assertTrue(t.admit("a.tld", 0))
        assertTrue(t.admit("b.tld", 10))
        assertTrue(t.admit("c.tld", 20)) // evicts a.tld, the least recently seen
        assertTrue(t.admit("a.tld", 30)) // forgotten, so admitted
        assertTrue(t.trackedHosts() <= 2)
    }

    @Test
    fun `a clock that goes backwards never locks a host out`() {
        val t = throttle()
        assertTrue(t.admit("google.com", 50_000))
        assertTrue(t.admit("google.com", 1_000))
    }
}
