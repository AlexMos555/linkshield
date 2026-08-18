package ai.cleanway.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The block log is what lets the app say "Blocked 3 sites today" and list them
 * even though the service did the blocking while no JS was alive. It is a
 * newest-first ring buffer serialised to JSON in SharedPreferences; the pure
 * part is tested here.
 */
class BlockLogTest {

    @Test
    fun `append puts newest first and keeps the cap`() {
        var json = "[]"
        for (i in 1..5) json = BlockLog.appendJson(json, "d$i.example", ts = i * 1000L, kind = BlockLog.KIND_BLOCKED, cap = 3)
        val entries = BlockLog.parse(json)
        assertEquals(listOf("d5.example", "d4.example", "d3.example"), entries.map { it.domain })
    }

    @Test
    fun `entries keep kind and timestamp`() {
        val json = BlockLog.appendJson("[]", "evil.example", ts = 42L, kind = BlockLog.KIND_WARNED, cap = 10)
        val e = BlockLog.parse(json).single()
        assertEquals("evil.example", e.domain)
        assertEquals(42L, e.ts)
        assertEquals(BlockLog.KIND_WARNED, e.kind)
    }

    @Test
    fun `countSince counts only recent entries`() {
        var json = "[]"
        json = BlockLog.appendJson(json, "old.example", ts = 1_000L, kind = BlockLog.KIND_BLOCKED, cap = 10)
        json = BlockLog.appendJson(json, "new1.example", ts = 90_000L, kind = BlockLog.KIND_BLOCKED, cap = 10)
        json = BlockLog.appendJson(json, "new2.example", ts = 95_000L, kind = BlockLog.KIND_WARNED, cap = 10)
        assertEquals(2, BlockLog.countSince(json, sinceMs = 50_000L))
    }

    @Test
    fun `garbage json is treated as empty, never thrown`() {
        assertTrue(BlockLog.parse("not json").isEmpty())
        val json = BlockLog.appendJson("{broken", "x.example", ts = 1L, kind = BlockLog.KIND_BLOCKED, cap = 5)
        assertEquals(1, BlockLog.parse(json).size)
    }

    @Test
    fun `notify dedupe - same domain within window is suppressed, others pass`() {
        val t = BlockNotifier.Throttle()
        assertTrue(t.shouldNotify("a.example", now = 0L))
        assertFalse(t.shouldNotify("a.example", now = 60_000L))
        assertTrue(t.shouldNotify("b.example", now = 61_000L))
        assertTrue(t.shouldNotify("a.example", now = BlockNotifier.PER_DOMAIN_WINDOW_MS + 1L))
    }

    @Test
    fun `notify storm guard - at most N notifications per minute`() {
        val t = BlockNotifier.Throttle()
        var shown = 0
        for (i in 0 until 20) if (t.shouldNotify("d$i.example", now = i * 100L)) shown++
        assertEquals(BlockNotifier.MAX_PER_MINUTE, shown)
    }
}
