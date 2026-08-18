package ai.cleanway.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
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

/**
 * The escape hatch for a wrongly blocked site. Our own rule says a false
 * positive is worse than a miss: without a way back, the only remedy is
 * turning the shield off entirely.
 */
class UserAllowTest {

    @Test
    fun `an allowed name covers itself and its subdomains`() {
        val allowed = setOf("mybank.example", "shop.co.uk")
        assertEquals("mybank.example", UserAllow.covers(allowed, "mybank.example"))
        assertEquals("mybank.example", UserAllow.covers(allowed, "login.mybank.example"))
        assertEquals("shop.co.uk", UserAllow.covers(allowed, "www.shop.co.uk"))
        assertNull(UserAllow.covers(allowed, "notmybank.example"))
        assertNull(UserAllow.covers(allowed, "example"))
        assertNull(UserAllow.covers(emptySet(), "mybank.example"))
    }

    @Test
    fun `names are normalised, junk is refused`() {
        assertEquals("mybank.example", UserAllow.normalize("  MyBank.Example.  "))
        assertEquals("xn--80ak6aa92e.com", UserAllow.normalize("XN--80AK6AA92E.COM"))
        assertNull(UserAllow.normalize("com"))
        assertNull(UserAllow.normalize(""))
        assertNull(UserAllow.normalize(null))
        assertNull(UserAllow.normalize("has space.com"))
        assertNull(UserAllow.normalize("-bad.example"))
        assertNull(UserAllow.normalize("a".repeat(300) + ".com"))
    }

    @Test
    fun `an allow decision outranks the blocklist, and only for the allowed name`() {
        val list = BlockList.parse(
            "# cleanway-dns-blocklist v1 generated=1 count=2 status=ok\nevil.example\nmybank.example\n",
            popularVeto = emptySet(), nowMs = 0L,
        )!!
        assertEquals(DnsDecision.BLOCK, DnsDecision.classify("mybank.example", list, emptySet()))
        assertEquals(DnsDecision.FORWARD, DnsDecision.classify("mybank.example", list, setOf("mybank.example")))
        assertEquals(DnsDecision.FORWARD, DnsDecision.classify("www.mybank.example", list, setOf("mybank.example")))
        // Allowing one site does not unblock the rest of the list.
        assertEquals(DnsDecision.BLOCK, DnsDecision.classify("evil.example", list, setOf("mybank.example")))
    }
}
