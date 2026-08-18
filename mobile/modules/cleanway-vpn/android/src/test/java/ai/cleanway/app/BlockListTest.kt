package ai.cleanway.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The on-device blocklist: the thing that turns "first visit passes" into
 * "first visit blocked" for every listed name. Parsing is strict (a bad file
 * is rejected whole), matching is a suffix walk, and a popular-domain veto
 * inside match() means even a bad publish cannot darken paypal.com.
 */
class BlockListTest {

    private val veto = setOf("paypal.com", "google.com", "github.com")

    private fun text(vararg names: String, generated: Long = 1_755_530_000L, status: String = "ok"): String =
        "# cleanway-dns-blocklist v1 generated=$generated count=${names.size} status=$status\n" +
            names.joinToString("\n") + (if (names.isEmpty()) "" else "\n")

    @Test
    fun `parses header and names, exposes version and count`() {
        val bl = BlockList.parse(text("a.example", "b.example", "list-canary.cleanway.ai"), popularVeto = veto, nowMs = 0L)
        assertNotNull(bl)
        assertEquals(1_755_530_000L, bl!!.version)
        assertEquals(3, bl.count)
        assertFalse(bl.revoked)
    }

    @Test
    fun `match blocks the name and its subdomains, never the parent`() {
        val bl = BlockList.parse(text("scotiabano.com", "gwcu.us.org"), popularVeto = veto, nowMs = 0L)!!
        assertEquals("scotiabano.com", bl.match("scotiabano.com"))
        assertEquals("scotiabano.com", bl.match("login.scotiabano.com"))
        assertEquals("scotiabano.com", bl.match("a.b.c.scotiabano.com"))
        assertEquals("gwcu.us.org", bl.match("www.gwcu.us.org"))
        assertNull(bl.match("us.org"))
        assertNull(bl.match("other.us.org"))
        assertNull(bl.match("com"))
        assertNull(bl.match("notscotiabano.com"))
    }

    @Test
    fun `popular veto - a listed popular name never blocks`() {
        // A bad publish that somehow contains paypal.com must be inert on the phone.
        val bl = BlockList.parse(text("paypal.com", "evil.example"), popularVeto = veto, nowMs = 0L)!!
        assertNull(bl.match("paypal.com"))
        assertNull(bl.match("www.paypal.com"))
        assertEquals("evil.example", bl.match("evil.example"))
    }

    @Test
    fun `popular veto applies to the registrable, so tenant sites on shared platforms still block`() {
        // github.io is deliberately NOT in the veto asset (it is a public suffix);
        // github.com is. evil.github.io must block, anything.github.com never.
        val bl = BlockList.parse(text("evil.github.io", "bad.github.com"), popularVeto = veto, nowMs = 0L)!!
        assertEquals("evil.github.io", bl.match("evil.github.io"))
        assertNull(bl.match("bad.github.com"))
    }

    @Test
    fun `rejects the whole file on a bad header, a bad line, or a bare TLD`() {
        assertNull(BlockList.parse("hello\nfoo.example\n", popularVeto = veto, nowMs = 0L))
        assertNull(BlockList.parse(text("ok.example", "not a domain!"), popularVeto = veto, nowMs = 0L))
        assertNull(BlockList.parse(text("ok.example", "com"), popularVeto = veto, nowMs = 0L))
        assertNull(BlockList.parse(text("ok.example", "-bad.example"), popularVeto = veto, nowMs = 0L))
        // count in header must match
        assertNull(BlockList.parse("# cleanway-dns-blocklist v1 generated=1 count=5 status=ok\na.example\n", popularVeto = veto, nowMs = 0L))
    }

    @Test
    fun `rejects oversized lists`() {
        val many = (0 until BlockList.MAX_ENTRIES + 1).map { "d$it.example" }.toTypedArray()
        assertNull(BlockList.parse(text(*many), popularVeto = veto, nowMs = 0L))
    }

    @Test
    fun `revoked list parses to an empty, revoked list`() {
        val bl = BlockList.parse("# cleanway-dns-blocklist v1 generated=7 count=0 status=revoked\n", popularVeto = veto, nowMs = 0L)
        assertNotNull(bl)
        assertTrue(bl!!.revoked)
        assertEquals(0, bl.count)
        assertNull(bl.match("anything.example"))
    }

    @Test
    fun `staleness uses the larger of wall-clock and monotonic age`() {
        val bl = BlockList.parse(text("a.example"), popularVeto = veto, nowMs = 1_000L, elapsedMs = 5_000L)!!
        assertFalse(bl.isStale(nowMs = 1_000L + 60_000L, elapsedMs = 5_000L + 60_000L))
        // Wall clock rolled back to zero, but 25h of uptime have passed → stale.
        assertTrue(bl.isStale(nowMs = 0L, elapsedMs = 5_000L + BlockList.STALE_AFTER_MS + 1))
        // Wall clock says 25h passed even though monotonic says a minute → stale (clock jumped forward, be safe).
        assertTrue(bl.isStale(nowMs = 1_000L + BlockList.STALE_AFTER_MS + 1, elapsedMs = 5_000L + 60_000L))
    }

    @Test
    fun `punycode and case are normalised`() {
        val bl = BlockList.parse(text("xn--80ak6aa92e.com", "MiXeD.Example"), popularVeto = veto, nowMs = 0L)!!
        assertEquals("xn--80ak6aa92e.com", bl.match("XN--80AK6AA92E.COM"))
        assertEquals("mixed.example", bl.match("www.mixed.example"))
    }

    @Test
    fun `list canary is recognised only when the loaded list contains it`() {
        val with = BlockList.parse(text("list-canary.cleanway.ai", "a.example"), popularVeto = veto, nowMs = 0L)!!
        val without = BlockList.parse(text("a.example"), popularVeto = veto, nowMs = 0L)!!
        assertTrue(with.hasListCanary())
        assertFalse(without.hasListCanary())
        // The canary label itself resolves through the same suffix walk.
        assertEquals("list-canary.cleanway.ai", with.match("r4nd0m.list-canary.cleanway.ai"))
    }
}
