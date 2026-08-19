package ai.cleanway.app

import java.io.ByteArrayOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The on-device blocklist: what turns "first visit passes" into "first visit
 * blocked". Parsing is strict (a bad file is rejected whole), matching is a
 * suffix walk over sorted 48-bit hashes, and a popular-domain veto sits on
 * top so even a bad publish cannot darken a top site.
 */
class BlockListTest {

    private val veto = setOf("paypal.com", "google.com", "github.com")

    /** Build a v2 blob the way the publisher does. */
    private fun blob(
        vararg names: String,
        generated: Long = 1_755_530_000L,
        revoked: Boolean = false,
        countOverride: Int? = null,
        sorted: Boolean = true,
    ): ByteArray {
        // Descending when `sorted` is false: "insertion order" would be sorted
        // by luck for some inputs and the test would flake.
        val hashes = names.map { BlockList.hashOf(it) }.distinct()
            .let { if (sorted) it.sorted() else it.sortedDescending() }
        val count = countOverride ?: hashes.size
        val out = ByteArrayOutputStream()
        out.write("CWBL2\n".toByteArray())
        val status = if (revoked) "revoked" else "ok"
        out.write("# cleanway-dns-blocklist v2 generated=$generated count=$count status=$status\n".toByteArray())
        if (!revoked) {
            for (h in hashes) for (b in BlockList.HASH_BYTES - 1 downTo 0) {
                out.write(((h shr (8 * b)) and 0xFF).toInt())
            }
        }
        return out.toByteArray()
    }

    // ── the cross-language contract ───────────────────────────────────

    @Test
    fun `hashOf matches the publisher's name_hash byte for byte`() {
        // Computed by api/services/blocklist_artifact.py::name_hash — if these
        // ever disagree the phone silently blocks nothing (or the wrong things).
        assertEquals(0xa379a6f6eeafL, BlockList.hashOf("example.com"))
        assertEquals(0x9c180de0cd69L, BlockList.hashOf("evil.example"))
        assertEquals(0x4ade574af9acL, BlockList.hashOf("list-canary.cleanway.ai"))
        assertEquals(0x2d2ae3e541d9L, BlockList.hashOf("gwcu.us.org"))
        assertEquals(0xdc7b4e6ffcc6L, BlockList.hashOf("xn--80ak6aa92e.com"))
        // Case and a trailing dot are normalised before hashing.
        assertEquals(BlockList.hashOf("example.com"), BlockList.hashOf("EXAMPLE.COM."))
    }

    // ── parsing ───────────────────────────────────────────────────────

    @Test
    fun `parses header and body, exposes version and count`() {
        val bl = BlockList.parse(blob("a.example", "b.example", "list-canary.cleanway.ai"), veto, nowMs = 0L)
        assertNotNull(bl)
        assertEquals(1_755_530_000L, bl!!.version)
        assertEquals(3, bl.count)
        assertFalse(bl.revoked)
        assertTrue(bl.hasListCanary())
    }

    @Test
    fun `rejects the whole file on bad magic, bad header, wrong count, truncation or bad order`() {
        val good = blob("a.example", "b.example")
        assertNull(BlockList.parse(good.copyOfRange(1, good.size), veto, 0L))          // magic
        assertNull(BlockList.parse("CWBL2\nhello\n".toByteArray(), veto, 0L))          // header
        assertNull(BlockList.parse(blob("a.example", countOverride = 9), veto, 0L))    // count
        assertNull(BlockList.parse(good.copyOfRange(0, good.size - 1), veto, 0L))      // truncated
        assertNull(BlockList.parse(blob("z.example", "a.example", sorted = false), veto, 0L))
        assertNull(BlockList.parse(ByteArray(3), veto, 0L))
    }

    @Test
    fun `an empty body is rejected — a list that blocks nothing is not a list`() {
        assertNull(BlockList.parse(blob(), veto, 0L))
    }

    @Test
    fun `revoked parses to an empty, revoked list`() {
        val bl = BlockList.parse(blob(revoked = true, countOverride = 0, generated = 7L), veto, 0L)
        assertNotNull(bl)
        assertTrue(bl!!.revoked)
        assertEquals(0, bl.count)
        assertNull(bl.match("anything.example"))
        assertFalse(bl.hasListCanary())
    }

    // ── matching ──────────────────────────────────────────────────────

    @Test
    fun `match blocks the name and its subdomains, never the parent`() {
        val bl = BlockList.parse(blob("scotiabano.com", "gwcu.us.org"), veto, 0L)!!
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
        val bl = BlockList.parse(blob("paypal.com", "evil.example"), veto, 0L)!!
        assertNull(bl.match("paypal.com"))
        assertNull(bl.match("www.paypal.com"))
        assertEquals("evil.example", bl.match("evil.example"))
    }

    @Test
    fun `popular veto applies to the registrable, so tenant sites on shared platforms still block`() {
        // github.io is deliberately NOT in the veto asset (it is a public
        // suffix); github.com is. evil.github.io must block, *.github.com never.
        val bl = BlockList.parse(blob("evil.github.io", "bad.github.com"), veto, 0L)!!
        assertEquals("evil.github.io", bl.match("evil.github.io"))
        assertNull(bl.match("bad.github.com"))
    }

    @Test
    fun `case and trailing dots are normalised at lookup`() {
        val bl = BlockList.parse(blob("xn--80ak6aa92e.com", "mixed.example"), veto, 0L)!!
        assertEquals("xn--80ak6aa92e.com", bl.match("XN--80AK6AA92E.COM"))
        assertEquals("mixed.example", bl.match("WWW.Mixed.Example."))
    }

    @Test
    fun `a large list stays correct and answers fast`() {
        val names = (0 until 50_000).map { "d$it.example" }
        val bl = BlockList.parse(blob(*names.toTypedArray()), veto, 0L)!!
        assertEquals(50_000, bl.count)
        assertEquals("d49999.example", bl.match("login.d49999.example"))
        assertNull(bl.match("d50000.example"))
        val start = System.nanoTime()
        repeat(10_000) { bl.match("www.some-unlisted-$it.example") }
        val perLookupUs = (System.nanoTime() - start) / 10_000 / 1000.0
        // The DNS read loop carries every query on the device; a lookup must
        // cost microseconds, not milliseconds.
        assertTrue("lookup took ${perLookupUs}us", perLookupUs < 200)
    }

    // ── staleness ─────────────────────────────────────────────────────

    @Test
    fun `staleness uses the most pessimistic of wall-clock, monotonic and generation age`() {
        val generated = 1_755_530_000L                       // header epoch, seconds
        val fetchedAt = generated * 1000L + 60_000L          // fetched a minute after publish
        val bl = BlockList.parse(blob("a.example", generated = generated), veto,
                                 nowMs = fetchedAt, elapsedMs = 5_000L)!!
        assertFalse(bl.isStale(nowMs = fetchedAt + 60_000L, elapsedMs = 5_000L + 60_000L))
        // Wall clock rolled back, but the phone has been up past the window.
        assertTrue(bl.isStale(nowMs = 0L, elapsedMs = 5_000L + BlockList.STALE_AFTER_MS + 1))
        // Wall clock jumped forward: be safe, call it stale.
        assertTrue(bl.isStale(nowMs = fetchedAt + BlockList.STALE_AFTER_MS + 1, elapsedMs = 5_000L + 60_000L))
        // The DATA can be old even if this phone fetched it a second ago.
        assertTrue(bl.isStale(nowMs = generated * 1000L + BlockList.STALE_AFTER_MS + 1, elapsedMs = 5_100L))
    }

    @Test
    fun `age is never inflated by a reboot or a clock that runs backwards`() {
        // Seen on a device 2026-08-19: a list fetched 40 minutes earlier read
        // "updated 17h ago", because the monotonic base was back-dated into
        // the negative after a reboot.
        val generated = 1_755_530_000L
        val fetchedAt = generated * 1000L
        val bl = BlockList.parse(blob("a.example", generated = generated), veto,
                                 nowMs = fetchedAt, elapsedMs = 0L)!!
        val fortyMinutes = 40L * 60 * 1000
        // Phone rebooted: monotonic is small, wall clock says 40 minutes.
        assertEquals(fortyMinutes, bl.ageMs(nowMs = fetchedAt + fortyMinutes, elapsedMs = 1_000L))
        // Clock dragged backwards: age never goes negative, never looks newer.
        assertEquals(0L, bl.ageMs(nowMs = fetchedAt - 99_999L, elapsedMs = 0L))
    }
}

/**
 * The popular veto must protect a popular ORGANISATION's own names without
 * cancelling blocks on TENANT sites hosted on a popular platform. Found
 * 2026-08-19 by simulating the shipped veto over the live artifact: 783 of
 * the 1,548 tenant suffixes the publisher targets were silently un-blockable,
 * because e.g. `best10cdn.blob.core.windows.net` has registrable
 * `windows.net`, which is top-10k.
 */
class BlockListVetoTest {
    private val veto = setOf("windows.net", "amazonaws.com", "linodeusercontent.com", "paypal.com", "github.com")
    private val shared = setOf("blob.core.windows.net", "s3.us-east-1.amazonaws.com",
                               "ip.linodeusercontent.com", "github.io")

    private fun list(vararg names: String): BlockList {
        val hashes = names.map { BlockList.hashOf(it) }.distinct().sorted()
        val out = java.io.ByteArrayOutputStream()
        out.write("CWBL2\n".toByteArray())
        out.write("# cleanway-dns-blocklist v2 generated=1 count=${hashes.size} status=ok\n".toByteArray())
        for (h in hashes) for (b in BlockList.HASH_BYTES - 1 downTo 0) out.write(((h shr (8 * b)) and 0xFF).toInt())
        return BlockList.parse(out.toByteArray(), veto, nowMs = 0L, sharedSuffixes = shared)!!
    }

    @Test
    fun `tenant sites on popular platforms still block`() {
        val bl = list(
            "best10cdn.blob.core.windows.net",
            "2fbe3e68.s3.us-east-1.amazonaws.com",
            "172-104-49-49.ip.linodeusercontent.com",
            "evil.github.io",
        )
        assertEquals("best10cdn.blob.core.windows.net", bl.match("best10cdn.blob.core.windows.net"))
        assertEquals("2fbe3e68.s3.us-east-1.amazonaws.com", bl.match("2fbe3e68.s3.us-east-1.amazonaws.com"))
        assertEquals("172-104-49-49.ip.linodeusercontent.com", bl.match("172-104-49-49.ip.linodeusercontent.com"))
        assertEquals("evil.github.io", bl.match("evil.github.io"))
    }

    @Test
    fun `the platform's own names are still protected by the veto`() {
        val bl = list("windows.net", "paypal.com", "www.github.com", "s3.us-east-1.amazonaws.com")
        assertNull(bl.match("windows.net"))
        assertNull(bl.match("login.paypal.com"))
        assertNull(bl.match("www.github.com"))
        // The shared suffix itself is the platform's name, not a tenant's.
        assertNull(bl.match("s3.us-east-1.amazonaws.com"))
    }

    @Test
    fun `without the shared-suffix asset the veto stays conservative`() {
        val hashes = listOf(BlockList.hashOf("x.blob.core.windows.net")).sorted()
        val out = java.io.ByteArrayOutputStream()
        out.write("CWBL2\n".toByteArray())
        out.write("# cleanway-dns-blocklist v2 generated=1 count=1 status=ok\n".toByteArray())
        for (h in hashes) for (b in BlockList.HASH_BYTES - 1 downTo 0) out.write(((h shr (8 * b)) and 0xFF).toInt())
        val bl = BlockList.parse(out.toByteArray(), veto, nowMs = 0L)!!   // no sharedSuffixes
        // Missing asset must never turn into over-blocking: veto still wins.
        assertNull(bl.match("x.blob.core.windows.net"))
    }
}
