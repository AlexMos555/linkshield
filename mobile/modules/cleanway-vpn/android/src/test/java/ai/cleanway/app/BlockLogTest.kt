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
    fun `lifetime counters survive ring-buffer truncation`() {
        // The ring buffer holds only the last DEFAULT_CAP entries, but the
        // "Blocked N sites" number must count every block ever — otherwise a
        // heavy user's total silently stops growing at 200.
        var counts = BlockLog.bumpCounts(null, BlockLog.KIND_BLOCKED)
        for (i in 0 until 500) counts = BlockLog.bumpCounts(counts, BlockLog.KIND_BLOCKED)
        counts = BlockLog.bumpCounts(counts, BlockLog.KIND_WARNED)
        counts = BlockLog.bumpCounts(counts, BlockLog.KIND_ALLOWED)
        val parsed = BlockLog.parseCounts(counts)
        assertEquals(501, parsed[BlockLog.KIND_BLOCKED])
        assertEquals(1, parsed[BlockLog.KIND_WARNED])
        assertEquals(1, parsed[BlockLog.KIND_ALLOWED])
    }

    @Test
    fun `counts are never negative and ignore garbage`() {
        assertEquals(0, BlockLog.parseCounts("not json")[BlockLog.KIND_BLOCKED])
        assertEquals(0, BlockLog.parseCounts(null)[BlockLog.KIND_WARNED])
        val one = BlockLog.bumpCounts("{garbage", BlockLog.KIND_BLOCKED)
        assertEquals(1, BlockLog.parseCounts(one)[BlockLog.KIND_BLOCKED])
    }

    @Test
    fun `garbage json is treated as empty, never thrown`() {
        assertTrue(BlockLog.parse("not json").isEmpty())
        val json = BlockLog.appendJson("{broken", "x.example", ts = 1L, kind = BlockLog.KIND_BLOCKED, cap = 5)
        assertEquals(1, BlockLog.parse(json).size)
    }

    @Test
    fun `source round-trips, and entries written before it read back with their only possible source`() {
        val json = BlockLog.appendJson("[]", "evil.example", ts = 1L, kind = BlockLog.KIND_BLOCKED, source = BlockLog.SOURCE_LINK)
        assertEquals(BlockLog.SOURCE_LINK, BlockLog.parse(json).single().source)

        // The shape every installed phone has on disk today: no "s" field.
        // Until now only the DNS loop recorded blocks and only the link guard's
        // background check recorded warnings.
        val legacy = """[{"d":"a.example","t":3,"k":"blocked"},{"d":"b.example","t":2,"k":"warned"},""" +
            """{"d":"c.example","t":1,"k":"allowed"},{"d":"d.example","t":0}]"""
        val parsed = BlockLog.parse(legacy)
        assertEquals(listOf("a.example", "b.example", "c.example", "d.example"), parsed.map { it.domain })
        assertEquals(listOf(BlockLog.SOURCE_DNS, BlockLog.SOURCE_LINK, null, BlockLog.SOURCE_DNS), parsed.map { it.source })
        assertEquals(BlockLog.KIND_BLOCKED, parsed.last().kind)
    }

    @Test
    fun `an unknown source is dropped rather than guessed`() {
        val e = BlockLog.parse("""[{"d":"a.example","t":1,"k":"blocked","s":"carrier-pigeon"}]""").single()
        assertNull(e.source)
    }

    @Test
    fun `allowed entries carry no source`() {
        val json = BlockLog.appendJson("[]", "mybank.example", ts = 5L, kind = BlockLog.KIND_ALLOWED)
        assertFalse(json.contains("\"s\""))
        assertNull(BlockLog.parse(json).single().source)
    }

    private fun entry(domain: String, ts: Long, kind: String = BlockLog.KIND_BLOCKED, source: String? = BlockLog.SOURCE_DNS) =
        BlockLog.Entry(domain, ts, kind, source)

    @Test
    fun `one visit is one event - A, AAAA and retries do not add rows or counts`() {
        var json: String? = null
        var newEvents = 0
        // A page visit: A + AAAA + HTTPS lookups and a retry, within seconds.
        for (ts in listOf(1_000L, 1_010L, 1_020L, 4_000L)) {
            val (next, isNew) = BlockLog.recordJson(json, entry("evil.example", ts))
            json = next
            if (isNew) newEvents++
        }
        assertEquals(1, newEvents)
        val only = BlockLog.parse(json).single()
        assertEquals("evil.example", only.domain)
        // The entry keeps the LATEST time: "blocked just now", not "a while ago".
        assertEquals(4_000L, only.ts)
    }

    @Test
    fun `a repeat moves to the front and a later visit is a new event`() {
        val w = BlockLog.COALESCE_WINDOW_MS
        var json = BlockLog.recordJson(null, entry("evil.example", 0L)).first
        json = BlockLog.recordJson(json, entry("other.example", 1_000L)).first
        val (repeated, repeatIsNew) = BlockLog.recordJson(json, entry("evil.example", 2_000L))
        assertFalse(repeatIsNew)
        assertEquals(listOf("evil.example", "other.example"), BlockLog.parse(repeated).map { it.domain })

        val (later, laterIsNew) = BlockLog.recordJson(repeated, entry("evil.example", 2_000L + w))
        assertTrue(laterIsNew)
        assertEquals(listOf("evil.example", "evil.example", "other.example"), BlockLog.parse(later).map { it.domain })
    }

    @Test
    fun `different kind or shield is a different event`() {
        var json = BlockLog.recordJson(null, entry("evil.example", 0L)).first
        val (viaLink, linkIsNew) = BlockLog.recordJson(json, entry("evil.example", 10L, source = BlockLog.SOURCE_LINK))
        assertTrue(linkIsNew)
        json = viaLink
        val (allowed, allowIsNew) = BlockLog.recordJson(json, entry("evil.example", 20L, BlockLog.KIND_ALLOWED, null))
        assertTrue(allowIsNew)
        assertEquals(3, BlockLog.parse(allowed).size)
    }

    @Test
    fun `an app polling a blocked host all day stays one row and does not push real events out`() {
        val w = BlockLog.COALESCE_WINDOW_MS
        var json: String? = null
        var newEvents = 0
        // One real block first, then a host polled every half window for a day.
        json = BlockLog.recordJson(json, entry("phish.example", 0L)).first
        var ts = 1_000L
        while (ts < 24L * 60 * 60 * 1000) {
            val (next, isNew) = BlockLog.recordJson(json, entry("tracker.example", ts), cap = 5)
            json = next
            if (isNew) newEvents++
            ts += w / 2
        }
        assertEquals(1, newEvents)
        assertEquals(listOf("tracker.example", "phish.example"), BlockLog.parse(json).map { it.domain })
    }

    @Test
    fun `a clock stepped backwards does not mint a new event`() {
        val json = BlockLog.recordJson(null, entry("evil.example", 100_000L)).first
        val (next, isNew) = BlockLog.recordJson(json, entry("evil.example", 99_000L))
        assertFalse(isNew)
        assertEquals(1, BlockLog.parse(next).size)
    }

    @Test
    fun `record keeps the cap`() {
        var json: String? = null
        for (i in 1..7) json = BlockLog.recordJson(json, entry("d$i.example", i * 1000L), cap = 3).first
        assertEquals(listOf("d7.example", "d6.example", "d5.example"), BlockLog.parse(json).map { it.domain })
    }

    /** How every installed phone recorded until now: one entry per DNS query, no source. */
    private fun legacyRing(vararg entries: Pair<String, Long>): String =
        entries.joinToString(",", "[", "]") { (d, t) -> """{"d":"$d","t":$t,"k":"blocked"}""" }

    @Test
    fun `a log written per query is collapsed to events and recounted, once`() {
        // Two visits to one site (A + AAAA + a retry, then again an hour
        // later) and one visit to another: 7 raw entries that read "Blocked 7".
        val hour = 60L * 60 * 1000
        val ring = legacyRing(
            "evil.example" to hour + 20, "evil.example" to hour + 10, "evil.example" to hour,
            "other.example" to 5_000L,
            "evil.example" to 2_000L, "evil.example" to 1_000L, "evil.example" to 0L,
        )
        val (entries, counts) = BlockLog.migrateJson(ring, """{"blocked":7,"warned":0,"allowed":0}""")
        val events = BlockLog.parse(entries)
        assertEquals(listOf("evil.example", "other.example", "evil.example"), events.map { it.domain })
        assertEquals(listOf(hour + 20, 5_000L, 2_000L), events.map { it.ts })
        assertEquals(listOf(BlockLog.SOURCE_DNS, BlockLog.SOURCE_DNS, BlockLog.SOURCE_DNS), events.map { it.source })
        assertEquals(3, BlockLog.parseCounts(counts)[BlockLog.KIND_BLOCKED])
    }

    @Test
    fun `a full legacy ring keeps its counts - what fell off cannot be recounted`() {
        val ring = legacyRing(*Array(5) { "evil.example" to (4 - it) * 1_000L })
        val (entries, counts) = BlockLog.migrateJson(ring, """{"blocked":900,"warned":2,"allowed":1}""", cap = 5)
        assertEquals(1, BlockLog.parse(entries).size)
        assertEquals(900, BlockLog.parseCounts(counts)[BlockLog.KIND_BLOCKED])
        assertEquals(2, BlockLog.parseCounts(counts)[BlockLog.KIND_WARNED])
    }

    @Test
    fun `an empty log migrates to an empty log with zero counts`() {
        val (entries, counts) = BlockLog.migrateJson(null, null)
        assertTrue(BlockLog.parse(entries).isEmpty())
        assertEquals(0, BlockLog.parseCounts(counts)[BlockLog.KIND_BLOCKED])
    }

    @Test
    fun `coalescing a list agrees with recording it event by event`() {
        val w = BlockLog.COALESCE_WINDOW_MS
        val times = listOf(0L, 1_000L, w / 2, w + w / 2 + 1, 3 * w, 3 * w + 5)
        var recorded: String? = null
        for (t in times) recorded = BlockLog.recordJson(recorded, entry("evil.example", t)).first
        val raw = times.reversed().map { entry("evil.example", it) }
        assertEquals(BlockLog.parse(recorded), BlockLog.coalesce(raw))
    }

    @Test
    fun `notify dedupe - same domain within window is suppressed, others pass`() {
        val w = BlockNotifier.PER_DOMAIN_WINDOW_MS
        val t = BlockNotifier.Throttle()
        assertTrue(t.shouldNotify("a.example", now = 0L))
        assertFalse(t.shouldNotify("a.example", now = w - 1L))
        assertTrue(t.shouldNotify("b.example", now = w - 1L))
        // The window restarted at w - 1 (the suppressed lookup), not at 0.
        assertFalse(t.shouldNotify("a.example", now = w + 1L))
        assertTrue(t.shouldNotify("a.example", now = 3 * w))
    }

    @Test
    fun `notify - an app polling a blocked host alerts a few times an hour, not every minute`() {
        val t = BlockNotifier.Throttle()
        val alerts = (0 until 60).count { t.shouldNotify("beacon.example", now = it * 60_000L) }
        assertEquals(BlockNotifier.MAX_PER_DOMAIN_PER_HOUR, alerts)
        // An hour after the first alert the budget frees up again.
        assertTrue(t.shouldNotify("beacon.example", now = 61 * 60_000L))
    }

    @Test
    fun `notify - one attempt's lookup burst and auto-reloads alert once, a new attempt alerts again`() {
        val t = BlockNotifier.Throttle()
        // A, AAAA, HTTPS record, then the browser's 1 s / 5 s / 30 s reloads.
        val burst = listOf(0L, 15L, 40L, 1_000L, 6_000L, 36_000L)
        assertEquals(1, burst.count { t.shouldNotify("scam.example", now = it) })
        // The person tries the site again a minute later: it must pop up again.
        assertTrue(t.shouldNotify("scam.example", now = 96_000L))
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

    /** v2 blob, the way the publisher renders it. */
    private fun v2ListOf(vararg names: String): BlockList {
        val hashes = names.map { BlockList.hashOf(it) }.distinct().sorted()
        val out = java.io.ByteArrayOutputStream()
        out.write("CWBL2\n".toByteArray())
        out.write("# cleanway-dns-blocklist v2 generated=1 count=${hashes.size} status=ok\n".toByteArray())
        for (h in hashes) for (b in BlockList.HASH_BYTES - 1 downTo 0) out.write(((h shr (8 * b)) and 0xFF).toInt())
        return BlockList.parse(out.toByteArray(), popularVeto = emptySet(), nowMs = 0L)!!
    }

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
        val list = v2ListOf("evil.example", "mybank.example")
        assertEquals(DnsDecision.BLOCK, DnsDecision.classify("mybank.example", list, emptySet()))
        assertEquals(DnsDecision.FORWARD, DnsDecision.classify("mybank.example", list, setOf("mybank.example")))
        assertEquals(DnsDecision.FORWARD, DnsDecision.classify("www.mybank.example", list, setOf("mybank.example")))
        // Allowing one site does not unblock the rest of the list.
        assertEquals(DnsDecision.BLOCK, DnsDecision.classify("evil.example", list, setOf("mybank.example")))
    }
}
