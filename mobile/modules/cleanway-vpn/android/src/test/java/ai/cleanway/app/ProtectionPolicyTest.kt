package ai.cleanway.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The native side of the device pass (billing plan A.10): the offline rule
 * the service applies on its own, the list cadence per mode, and what the
 * DNS loop does in each mode.
 *
 * The rule's cases are the server's (tests/billing/test_entitlement.py) and
 * the app's (scripts/test-entitlement.mjs) verbatim: three implementations,
 * one table, so a phone that never opens the app downgrades at the same
 * moment the server would — and not a day earlier because its clock is wrong.
 */
class ProtectionPolicyTest {

    private val now = 1_800_000_000L
    private val day = 86_400L

    private fun pass(
        mode: ProtectionMode = ProtectionMode.FULL,
        policy: ProtectionMode = ProtectionMode.BASIC,
        until: Long? = now + 20 * day,
        grace: Long? = now + 27 * day,
        iat: Long = now,
        src: String = "subscription",
    ) = StoredPass(mode, policy, until, grace, iat, src)

    @Test
    fun `no pass means full - the shield as it was before billing`() {
        assertEquals(ProtectionMode.FULL, ProtectionPolicy.effectiveMode(null, now))
        assertNull(ProtectionPolicy.nextChangeSec(null, now))
    }

    @Test
    fun `full until, full through grace, then the lapse policy`() {
        val p = pass()
        assertEquals(ProtectionMode.FULL, ProtectionPolicy.effectiveMode(p, now + 19 * day))
        assertEquals(ProtectionMode.FULL, ProtectionPolicy.effectiveMode(p, now + 26 * day))
        assertEquals(ProtectionMode.BASIC, ProtectionPolicy.effectiveMode(p, now + 27 * day))
        assertEquals(ProtectionMode.OFF, ProtectionPolicy.effectiveMode(pass(policy = ProtectionMode.OFF), now + 27 * day))
    }

    @Test
    fun `a clock turned back cannot extend the pass`() {
        val p = pass(until = now + day, grace = null)
        assertEquals(ProtectionMode.FULL, ProtectionPolicy.effectiveMode(p, now - 365 * day))
        assertEquals(ProtectionMode.BASIC, ProtectionPolicy.effectiveMode(p, now + day))
    }

    @Test
    fun `a trial has no grace`() {
        val p = pass(until = now + 14 * day, grace = null, src = "trial")
        assertEquals(ProtectionMode.FULL, ProtectionPolicy.effectiveMode(p, now + 13 * day))
        assertEquals(ProtectionMode.BASIC, ProtectionPolicy.effectiveMode(p, now + 14 * day))
    }

    @Test
    fun `an open-ended pass keeps its mode`() {
        assertEquals(ProtectionMode.FULL, ProtectionPolicy.effectiveMode(pass(until = null, grace = null, src = "legacy"), now + 3650 * day))
        assertEquals(ProtectionMode.BASIC, ProtectionPolicy.effectiveMode(pass(mode = ProtectionMode.BASIC, until = null, grace = null, src = "none"), now + 30 * day))
    }

    @Test
    fun `the mode next changes at the end of grace, else at until, never for an open-ended pass`() {
        assertEquals(now + 27 * day, ProtectionPolicy.nextChangeSec(pass(), now + 1))
        assertEquals(now + 27 * day, ProtectionPolicy.nextChangeSec(pass(), now + 21 * day))
        assertNull(ProtectionPolicy.nextChangeSec(pass(), now + 28 * day))
        assertEquals(now + 20 * day, ProtectionPolicy.nextChangeSec(pass(grace = null), now))
        assertNull(ProtectionPolicy.nextChangeSec(pass(until = null, grace = null), now))
        assertEquals(now + 27 * day, ProtectionPolicy.nextChangeSec(pass(), now - 100 * day))
    }

    @Test
    fun `basic refreshes the list weekly and blocks, off blocks nothing, full is unchanged`() {
        assertEquals(SyncPolicy.REFRESH_MS, ProtectionPolicy.refreshMs(ProtectionMode.FULL))
        assertEquals(7L * 24 * 60 * 60 * 1000, ProtectionPolicy.refreshMs(ProtectionMode.BASIC))
        assertEquals(ProtectionPolicy.BASIC_REFRESH_MS, ProtectionPolicy.refreshMs(ProtectionMode.OFF))
        assertEquals(BlockList.STALE_AFTER_MS, ProtectionPolicy.staleAfterMs(ProtectionMode.FULL))
        assertEquals(8L * 24 * 60 * 60 * 1000, ProtectionPolicy.staleAfterMs(ProtectionMode.BASIC))
        assertTrue(ProtectionPolicy.blocks(ProtectionMode.FULL))
        assertTrue(ProtectionPolicy.blocks(ProtectionMode.BASIC))
        assertFalse(ProtectionPolicy.blocks(ProtectionMode.OFF))
    }

    @Test
    fun `the weekly cadence keeps its jitter and its failure backoff`() {
        val weekly = ProtectionPolicy.BASIC_REFRESH_MS
        val delay = SyncPolicy.nextDelayMs(0, 12_345L, weekly)
        assertTrue("$delay", delay >= weekly * 9 / 10 && delay <= weekly * 11 / 10)
        assertEquals(5L * 60_000, SyncPolicy.nextDelayMs(1, 0L, weekly))
        assertEquals(15L * 60_000, SyncPolicy.nextDelayMs(2, 0L, weekly))
        // On start, a list younger than half the cadence needs no fetch.
        assertFalse(SyncPolicy.shouldFetchOnStart(3 * 24 * 60 * 60 * 1000L, weekly))
        assertTrue(SyncPolicy.shouldFetchOnStart(4 * 24 * 60 * 60 * 1000L, weekly))
        assertTrue(SyncPolicy.shouldFetchOnStart(4 * 60 * 60 * 1000L))
    }

    @Test
    fun `a week-old list is stale for full, fresh enough for basic`() {
        val loaded = 1_727_000_000_000L
        // The list's age also counts from its publisher epoch (BlockList.ageMs), so publish it at load time.
        val list = BlockList.parse(BlockList.render(longArrayOf(BlockList.hashOf("evil.example")), loaded / 1000), emptySet(), nowMs = loaded)!!
        val weekLater = loaded + 7L * 24 * 60 * 60 * 1000
        assertTrue(list.isStale(weekLater, 0L))
        assertFalse(list.isStale(weekLater, 0L, ProtectionPolicy.staleAfterMs(ProtectionMode.BASIC)))
        assertTrue(list.isStale(weekLater + 2L * 24 * 60 * 60 * 1000, 0L, ProtectionPolicy.staleAfterMs(ProtectionMode.BASIC)))
    }

    @Test
    fun `off forwards listed names like a pause, and the tunnel canary still answers`() {
        val hashes = longArrayOf(BlockList.hashOf("evil.example"))
        val list = BlockList.parse(BlockList.render(hashes, 1L), emptySet(), nowMs = 0L)!!
        val off = !ProtectionPolicy.blocks(ProtectionMode.OFF)
        assertEquals(DnsDecision.FORWARD, DnsDecision.classify("evil.example", list, paused = off))
        assertEquals(DnsDecision.CANARY, DnsDecision.classify(CleanwayVpnService.CANARY_DOMAIN, list, paused = off))
        assertEquals(DnsDecision.BLOCK, DnsDecision.classify("evil.example", list, paused = !ProtectionPolicy.blocks(ProtectionMode.BASIC)))
    }

    @Test
    fun `the pass the app hands over round-trips, and garbage reads as no pass`() {
        val p = pass(src = "trial")
        assertEquals(p, ProtectionPolicy.parse(ProtectionPolicy.format(p)))
        val open = pass(until = null, grace = null, src = "legacy")
        assertEquals(open, ProtectionPolicy.parse(ProtectionPolicy.format(open)))
        assertEquals(
            pass(mode = ProtectionMode.BASIC, policy = ProtectionMode.OFF, until = 5L, grace = null, iat = 1L, src = "none"),
            ProtectionPolicy.parse("""{"mode":"basic","lapse_policy":"off","until":5,"grace_until":null,"iat":1,"src":"none","dev":"x","exp":9}"""),
        )
        for (bad in listOf(null, "", "   ", "not json", "[1]", """{"mode":"turbo","lapse_policy":"basic","iat":1}""",
            """{"mode":"full","lapse_policy":"full","iat":1}""", """{"mode":"full","lapse_policy":"basic"}""")) {
            assertNull("for $bad", ProtectionPolicy.parse(bad))
        }
    }

    @Test
    fun `the trial fingerprint is a labelled sha-256, never the id itself`() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", TrialFingerprint.digest("abc"))
        assertEquals(64, TrialFingerprint.digest("cleanway-trial:9774d56d682e549c").length)
        assertFalse(TrialFingerprint.digest("cleanway-trial:9774d56d682e549c").contains("9774d56d682e549c"))
    }

    @Test
    fun `the wire words`() {
        assertEquals(ProtectionMode.BASIC, ProtectionMode.parse("basic"))
        assertNull(ProtectionMode.parse("Basic"))
        assertNull(ProtectionMode.parse(null))
        assertEquals(listOf("full", "basic", "off"), ProtectionMode.values().map { it.wire })
    }
}
