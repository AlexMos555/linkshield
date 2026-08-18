package ai.cleanway.app

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Pins the ORDER of the proxy loop's checks — the whole bug.
 *
 * `block-canary.cleanway.ai` is a subdomain of `cleanway.ai`, and `cleanway.ai`
 * is a system suffix, so `isSystemDomain(canary)` is TRUE. That is correct for
 * the allowlist's own purpose (never block our API) and exactly why the loop
 * must test the canary BEFORE it consults the allowlist. With the checks the
 * other way round every probe was classified "system → forward upstream", the
 * canary branch was unreachable, and the shield could not turn green on any
 * device. Found 2026-08-18 by tracing the tunnel: the probe's query arrived
 * and left again without touching the counter.
 */
class DnsDecisionTest {

    private val canary = CleanwayVpnService.CANARY_DOMAIN

    @Test
    fun `canary is a system domain by suffix — the trap this file exists for`() {
        assertTrue(DomainPolicy.isSystemDomain(canary))
        assertTrue(DomainPolicy.isSystemDomain("abc123.$canary"))
    }

    @Test
    fun `classifier tests the canary before the system allowlist`() {
        assertEquals(DnsDecision.CANARY, DnsDecision.classify(canary, emptySet(), emptySet()))
        assertEquals(DnsDecision.CANARY, DnsDecision.classify("r4nd0m.$canary", emptySet(), emptySet()))
        // A canary label in the blocklist is STILL the canary, not BLOCK: the
        // probe is silent by design and must never raise a block event.
        assertEquals(DnsDecision.CANARY, DnsDecision.classify(canary, setOf(canary), emptySet()))
    }

    @Test
    fun `system domains are forwarded even if someone put them in the blocklist`() {
        assertEquals(DnsDecision.FORWARD, DnsDecision.classify("api.cleanway.ai", setOf("api.cleanway.ai"), emptySet()))
        assertEquals(DnsDecision.FORWARD, DnsDecision.classify("mtalk.google.com", emptySet(), emptySet()))
    }

    @Test
    fun `blocked, safe and unknown fall through in that order`() {
        assertEquals(DnsDecision.BLOCK, DnsDecision.classify("evil.tld", setOf("evil.tld"), setOf("evil.tld")))
        assertEquals(DnsDecision.FORWARD, DnsDecision.classify("ok.tld", emptySet(), setOf("ok.tld")))
        assertEquals(DnsDecision.FORWARD_AND_CHECK, DnsDecision.classify("new.tld", emptySet(), emptySet()))
    }
}
