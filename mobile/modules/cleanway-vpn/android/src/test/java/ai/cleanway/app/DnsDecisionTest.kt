package ai.cleanway.app

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Pins the ORDER of the proxy loop's checks — the whole bug, twice over.
 *
 * `block-canary.cleanway.ai` and `list-canary.cleanway.ai` are subdomains of
 * `cleanway.ai`, which is a system suffix, so `isSystemDomain(canary)` is TRUE.
 * That is correct for the allowlist's own purpose (never block our API) and
 * exactly why the loop must test both canaries BEFORE it consults the
 * allowlist. With the checks the other way round every probe was classified
 * "system → forward upstream", the canary branch was unreachable, and the
 * shield could not turn green on any device (found 2026-08-18 by tracing the
 * tunnel).
 *
 * Since the local blocklist (2026-08-18) the decision is:
 *   CANARY → LIST_CANARY → system FORWARD → list BLOCK → FORWARD.
 * There is no FORWARD_AND_CHECK any more: no lookup is sent to Cleanway, and
 * a listed name is blocked on the very first query.
 */
class DnsDecisionTest {

    private val canary = CleanwayVpnService.CANARY_DOMAIN
    private val listCanary = BlockList.LIST_CANARY

    private fun list(vararg names: String): BlockList =
        BlockList.parse(
            "# cleanway-dns-blocklist v1 generated=1 count=${names.size} status=ok\n" + names.joinToString("\n") + "\n",
            popularVeto = emptySet(), nowMs = 0L,
        )!!

    @Test
    fun `both canaries are system domains by suffix — the trap this file exists for`() {
        assertTrue(DomainPolicy.isSystemDomain(canary))
        assertTrue(DomainPolicy.isSystemDomain("abc123.$canary"))
        assertTrue(DomainPolicy.isSystemDomain(listCanary))
    }

    @Test
    fun `classifier tests the tunnel canary before everything`() {
        assertEquals(DnsDecision.CANARY, DnsDecision.classify(canary, BlockList.empty()))
        assertEquals(DnsDecision.CANARY, DnsDecision.classify("r4nd0m.$canary", BlockList.empty()))
        // A canary label in the blocklist is STILL the canary, not BLOCK: the
        // probe is silent by design and must never raise a block event.
        assertEquals(DnsDecision.CANARY, DnsDecision.classify(canary, list(canary)))
    }

    @Test
    fun `list canary answers only when the loaded list contains it`() {
        assertEquals(DnsDecision.LIST_CANARY, DnsDecision.classify("x7.$listCanary", list(listCanary, "evil.tld")))
        // No list loaded (or a list without the canary line): the probe must
        // NOT be answered — that is precisely how the app learns the list is
        // absent — and must not leak upstream either: it is under cleanway.ai.
        assertEquals(DnsDecision.FORWARD, DnsDecision.classify("x7.$listCanary", BlockList.empty()))
        assertEquals(DnsDecision.FORWARD, DnsDecision.classify("x7.$listCanary", list("evil.tld")))
    }

    @Test
    fun `system domains are forwarded even if a list contained them`() {
        assertEquals(DnsDecision.FORWARD, DnsDecision.classify("api.cleanway.ai", list("api.cleanway.ai")))
        assertEquals(DnsDecision.FORWARD, DnsDecision.classify("mtalk.google.com", list("google.com")))
    }

    @Test
    fun `listed names block on the FIRST lookup, subdomains included, everything else forwards`() {
        val l = list("evil.tld", "gwcu.us.org")
        assertEquals(DnsDecision.BLOCK, DnsDecision.classify("evil.tld", l))
        assertEquals(DnsDecision.BLOCK, DnsDecision.classify("login.evil.tld", l))
        assertEquals(DnsDecision.BLOCK, DnsDecision.classify("www.gwcu.us.org", l))
        assertEquals(DnsDecision.FORWARD, DnsDecision.classify("us.org", l))
        assertEquals(DnsDecision.FORWARD, DnsDecision.classify("new.tld", l))
        assertEquals(DnsDecision.FORWARD, DnsDecision.classify("new.tld", BlockList.empty()))
    }
}
