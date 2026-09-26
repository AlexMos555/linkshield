package ai.cleanway.app

import ai.cleanway.app.MessageTestSupport.list
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * A link out of a message is judged in the DNS decision's order: system
 * suffixes and the person's allow list first (never flagged), then the list
 * (a match is dangerous). DnsDecisionTest pins the same order for the tunnel;
 * the two must not disagree about a host.
 */
class LinkPolicyTest {

    private val bad = list("evil.tld", "gwcu.us.org", "xn--c1aapkosapc.xn--p1ai", "api.cleanway.ai")

    @Test
    fun `a listed host and its subdomains are blocked, the listed suffix is reported`() {
        assertEquals(LinkStatus.BLOCKED, LinkPolicy.classify("evil.tld", bad, emptySet()))
        assertEquals(LinkStatus.BLOCKED, LinkPolicy.classify("login.evil.tld", bad, emptySet()))
        assertEquals("evil.tld", LinkPolicy.listedSuffix("login.evil.tld", bad, emptySet()))
        assertEquals("gwcu.us.org", LinkPolicy.listedSuffix("www.gwcu.us.org", bad, emptySet()))
    }

    @Test
    fun `an unlisted host is unknown, never safe`() {
        assertEquals(LinkStatus.UNKNOWN, LinkPolicy.classify("new.tld", bad, emptySet()))
        assertEquals(LinkStatus.UNKNOWN, LinkPolicy.classify("us.org", bad, emptySet()))
        assertNull(LinkPolicy.listedSuffix("new.tld", bad, emptySet()))
    }

    @Test
    fun `no list at all means unknown, not blocked`() {
        assertEquals(LinkStatus.UNKNOWN, LinkPolicy.classify("evil.tld", null, emptySet()))
        assertNull(LinkPolicy.listedSuffix("evil.tld", null, emptySet()))
    }

    @Test
    fun `system domains are never flagged, even if a list contained them`() {
        assertEquals(LinkStatus.SYSTEM, LinkPolicy.classify("api.cleanway.ai", bad, emptySet()))
        assertEquals(LinkStatus.SYSTEM, LinkPolicy.classify("docs.google.com", list("google.com"), emptySet()))
        assertNull(LinkPolicy.listedSuffix("api.cleanway.ai", bad, emptySet()))
    }

    @Test
    fun `a system domain is not vouched for, the person's allow is`() {
        // Anyone can publish on sites.google.com: never blocked, never "allowed".
        assertEquals(LinkStatus.SYSTEM, LinkPolicy.classify("sites.google.com", null, emptySet()))
        assertEquals(LinkStatus.ALLOWED_BY_USER, LinkPolicy.classify("mine.example", null, setOf("mine.example")))
    }

    @Test
    fun `the person's allow outranks the list, subdomains included`() {
        val allowed = setOf("evil.tld")
        assertEquals(LinkStatus.ALLOWED_BY_USER, LinkPolicy.classify("login.evil.tld", bad, allowed))
        assertNull(LinkPolicy.listedSuffix("evil.tld", bad, allowed))
    }

    @Test
    fun `a cyrillic host from a message matches once punycoded`() {
        val host = LinkExtractor.extract("Оплата на госуслуги.рф", MessageTestSupport.rules.bareTlds).single().host
        assertEquals(LinkStatus.BLOCKED, LinkPolicy.classify(host, bad, emptySet()))
    }

    @Test
    fun `agrees with the DNS decision on every host it shares`() {
        val allowed = setOf("mine.example")
        val hosts = listOf("evil.tld", "a.evil.tld", "new.tld", "api.cleanway.ai", "mine.example", "gwcu.us.org")
        for (h in hosts) {
            val dns = DnsDecision.classify(h, bad, allowed)
            val msg = LinkPolicy.classify(h, bad, allowed)
            assertEquals(dns == DnsDecision.BLOCK, msg == LinkStatus.BLOCKED, "disagree on $h")
        }
    }
}
