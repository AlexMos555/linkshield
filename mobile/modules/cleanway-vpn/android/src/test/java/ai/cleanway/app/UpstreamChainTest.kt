package ai.cleanway.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The tunnel carries DNS for the whole phone. Two rules this file pins:
 *
 *  1. **Never silent.** Every query gets an answer. The old chain did
 *     `if (!dohUsable) return` — with both transports suppressed for 60s,
 *     every lookup on the device was dropped without a reply, so every app
 *     sat on its resolver timeout. To the user that is "the internet is
 *     broken", with a green shield on screen. A SERVFAIL is honest and fast:
 *     it never forges an answer, and the stub fails immediately instead of
 *     hanging.
 *  2. **Never all-suppressed.** The breaker always offers at least one
 *     transport to try (half-open trial), so a network blip cannot leave the
 *     phone with no path to DNS.
 */
class UpstreamChainTest {

    private fun query(name: String = "example.com"): ByteArray {
        // IP+UDP header (28 bytes) + DNS header (12) + question
        val labels = name.split(".").flatMap { listOf(it.length.toByte()) + it.toByteArray().toList() } + 0.toByte()
        val dns = byteArrayOf(0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0) +
            labels.toByteArray() + byteArrayOf(0, 1, 0, 1)
        val ip = ByteArray(28)
        ip[0] = 0x45
        return ip + dns
    }

    // ── never silent ──────────────────────────────────────────────────

    @Test
    fun `makeServfail answers the query with rcode 2 and keeps the transaction id`() {
        val q = query()
        val out = DnsUtil.makeServfail(q, q.size)
        assertNotNull(out)
        val dns = DnsUtil.IP_UDP_HEADER
        assertEquals(0x12.toByte(), out!![dns])
        assertEquals(0x34.toByte(), out[dns + 1])
        assertTrue("QR bit must be set", (out[dns + 2].toInt() and 0x80) != 0)
        assertEquals("RCODE must be 2 (SERVFAIL)", 2, out[dns + 3].toInt() and 0x0F)
        // Question echoed verbatim so the stub matches it to its request.
        assertEquals(q.size, out.size)
        for (i in dns + 12 until q.size) assertEquals(q[i], out[i])
    }

    @Test
    fun `makeServfail refuses a runt packet instead of emitting garbage`() {
        assertEquals(null, DnsUtil.makeServfail(ByteArray(10), 10))
    }

    @Test
    fun `servfail is a different answer from nxdomain — a failure must never look like a block`() {
        val q = query()
        val sf = DnsUtil.makeServfail(q, q.size)!!
        val nx = DnsUtil.makeNxDomain(q, q.size)!!
        val dns = DnsUtil.IP_UDP_HEADER
        assertEquals(2, sf[dns + 3].toInt() and 0x0F)
        assertEquals(3, nx[dns + 3].toInt() and 0x0F)
    }

    // ── breaker ───────────────────────────────────────────────────────

    @Test
    fun `all transports healthy - primary first, in preference order`() {
        val b = TransportBreaker()
        assertEquals(listOf(Transport.UDP_PRIMARY, Transport.UDP_SECONDARY, Transport.DOH), b.order(0L))
    }

    @Test
    fun `a failing transport is suppressed only after repeated failures`() {
        val b = TransportBreaker()
        b.onFailure(Transport.UDP_PRIMARY, 0L)
        assertEquals(Transport.UDP_PRIMARY, b.order(0L).first())
        b.onFailure(Transport.UDP_PRIMARY, 100L)
        b.onFailure(Transport.UDP_PRIMARY, 200L)
        // Third strike: demoted, not removed — the others are tried first.
        assertEquals(Transport.UDP_SECONDARY, b.order(300L).first())
        assertFalse(b.order(300L).isEmpty())
    }

    @Test
    fun `success resets the failure count`() {
        val b = TransportBreaker()
        repeat(2) { b.onFailure(Transport.UDP_PRIMARY, 0L) }
        b.onSuccess(Transport.UDP_PRIMARY)
        repeat(2) { b.onFailure(Transport.UDP_PRIMARY, 0L) }
        assertEquals(Transport.UDP_PRIMARY, b.order(0L).first())
    }

    @Test
    fun `everything suppressed still offers a half-open trial — never an empty chain`() {
        val b = TransportBreaker()
        for (t in Transport.values()) repeat(3) { b.onFailure(t, 0L) }
        val order = b.order(1_000L)
        assertFalse("the chain must never be empty", order.isEmpty())
        // The one closest to recovery is tried first.
        assertEquals(Transport.UDP_PRIMARY, order.first())
    }

    @Test
    fun `suppression expires and the transport returns to the front`() {
        val b = TransportBreaker()
        repeat(3) { b.onFailure(Transport.UDP_PRIMARY, 0L) }
        val backoff = TransportBreaker.BACKOFF_MS.first()
        assertEquals(Transport.UDP_SECONDARY, b.order(backoff - 1).first())
        assertEquals(Transport.UDP_PRIMARY, b.order(backoff + 1).first())
    }

    @Test
    fun `repeated failures lengthen the backoff, capped`() {
        val b = TransportBreaker()
        repeat(3) { b.onFailure(Transport.DOH, 0L) }
        assertEquals(TransportBreaker.BACKOFF_MS[0], b.suppressedUntil(Transport.DOH))
        repeat(3) { b.onFailure(Transport.DOH, TransportBreaker.BACKOFF_MS[0]) }
        assertEquals(TransportBreaker.BACKOFF_MS[0] + TransportBreaker.BACKOFF_MS[1], b.suppressedUntil(Transport.DOH))
        repeat(9) { b.onFailure(Transport.DOH, 0L) }
        assertTrue(b.suppressedUntil(Transport.DOH) <= TransportBreaker.BACKOFF_MS.last() * 2)
    }
}
