package ai.cleanway.app

import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Which network's resolver the shield asks first (UnderlyingDns).
 *
 * The rule the whole feature rests on: the shield's DNS goes where the rest of
 * the phone's traffic goes — the network Android routes through — so a router
 * resolver is only asked over its own Wi-Fi and the operator's only over
 * mobile data. And the tunnel's own address is never an upstream.
 */
class UnderlyingDnsTest {

    private fun ip(vararg b: Int): InetAddress = InetAddress.getByAddress(ByteArray(b.size) { b[it].toByte() })
    private fun ip6(last: Int): InetAddress = InetAddress.getByAddress(ByteArray(16).also { it[0] = 0x2a.toByte(); it[15] = last.toByte() })

    private val router = ip(192, 168, 1, 1)
    private val operator1 = ip(10, 64, 0, 1)
    private val operator2 = ip(10, 64, 0, 2)
    private val tunnel = ip(10, 0, 0, 2)

    private fun net(name: String, kind: NetKind, validated: Boolean = true, dns: List<InetAddress>, since: Long = 0L) =
        NetworkCandidate(name, kind, validated, dns, since)

    @Test
    fun `wifi wins over mobile data, like Android's own routing`() {
        val chosen = UnderlyingDns.choose(
            listOf(net("cell", NetKind.CELLULAR, dns = listOf(operator1)), net("wifi", NetKind.WIFI, dns = listOf(router))),
            emptySet(),
        )
        assertEquals("wifi", chosen!!.handle)
        assertEquals(listOf(router), chosen.servers)
    }

    @Test
    fun `a validated network wins over one that has not passed its internet check`() {
        val chosen = UnderlyingDns.choose(
            listOf(
                net("captive-wifi", NetKind.WIFI, validated = false, dns = listOf(router)),
                net("cell", NetKind.CELLULAR, dns = listOf(operator1)),
            ),
            emptySet(),
        )
        assertEquals("cell", chosen!!.handle)
    }

    @Test
    fun `among equals the network the phone just switched to wins`() {
        val chosen = UnderlyingDns.choose(
            listOf(net("old", NetKind.WIFI, dns = listOf(router), since = 1L), net("new", NetKind.WIFI, dns = listOf(operator1), since = 2L)),
            emptySet(),
        )
        assertEquals("new", chosen!!.handle)
    }

    @Test
    fun `a network with no usable resolver is skipped, and none at all means the public chain`() {
        val chosen = UnderlyingDns.choose(
            listOf(net("wifi", NetKind.WIFI, dns = listOf(tunnel)), net("cell", NetKind.CELLULAR, dns = listOf(operator1))),
            setOf(tunnel),
        )
        assertEquals("cell", chosen!!.handle)
        assertNull(UnderlyingDns.choose(listOf(net("wifi", NetKind.WIFI, dns = emptyList())), emptySet()))
        assertNull(UnderlyingDns.choose(emptyList<NetworkCandidate<String>>(), emptySet()))
    }

    @Test
    fun `servers - IPv4 first, never the tunnel, loopback, wildcard or multicast, at most two`() {
        val servers = UnderlyingDns.usableServers(
            listOf(ip6(1), tunnel, ip(127, 0, 0, 1), ip(0, 0, 0, 0), ip(224, 0, 0, 251), operator1, operator1, operator2, ip(10, 64, 0, 3)),
            setOf(tunnel),
        )
        assertEquals(listOf(operator1, operator2), servers)
        assertEquals(listOf(ip6(1)), UnderlyingDns.usableServers(listOf(ip6(1)), emptySet()))
    }

    private fun answer(rcode: Int): ByteArray = byteArrayOf(0x12, 0x34, 0x81.toByte(), (0x80 or rcode).toByte(), 0, 1, 0, 0, 0, 0, 0, 0)

    @Test
    fun `SERVFAIL and REFUSED hand over to the public resolvers, every other answer is passed on`() {
        assertTrue(UnderlyingDns.isUsableAnswer(answer(0), 0, 12))   // NOERROR
        assertTrue(UnderlyingDns.isUsableAnswer(answer(3), 0, 12))   // NXDOMAIN — also how an operator blocks
        assertFalse(UnderlyingDns.isUsableAnswer(answer(2), 0, 12))  // SERVFAIL
        assertFalse(UnderlyingDns.isUsableAnswer(answer(5), 0, 12))  // REFUSED
        assertFalse(UnderlyingDns.isUsableAnswer(ByteArray(6), 0, 6)) // runt
        // The rcode is read at the payload's own offset.
        assertFalse(UnderlyingDns.isUsableAnswer(ByteArray(4) + answer(2), 4, 12))
    }
}
