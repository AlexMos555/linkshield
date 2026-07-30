/**
 * Unit tests for `DnsUtil` + `DomainPolicy`. Pure JVM — no Android runtime
 * required. Target: `src/test/kotlin` under the Android VPN module's Gradle
 * project.
 *
 * Run:
 *   ./gradlew :vpn:test
 */

package ai.cleanway.app

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

// ─── Fixtures ───────────────────────────────────────────────────────────────

private object Fixtures {
    /**
     * Synthesize a minimal IPv4+UDP+DNS question packet (one QNAME, A/IN).
     * Mirrors the iOS `Fixtures.queryPacket` test helper so both sides parse
     * identical inputs.
     */
    fun queryPacket(domain: String): ByteArray {
        val parts = domain.split(".")
        val qnameSize = parts.sumOf { it.length + 1 } + 1 /* terminator */ + 4 /* qtype+qclass */

        val udpLen = 8 + 12 + qnameSize
        val totalLen = 20 + udpLen
        val packet = ByteArray(totalLen)

        // IP header
        packet[0] = 0x45.toByte()         // v4, IHL 5
        packet[2] = ((totalLen ushr 8) and 0xFF).toByte()
        packet[3] = (totalLen and 0xFF).toByte()
        packet[9] = 17                    // UDP
        // src 10.0.0.2 -> dst 10.0.0.1
        packet[12] = 10; packet[13] = 0; packet[14] = 0; packet[15] = 2
        packet[16] = 10; packet[17] = 0; packet[18] = 0; packet[19] = 1

        // UDP header
        packet[20] = 0xC0.toByte(); packet[21] = 0x00 // src port 49152
        packet[22] = 0x00; packet[23] = 0x35         // dst port 53
        packet[24] = ((udpLen ushr 8) and 0xFF).toByte()
        packet[25] = (udpLen and 0xFF).toByte()

        // DNS header
        packet[28] = 0x12; packet[29] = 0x34          // txn id
        packet[30] = 0x01; packet[31] = 0x00          // RD
        packet[33] = 0x01                             // QDCOUNT=1

        // QNAME
        var pos = 40
        for (label in parts) {
            val bytes = label.toByteArray(Charsets.UTF_8)
            require(bytes.size < 64)
            packet[pos] = bytes.size.toByte()
            pos++
            bytes.forEachIndexed { i, b -> packet[pos + i] = b }
            pos += bytes.size
        }
        packet[pos] = 0  // terminator
        pos++
        // QTYPE=A, QCLASS=IN
        packet[pos] = 0; packet[pos + 1] = 1
        packet[pos + 2] = 0; packet[pos + 3] = 1

        return packet
    }
}

// ─── extractDomain ──────────────────────────────────────────────────────────

class DnsUtilExtractDomainTest {
    @Test
    fun `extracts a standard domain`() {
        val packet = Fixtures.queryPacket("example.com")
        assertEquals("example.com", DnsUtil.extractDomain(packet, packet.size))
    }

    @Test
    fun `extracts a multi-label domain`() {
        val packet = Fixtures.queryPacket("sub.nested.example.com")
        assertEquals(
            "sub.nested.example.com",
            DnsUtil.extractDomain(packet, packet.size),
        )
    }

    @Test
    fun `rejects packets shorter than the headers`() {
        val tiny = byteArrayOf(0, 1, 2)
        assertNull(DnsUtil.extractDomain(tiny, tiny.size))
    }

    @Test
    fun `rejects compressed QNAME (pointer)`() {
        val packet = Fixtures.queryPacket("x.example.com")
        packet[40] = 0xC0.toByte() // compression pointer prefix
        assertNull(DnsUtil.extractDomain(packet, packet.size))
    }

    @Test
    fun `rejects oversized labels`() {
        val packet = Fixtures.queryPacket("ok.test")
        packet[40] = 0x7F // 127 > 63 legal max
        assertNull(DnsUtil.extractDomain(packet, packet.size))
    }
}

// ─── makeNxDomain ───────────────────────────────────────────────────────────

class DnsUtilNxDomainTest {
    @Test
    fun `sets QR AA and RCODE bits`() {
        val packet = Fixtures.queryPacket("bad.test")
        val response = DnsUtil.makeNxDomain(packet, packet.size)
        assertNotNull(response)

        val flagsHigh = response[30].toInt() and 0xFF
        val flagsLow = response[31].toInt() and 0xFF
        assertTrue(flagsHigh and 0x80 == 0x80, "QR must be 1")
        assertTrue(flagsHigh and 0x04 == 0x04, "AA must be 1")
        assertEquals(3, flagsLow and 0x0F, "RCODE must be NXDOMAIN (3)")
    }

    @Test
    fun `swaps source and destination addresses`() {
        val packet = Fixtures.queryPacket("bad.test")
        val response = DnsUtil.makeNxDomain(packet, packet.size)!!
        // Orig src 10.0.0.2, dst 10.0.0.1
        assertEquals(10, response[12].toInt() and 0xFF)
        assertEquals(1, response[15].toInt() and 0xFF)
        assertEquals(10, response[16].toInt() and 0xFF)
        assertEquals(2, response[19].toInt() and 0xFF)
    }

    @Test
    fun `swaps UDP ports`() {
        val packet = Fixtures.queryPacket("bad.test")
        val response = DnsUtil.makeNxDomain(packet, packet.size)!!
        // src port was 49152 (0xC000), dst 53 — must flip.
        assertEquals(0x00, response[20].toInt() and 0xFF)
        assertEquals(0x35, response[21].toInt() and 0xFF)
        assertEquals(0xC0, response[22].toInt() and 0xFF)
        assertEquals(0x00, response[23].toInt() and 0xFF)
    }
}

// ─── wrapResponse ───────────────────────────────────────────────────────────

class DnsUtilWrapResponseTest {
    @Test
    fun `wraps upstream DNS payload with swapped headers`() {
        val query = Fixtures.queryPacket("safe.test")
        val payload = byteArrayOf(0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte(), 0xDD.toByte())
        val out = DnsUtil.wrapResponse(query, query.size, payload, 0, payload.size)
        assertNotNull(out)
        assertEquals(DnsUtil.IP_UDP_HEADER + payload.size, out.size)
        // Payload tail
        assertEquals(0xAA.toByte(), out[DnsUtil.IP_UDP_HEADER])
        assertEquals(0xDD.toByte(), out[DnsUtil.IP_UDP_HEADER + 3])
        // Addresses swapped
        assertEquals(10, out[12].toInt() and 0xFF)
        assertEquals(1, out[15].toInt() and 0xFF)
    }

    @Test
    fun `rejects malformed query`() {
        val garbage = byteArrayOf(0, 1, 2)
        assertNull(DnsUtil.wrapResponse(garbage, garbage.size, byteArrayOf(1), 0, 1))
    }

    @Test
    fun `rejects out-of-bounds payload slice`() {
        val query = Fixtures.queryPacket("x.test")
        val payload = byteArrayOf(1, 2, 3)
        // length exceeds buffer
        assertNull(DnsUtil.wrapResponse(query, query.size, payload, 0, 100))
    }
}

// ─── DomainPolicy ───────────────────────────────────────────────────────────

class DomainPolicyTest {
    @Test
    fun `system suffixes are never blocked`() {
        assertTrue(DomainPolicy.isSystemDomain("google.com"))
        assertTrue(DomainPolicy.isSystemDomain("api.googleapis.com"))
        assertTrue(DomainPolicy.isSystemDomain("play.google.com"))
        assertTrue(DomainPolicy.isSystemDomain("cleanway.ai"))
        assertTrue(DomainPolicy.isSystemDomain("clients3.cloudflare-dns.com"))
    }

    @Test
    fun `non-system domains are not system`() {
        assertFalse(DomainPolicy.isSystemDomain("example.com"))
        assertFalse(DomainPolicy.isSystemDomain("evil.test"))
    }

    @Test
    fun `suffix match is bounded — not a naive endsWith`() {
        // "notgoogle.com" should NOT match "google.com" as a suffix
        assertFalse(DomainPolicy.isSystemDomain("notgoogle.com"))
        assertFalse(DomainPolicy.isSystemDomain("fakeandroid.com"))
    }

    @Test
    fun `case-insensitive matching`() {
        assertTrue(DomainPolicy.isSystemDomain("GOOGLE.COM"))
        assertTrue(DomainPolicy.isSystemDomain("Api.GoogleAPIs.Com"))
    }
}
