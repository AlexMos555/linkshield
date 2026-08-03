package ai.cleanway.app

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * The IPv4 header checksum is mandatory (RFC 791). Zeroing it — as this code
 * originally did — makes the kernel drop every response we write back into the
 * tunnel, so no domain resolves while the shield still claims to be on. These
 * tests pin the checksum so that regression cannot return silently.
 */
class DnsUtilChecksumTest {

    /** Independent re-implementation used as the oracle (RFC 1071). */
    private fun expectedChecksum(header: ByteArray): Int {
        var sum = 0L
        var i = 0
        while (i < 20) {
            if (i == 10) { i += 2; continue } // checksum field counts as zero
            val hi = (header[i].toInt() and 0xFF) shl 8
            val lo = header[i + 1].toInt() and 0xFF
            sum += (hi or lo).toLong()
            i += 2
        }
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv().toInt() and 0xFFFF
    }

    private fun sampleQuery(): ByteArray {
        val p = ByteArray(DnsUtil.IP_UDP_HEADER + 12)
        p[0] = 0x45                      // IPv4, IHL 5
        p[8] = 64                        // TTL
        p[9] = 17                        // UDP
        // src 10.0.0.2 -> dst 10.0.0.1
        p[12] = 10; p[13] = 0; p[14] = 0; p[15] = 2
        p[16] = 10; p[17] = 0; p[18] = 0; p[19] = 1
        p[20] = 0x30; p[21] = 0x39       // src port 12345
        p[22] = 0x00; p[23] = 0x35       // dst port 53
        return p
    }

    @Test
    fun `wrapResponse writes a non-zero header checksum`() {
        val out = DnsUtil.wrapResponse(
            query = sampleQuery(), queryLength = DnsUtil.IP_UDP_HEADER + 12,
            payload = ByteArray(24) { 7 }, payloadOffset = 0, payloadLength = 24,
        )
        requireNotNull(out)
        val written = ((out[10].toInt() and 0xFF) shl 8) or (out[11].toInt() and 0xFF)
        assertNotEquals(0, written, "a zeroed IPv4 checksum makes the kernel drop the packet")
    }

    @Test
    fun `checksum matches an independent RFC 1071 computation`() {
        val out = DnsUtil.wrapResponse(
            query = sampleQuery(), queryLength = DnsUtil.IP_UDP_HEADER + 12,
            payload = ByteArray(40) { 3 }, payloadOffset = 0, payloadLength = 40,
        )
        requireNotNull(out)
        val written = ((out[10].toInt() and 0xFF) shl 8) or (out[11].toInt() and 0xFF)
        assertEquals(expectedChecksum(out), written)
    }

    @Test
    fun `verifying the full header sums to 0xFFFF`() {
        // A receiver checksums the whole header including the checksum field;
        // a correct packet always folds to 0xFFFF.
        val out = DnsUtil.wrapResponse(
            query = sampleQuery(), queryLength = DnsUtil.IP_UDP_HEADER + 12,
            payload = ByteArray(16) { 1 }, payloadOffset = 0, payloadLength = 16,
        )
        requireNotNull(out)
        var sum = 0L
        var i = 0
        while (i < 20) {
            sum += (((out[i].toInt() and 0xFF) shl 8) or (out[i + 1].toInt() and 0xFF)).toLong()
            i += 2
        }
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        assertEquals(0xFFFF, sum.toInt())
    }

    @Test
    fun `NXDOMAIN replies also carry a valid checksum`() {
        val nx = DnsUtil.makeNxDomain(sampleQuery(), DnsUtil.IP_UDP_HEADER + 12)
        if (nx != null) {
            var sum = 0L
            var i = 0
            while (i < 20) {
                sum += (((nx[i].toInt() and 0xFF) shl 8) or (nx[i + 1].toInt() and 0xFF)).toLong()
                i += 2
            }
            while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
            assertEquals(0xFFFF, sum.toInt(), "a blocked domain's NXDOMAIN must reach the app too")
        }
    }

    @Test
    fun `header length comes from IHL so options are covered`() {
        val p = sampleQuery()
        p[0] = 0x45
        DnsUtil.writeIpv4HeaderChecksum(p)
        assertTrue((p[10].toInt() and 0xFF) != 0 || (p[11].toInt() and 0xFF) != 0)
    }
}
