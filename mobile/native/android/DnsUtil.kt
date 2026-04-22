/**
 * DNS wire-format parser + response synthesis for Android.
 *
 * Pure-Kotlin object — no Android dependencies — so it can be unit-tested
 * on the JVM without an emulator.
 *
 * Mirrors the iOS `DNSParser` (Swift). Keep the two in sync when changing
 * parsing rules or adding features.
 *
 * Scope intentionally minimal:
 * - `extractDomain(packet, length)` — parse first-question QNAME
 * - `makeNxDomain(query, length)` — flip the query into an NXDOMAIN response
 * - `wrapResponse(query, queryLength, payload, ...)` — wrap a raw DNS
 *   payload in the IP+UDP headers from the original query (src/dst swapped)
 *
 * Intentional omissions:
 * - Message compression (RFC 1035 §4.1.4) — pointers return null (fail-safe).
 * - IPv6 — the tunnel is v4-only today.
 */

package ai.cleanway.app

object DnsUtil {
    const val IP_UDP_HEADER = 28
    private const val DNS_HEADER = 12
    private const val MAX_LABEL = 63
    private const val MAX_DOMAIN = 253

    fun extractDomain(packet: ByteArray, length: Int): String? {
        val start = IP_UDP_HEADER + DNS_HEADER
        if (length <= start) return null

        val sb = StringBuilder()
        var pos = start
        var total = 0

        while (pos < length) {
            val labelByte = packet[pos].toInt() and 0xFF
            if (labelByte == 0) break
            // Compression pointer — unsupported; fail-safe reject.
            if (labelByte and 0xC0 != 0) return null
            if (labelByte > MAX_LABEL) return null
            pos++
            if (pos + labelByte > length) return null
            if (sb.isNotEmpty()) sb.append('.')
            try {
                sb.append(String(packet, pos, labelByte, Charsets.UTF_8))
            } catch (e: Exception) {
                return null
            }
            total += labelByte + 1
            if (total > MAX_DOMAIN) return null
            pos += labelByte
        }

        return if (sb.isEmpty()) null else sb.toString()
    }

    /**
     * Flip a query into an authoritative NXDOMAIN response with addresses +
     * ports swapped so the tunnel client accepts it as a reply.
     * Returns null if the input is malformed.
     */
    fun makeNxDomain(query: ByteArray, length: Int): ByteArray? {
        if (length < IP_UDP_HEADER + DNS_HEADER) return null
        val out = query.copyOf(length)

        // Flags: QR=1, AA=1 (authoritative), RCODE=3 (NXDOMAIN). Preserve RD bit.
        val flagsHigh = IP_UDP_HEADER + 2
        val flagsLow = IP_UDP_HEADER + 3
        out[flagsHigh] = ((out[flagsHigh].toInt() and 0x01) or 0x84).toByte()
        out[flagsLow] = 0x83.toByte()

        swapIpv4Addresses(out)
        swapUdpPorts(out)

        // Zero UDP checksum (optional in v4).
        out[26] = 0
        out[27] = 0

        return out
    }

    fun wrapResponse(
        query: ByteArray,
        queryLength: Int,
        payload: ByteArray,
        payloadOffset: Int,
        payloadLength: Int,
    ): ByteArray? {
        if (queryLength < IP_UDP_HEADER) return null
        if (payloadLength < 0 || payloadOffset < 0) return null
        if (payloadOffset + payloadLength > payload.size) return null

        val totalLength = IP_UDP_HEADER + payloadLength
        val out = ByteArray(totalLength)

        // Copy IP+UDP headers from query
        System.arraycopy(query, 0, out, 0, IP_UDP_HEADER)
        // Append DNS payload from upstream
        System.arraycopy(payload, payloadOffset, out, IP_UDP_HEADER, payloadLength)

        // Patch IP total length (bytes 2..4, big-endian)
        out[2] = ((totalLength ushr 8) and 0xFF).toByte()
        out[3] = (totalLength and 0xFF).toByte()

        // Zero IP checksum (many clients accept 0)
        out[10] = 0
        out[11] = 0

        swapIpv4Addresses(out)
        swapUdpPorts(out)

        // Patch UDP length (bytes 24..26)
        val udpLength = 8 + payloadLength
        out[24] = ((udpLength ushr 8) and 0xFF).toByte()
        out[25] = (udpLength and 0xFF).toByte()

        // Zero UDP checksum
        out[26] = 0
        out[27] = 0

        return out
    }

    private fun swapIpv4Addresses(packet: ByteArray) {
        if (packet.size < 20) return
        for (i in 0 until 4) {
            val tmp = packet[12 + i]
            packet[12 + i] = packet[16 + i]
            packet[16 + i] = tmp
        }
    }

    private fun swapUdpPorts(packet: ByteArray) {
        if (packet.size < 24) return
        for (i in 0 until 2) {
            val tmp = packet[20 + i]
            packet[20 + i] = packet[22 + i]
            packet[22 + i] = tmp
        }
    }
}
