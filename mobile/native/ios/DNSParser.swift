/**
 * DNS wire-format parser + response synthesis.
 *
 * Extracted from PacketTunnelProvider so it can be unit-tested from the main
 * app target (Swift Testing) without running the packet tunnel extension.
 *
 * Scope intentionally minimal:
 * - `extractDomain(from:)` — parse the QNAME of the first question.
 * - `makeNXDomain(query:)` — flip the query into an authoritative NXDOMAIN.
 * - `wrapResponse(payload:basedOnQuery:)` — wrap a raw DNS payload in the
 *   IP+UDP headers copied from the original query (with src/dst swapped).
 *
 * NOT a full DNS implementation — does not handle:
 * - Message compression (RFC 1035 §4.1.4 pointers) — checks the MSB bits and
 *   returns nil to fail-safely, so a corrupted/compressed query is ignored
 *   (upstream forwarding still works because we never parsed it in the first
 *   place).
 * - IPv6 headers. Today's VPN config is v4-only.
 *
 * The binary layout we assume:
 *   bytes 0..20   IP header (v4, no options)
 *   bytes 20..28  UDP header
 *   bytes 28..    DNS message (header 12 bytes + question section)
 */

import Foundation

enum DNSParser {
    /// IP v4 (no options) + UDP — the simplest case we handle.
    static let ipUdpHeaderSize = 28
    /// DNS header size (always 12 bytes per RFC 1035).
    static let dnsHeaderSize = 12
    /// Max legal label length; longer → malformed.
    static let maxLabelLength = 63
    /// Max legal FQDN length; longer → reject.
    static let maxDomainLength = 253

    /// Returns the domain name from a DNS query packet, or nil if not a
    /// well-formed question we can handle.
    static func extractDomain(from packet: Data) -> String? {
        guard packet.count > ipUdpHeaderSize + dnsHeaderSize else { return nil }

        var pos = ipUdpHeaderSize + dnsHeaderSize
        var parts: [String] = []
        var totalLength = 0

        while pos < packet.count {
            let labelByte = Int(packet[pos])
            if labelByte == 0 {
                break
            }
            // Compressed pointers start with bits 11 — unsupported; reject.
            if labelByte & 0xC0 != 0 {
                return nil
            }
            if labelByte > maxLabelLength {
                return nil
            }
            pos += 1
            guard pos + labelByte <= packet.count else { return nil }
            let labelData = packet.subdata(in: pos..<(pos + labelByte))
            guard let label = String(data: labelData, encoding: .utf8),
                  !label.isEmpty else { return nil }
            parts.append(label)
            totalLength += labelByte + 1
            if totalLength > maxDomainLength { return nil }
            pos += labelByte
        }

        let name = parts.joined(separator: ".")
        return name.isEmpty ? nil : name
    }

    /// Build an NXDOMAIN response by flipping QR + RCODE bits in a copy of the
    /// original query. Returns nil if the query is too short to mutate safely.
    static func makeNXDomain(query: Data) -> Data? {
        guard query.count >= ipUdpHeaderSize + dnsHeaderSize else { return nil }
        var response = query
        // Flags field is at offset 28+2..28+4 (relative to DNS header start)
        let flagsHigh = ipUdpHeaderSize + 2
        let flagsLow = ipUdpHeaderSize + 3
        // QR=1 (response), Opcode=0, AA=1 (authoritative), TC=0, RD=copied
        response[flagsHigh] = (response[flagsHigh] & 0x01) | 0x84
        // RA=1 (recursion available), Z=0, RCODE=3 (NXDOMAIN)
        response[flagsLow] = 0x83
        // Swap IP src/dst (bytes 12..20 in IP header)
        swapIPv4Addresses(in: &response)
        // Swap UDP ports (bytes 20..22 and 22..24)
        swapUdpPorts(in: &response)
        // Zero out UDP checksum — optional in IPv4, router will still deliver.
        if response.count > 27 {
            response[26] = 0
            response[27] = 0
        }
        return response
    }

    /// Given a fresh DNS payload from the upstream resolver and the original
    /// query (which carries the tunnel-client's source address in its IP
    /// header), build a complete IPv4+UDP response packet.
    static func wrapResponse(payload: Data, basedOnQuery query: Data) -> Data? {
        guard query.count >= ipUdpHeaderSize else { return nil }
        var header = query.subdata(in: 0..<ipUdpHeaderSize)

        let totalLength = UInt16(header.count + payload.count)
        // IP total length is at offset 2..4 (big-endian)
        header[2] = UInt8((totalLength >> 8) & 0xFF)
        header[3] = UInt8(totalLength & 0xFF)

        // Zero IP checksum; many clients accept 0 (we could recompute, but
        // consumers on the tunnel side typically verify at upper layers).
        header[10] = 0
        header[11] = 0

        swapIPv4Addresses(in: &header)
        swapUdpPorts(in: &header)

        // UDP length (offset 24..26 in the full packet / 4..6 in UDP header)
        let udpLength = UInt16(8 + payload.count)
        header[24] = UInt8((udpLength >> 8) & 0xFF)
        header[25] = UInt8(udpLength & 0xFF)

        // Zero UDP checksum
        header[26] = 0
        header[27] = 0

        var out = Data(capacity: Int(totalLength))
        out.append(header)
        out.append(payload)
        return out
    }

    // MARK: - Internals

    private static func swapIPv4Addresses(in packet: inout Data) {
        guard packet.count >= 20 else { return }
        var src = Array(packet[12..<16])
        var dst = Array(packet[16..<20])
        packet.replaceSubrange(12..<16, with: dst)
        packet.replaceSubrange(16..<20, with: src)
        _ = src  // silence unused-var lint if compiled strict
        _ = dst
    }

    private static func swapUdpPorts(in packet: inout Data) {
        guard packet.count >= 24 else { return }
        let srcPort = Array(packet[20..<22])
        let dstPort = Array(packet[22..<24])
        packet.replaceSubrange(20..<22, with: dstPort)
        packet.replaceSubrange(22..<24, with: srcPort)
    }
}
