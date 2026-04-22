/**
 * Unit tests for `DNSParser` and `DomainPolicy`.
 *
 * Target: the main app test bundle — these types must be shared between the
 * tunnel extension and the app, so building from either should be fine.
 *
 * Run:
 *   swift test --package-path mobile/native/ios    (stand-alone)
 *   xcodebuild test -scheme Cleanway -only-testing:CleanwayTests/DNSParserTests
 */

import Foundation
import Testing

@testable import CleanwayVPN

// ─── Fixtures ───────────────────────────────────────────────────────────────

private enum Fixtures {
    /// Synthesize a minimal IPv4+UDP+DNS query with a single QNAME + one QTYPE/QCLASS.
    /// Produces the packet layout our tunnel would actually see at
    /// `packetFlow.readPackets`.
    static func queryPacket(domain: String) -> Data {
        // ── IP header (20 bytes, v4 no options) ──
        var ip = Data(count: 20)
        ip[0] = 0x45 // version 4, IHL 5
        // total length fixed up at the end
        ip[9] = 17   // protocol = UDP
        // src 10.0.0.2, dst 10.0.0.1
        ip[12] = 10; ip[13] = 0; ip[14] = 0; ip[15] = 2
        ip[16] = 10; ip[17] = 0; ip[18] = 0; ip[19] = 1

        // ── UDP header (8 bytes) ──
        var udp = Data(count: 8)
        udp[0] = 0xC0; udp[1] = 0x00 // src port 49152
        udp[2] = 0x00; udp[3] = 0x35 // dst port 53

        // ── DNS header ──
        var dns = Data(count: 12)
        dns[0] = 0x12; dns[1] = 0x34 // txn id
        dns[2] = 0x01; dns[3] = 0x00 // RD
        dns[5] = 0x01               // QDCOUNT=1

        // ── QNAME ──
        var qname = Data()
        for label in domain.split(separator: ".") {
            let bytes = Array(label.utf8)
            precondition(bytes.count < 64)
            qname.append(UInt8(bytes.count))
            qname.append(contentsOf: bytes)
        }
        qname.append(0) // null terminator
        // QTYPE=A, QCLASS=IN
        qname.append(contentsOf: [0x00, 0x01, 0x00, 0x01])

        // Compose & patch IP + UDP lengths
        let udpLen = UInt16(8 + dns.count + qname.count)
        udp[4] = UInt8(udpLen >> 8); udp[5] = UInt8(udpLen & 0xFF)
        let totalLen = UInt16(20) + udpLen
        ip[2] = UInt8(totalLen >> 8); ip[3] = UInt8(totalLen & 0xFF)

        var out = Data()
        out.append(ip)
        out.append(udp)
        out.append(dns)
        out.append(qname)
        return out
    }
}

// ─── extractDomain ──────────────────────────────────────────────────────────

@Test("extracts a standard domain")
func extractsStandardDomain() {
    let packet = Fixtures.queryPacket(domain: "example.com")
    #expect(DNSParser.extractDomain(from: packet) == "example.com")
}

@Test("extracts a long multi-label domain")
func extractsMultiLabel() {
    let packet = Fixtures.queryPacket(domain: "sub.nested.example.com")
    #expect(DNSParser.extractDomain(from: packet) == "sub.nested.example.com")
}

@Test("rejects a packet shorter than the IP+UDP+DNS headers")
func rejectsShortPacket() {
    let tiny = Data([0x00, 0x01, 0x02])
    #expect(DNSParser.extractDomain(from: tiny) == nil)
}

@Test("rejects a compressed-pointer QNAME")
func rejectsCompressed() {
    var packet = Fixtures.queryPacket(domain: "x.y.example.com")
    // First label byte becomes 0xC0 (compression pointer prefix)
    let qnameStart = 28 + 12
    packet[qnameStart] = 0xC0
    #expect(DNSParser.extractDomain(from: packet) == nil)
}

@Test("rejects an oversized label")
func rejectsOversizedLabel() {
    var packet = Fixtures.queryPacket(domain: "ok.test")
    packet[28 + 12] = 0x7F // 127 > 63 max
    #expect(DNSParser.extractDomain(from: packet) == nil)
}

// ─── makeNXDomain ───────────────────────────────────────────────────────────

@Test("NXDOMAIN response flips QR + RCODE bits")
func nxdomainFlipsFlags() {
    let packet = Fixtures.queryPacket(domain: "bad.test")
    let response = try #require(DNSParser.makeNXDomain(query: packet))

    // flags high byte — QR=1, AA=1 ⇒ 0x84 (or 0x85 with RD set)
    let flagsHigh = response[28 + 2]
    #expect(flagsHigh & 0x80 == 0x80, "QR must be 1 on responses")
    #expect(flagsHigh & 0x04 == 0x04, "AA must be 1")
    // flags low byte — RCODE=3
    let flagsLow = response[28 + 3]
    #expect(flagsLow & 0x0F == 0x03, "RCODE must be NXDOMAIN")
}

@Test("NXDOMAIN swaps IP addresses")
func nxdomainSwapsAddresses() {
    let packet = Fixtures.queryPacket(domain: "bad.test")
    let response = try #require(DNSParser.makeNXDomain(query: packet))
    // Original src 10.0.0.2, dst 10.0.0.1 — response should flip them
    #expect(response[12] == 10 && response[15] == 1, "new src should be old dst")
    #expect(response[16] == 10 && response[19] == 2, "new dst should be old src")
}

@Test("NXDOMAIN swaps UDP ports")
func nxdomainSwapsPorts() {
    let packet = Fixtures.queryPacket(domain: "bad.test")
    let response = try #require(DNSParser.makeNXDomain(query: packet))
    #expect(response[20] == 0x00 && response[21] == 0x35, "src port now 53")
    #expect(response[22] == 0xC0 && response[23] == 0x00, "dst port now 49152")
}

// ─── wrapResponse ───────────────────────────────────────────────────────────

@Test("wraps upstream payload with IP+UDP headers copied from query")
func wrapsUpstreamPayload() {
    let query = Fixtures.queryPacket(domain: "safe.test")
    let payload = Data([0xAA, 0xBB, 0xCC, 0xDD])
    let wrapped = try #require(DNSParser.wrapResponse(payload: payload, basedOnQuery: query))
    #expect(wrapped.count == 28 + payload.count)
    // Addresses + ports swapped
    #expect(wrapped[12] == 10 && wrapped[15] == 1)
    #expect(wrapped[20] == 0x00 && wrapped[21] == 0x35)
    // Payload at the end
    #expect(wrapped.suffix(4) == Data([0xAA, 0xBB, 0xCC, 0xDD]))
}

@Test("wrapResponse rejects malformed query")
func wrapResponseRejectsTooShort() {
    let garbage = Data([0x00, 0x01, 0x02])
    #expect(DNSParser.wrapResponse(payload: Data([0xFF]), basedOnQuery: garbage) == nil)
}

// ─── DomainPolicy ───────────────────────────────────────────────────────────

@Test("system suffixes are never blocked")
func systemSuffixesNeverBlocked() {
    #expect(DomainPolicy.isSystemDomain("apple.com"))
    #expect(DomainPolicy.isSystemDomain("www.apple.com"))
    #expect(DomainPolicy.isSystemDomain("api.icloud.com"))
    #expect(DomainPolicy.isSystemDomain("mzstatic.com"))
    #expect(DomainPolicy.isSystemDomain("cleanway.ai"))
}

@Test("non-system domains are not system domains")
func nonSystemDomains() {
    #expect(!DomainPolicy.isSystemDomain("example.com"))
    #expect(!DomainPolicy.isSystemDomain("evil.test"))
    #expect(!DomainPolicy.isSystemDomain("notapple.com"), "suffix must be a bounded match")
}

@Test("case-insensitive suffix matching")
func caseInsensitive() {
    #expect(DomainPolicy.isSystemDomain("APPLE.COM"))
    #expect(DomainPolicy.isSystemDomain("Api.iCloud.Com"))
}
