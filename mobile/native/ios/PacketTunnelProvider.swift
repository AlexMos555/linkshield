/**
 * LinkShield iOS VPN Tunnel (NEPacketTunnelProvider)
 *
 * DNS-only local VPN. Does NOT inspect traffic content.
 * Only intercepts DNS queries to check domains against blocklist.
 *
 * Setup: Add Network Extension target in Xcode with
 * NEPacketTunnelProvider capability.
 *
 * Privacy: Only domain names are checked. No traffic content
 * is ever read, stored, or transmitted.
 */

import NetworkExtension

class PacketTunnelProvider: NEPacketTunnelProvider {

    // Blocked domains cache
    private var blockedDomains = Set<String>()

    // Bloom filter for known-safe domains (loaded from CDN)
    private var bloomFilter: Data?

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        // Configure DNS settings
        let dnsSettings = NEDNSSettings(servers: ["127.0.0.1"])
        dnsSettings.matchDomains = [""] // Match all domains

        let tunnelSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        tunnelSettings.dnsSettings = dnsSettings

        // Set up split tunnel (only DNS, no traffic)
        tunnelSettings.ipv4Settings = NEIPv4Settings(
            addresses: ["10.0.0.1"],
            subnetMasks: ["255.255.255.0"]
        )
        tunnelSettings.ipv4Settings?.includedRoutes = [] // No traffic routing
        tunnelSettings.mtu = NSNumber(value: 1500)

        setTunnelNetworkSettings(tunnelSettings) { error in
            if let error = error {
                completionHandler(error)
                return
            }

            // Load bloom filter
            self.loadBloomFilter()

            // Start reading DNS packets
            self.startDNSProxy()

            completionHandler(nil)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        completionHandler()
    }

    // MARK: - DNS Proxy

    private func startDNSProxy() {
        // Read packets from the tunnel
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self else { return }

            for (index, packet) in packets.enumerated() {
                self.handleDNSPacket(packet, protocolNumber: protocols[index])
            }

            // Continue reading
            self.startDNSProxy()
        }
    }

    private func handleDNSPacket(_ packet: Data, protocolNumber: NSNumber) {
        // Parse DNS query to extract domain name
        guard let domain = extractDomainFromDNS(packet) else {
            // Not a DNS packet or can't parse — forward as-is
            packetFlow.writePackets([packet], withProtocols: [protocolNumber])
            return
        }

        let normalizedDomain = domain.lowercased()

        // Check if domain should be blocked
        if shouldBlock(normalizedDomain) {
            // Return NXDOMAIN response
            if let nxResponse = createNXDOMAINResponse(for: packet) {
                packetFlow.writePackets([nxResponse], withProtocols: [protocolNumber])
            }

            // Send notification to app
            notifyBlocked(domain: normalizedDomain)
            return
        }

        // Domain is safe — forward packet to real DNS
        packetFlow.writePackets([packet], withProtocols: [protocolNumber])
    }

    // MARK: - Domain Checking

    private func shouldBlock(_ domain: String) -> Bool {
        // Skip system domains
        let systemSuffixes = ["apple.com", "icloud.com", "mzstatic.com", "linkshield.io"]
        if systemSuffixes.contains(where: { domain.hasSuffix($0) }) {
            return false
        }

        // Check local blocklist
        if blockedDomains.contains(domain) {
            return true
        }

        // Check bloom filter (known safe)
        if isInBloomFilter(domain) {
            return false
        }

        // Unknown domain — check API asynchronously
        // For now, allow and check in background
        checkDomainAsync(domain)
        return false
    }

    private func checkDomainAsync(_ domain: String) {
        let url = URL(string: "https://api.linkshield.io/api/v1/public/check/\(domain)")!
        URLSession.shared.dataTask(with: url) { [weak self] data, _, _ in
            guard let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let level = json["level"] as? String else { return }

            if level == "dangerous" {
                self?.blockedDomains.insert(domain)
                self?.notifyBlocked(domain: domain)
            }
        }.resume()
    }

    // MARK: - Bloom Filter

    private func loadBloomFilter() {
        // Load from app group shared container or CDN
        // For now, placeholder
    }

    private func isInBloomFilter(_ domain: String) -> Bool {
        guard bloomFilter != nil else { return false }
        // MurmurHash3 check — same as JS implementation
        return false // Placeholder
    }

    // MARK: - DNS Parsing (simplified)

    private func extractDomainFromDNS(_ packet: Data) -> String? {
        // DNS packet starts at byte 12 (after IP header offset)
        // This is a simplified parser — production needs full DNS parsing
        guard packet.count > 20 else { return nil }

        // Skip IP + UDP headers (28 bytes typically)
        let dnsOffset = 28
        guard packet.count > dnsOffset + 12 else { return nil }

        var domain = ""
        var pos = dnsOffset + 12 // Skip DNS header

        while pos < packet.count {
            let labelLength = Int(packet[pos])
            if labelLength == 0 { break }
            pos += 1

            if pos + labelLength > packet.count { break }

            let label = String(data: packet[pos..<pos + labelLength], encoding: .utf8) ?? ""
            domain += (domain.isEmpty ? "" : ".") + label
            pos += labelLength
        }

        return domain.isEmpty ? nil : domain
    }

    private func createNXDOMAINResponse(for query: Data) -> Data? {
        // Create a minimal NXDOMAIN DNS response
        // In production, properly construct DNS response packet
        guard query.count > 30 else { return nil }

        var response = query
        // Set QR bit (response) and RCODE = 3 (NXDOMAIN)
        let dnsOffset = 28
        if response.count > dnsOffset + 3 {
            response[dnsOffset + 2] = 0x81 // QR=1, Opcode=0, AA=0, TC=0, RD=1
            response[dnsOffset + 3] = 0x83 // RA=1, RCODE=3 (NXDOMAIN)
        }
        return response
    }

    // MARK: - Notifications

    private func notifyBlocked(domain: String) {
        // Post to app via Darwin notification or app group UserDefaults
        let sharedDefaults = UserDefaults(suiteName: "group.io.linkshield.app")
        var blocked = sharedDefaults?.stringArray(forKey: "blocked_domains") ?? []
        blocked.append("\(domain)|\(Date().timeIntervalSince1970)")
        sharedDefaults?.set(blocked.suffix(100), forKey: "blocked_domains")
    }
}
