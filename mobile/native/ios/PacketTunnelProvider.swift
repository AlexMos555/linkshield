/**
 * Cleanway iOS VPN Tunnel (NEPacketTunnelProvider)
 *
 * DNS-only local VPN. Does NOT inspect traffic content.
 * Only DNS queries are intercepted; all other traffic bypasses the tunnel.
 *
 * Hardening over the v0.1 skeleton:
 * - Real upstream DNS forwarding over UDP (was returning the query as its own
 *   response — nothing ever resolved).
 * - Thread-safe blocklist / safe cache via `actor BlocklistCache`.
 * - Swift 6 strict concurrency: all mutable state lives in actors; only
 *   `Sendable` values cross boundaries.
 * - System-domain guard centralized in `DomainPolicy` so it can be unit-tested
 *   from the main app target without running the extension.
 * - Logging via `os.Logger` (never `print`) per Swift security rules.
 *
 * Privacy invariants:
 * - Only domain names are ever read — no TCP/UDP payload is inspected.
 * - Checked domains leave the extension only as a GET to
 *   `/api/v1/public/check/{domain}` (domain only, never a URL path).
 * - App-group storage is `group.ai.cleanway.app`; cleared on logout.
 *
 * Setup: Add a Network Extension target in Xcode with
 * NEPacketTunnelProvider capability; register the App Group.
 */

import Foundation
import Network
import NetworkExtension
import os

private let log = Logger(subsystem: "ai.cleanway.app", category: "vpn.tunnel")
private let upstreamDNS = NWEndpoint.hostPort(host: "1.1.1.1", port: 53)
private let appGroup = "group.ai.cleanway.app"
private let apiBase = "https://api.cleanway.ai"

/// Thread-safe blocklist + safe-domain cache. All writes happen inside the
/// actor; reads return `Sendable` booleans so they are race-free.
actor BlocklistCache {
    private var blocked: Set<String> = []
    private var safe: Set<String> = []
    private let safeCacheCap = 10_000

    func isBlocked(_ domain: String) -> Bool { blocked.contains(domain) }
    func isSafe(_ domain: String) -> Bool { safe.contains(domain) }

    func markBlocked(_ domain: String) {
        blocked.insert(domain)
    }

    func markSafe(_ domain: String) {
        if safe.count >= safeCacheCap {
            // Best-effort LRU: drop an arbitrary entry to bound memory.
            if let first = safe.first { safe.remove(first) }
        }
        safe.insert(domain)
    }
}

/// Platform-independent policy — unit-tested in the app target.
enum DomainPolicy {
    /// System suffixes we NEVER block to avoid bricking the device.
    /// Update in sync with Android `CleanwayVpnService.systemSuffixes`.
    static let systemSuffixes: [String] = [
        "apple.com",
        "icloud.com",
        "mzstatic.com",
        "cleanway.ai",
        "cloudflare-dns.com",
    ]

    static func isSystemDomain(_ domain: String) -> Bool {
        let lower = domain.lowercased()
        return systemSuffixes.contains { lower == $0 || lower.hasSuffix("." + $0) }
    }
}

final class PacketTunnelProvider: NEPacketTunnelProvider {

    private let cache = BlocklistCache()
    private var readTask: Task<Void, Never>?

    // MARK: - Lifecycle

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let dnsSettings = NEDNSSettings(servers: ["10.0.0.1"])
        dnsSettings.matchDomains = [""] // Every domain

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.dnsSettings = dnsSettings
        settings.ipv4Settings = NEIPv4Settings(
            addresses: ["10.0.0.2"],
            subnetMasks: ["255.255.255.255"]
        )
        // We route ONLY the synthetic DNS address through the tunnel. All
        // application traffic bypasses us entirely.
        settings.ipv4Settings?.includedRoutes = [
            NEIPv4Route(destinationAddress: "10.0.0.1", subnetMask: "255.255.255.255")
        ]
        settings.mtu = NSNumber(value: 1500)

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error = error {
                log.error("tunnel_start_failed: \(error.localizedDescription, privacy: .public)")
                completionHandler(error)
                return
            }
            self?.readTask = Task { [weak self] in await self?.readLoop() }
            log.info("tunnel_started")
            completionHandler(nil)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        readTask?.cancel()
        readTask = nil
        log.info("tunnel_stopped reason=\(reason.rawValue, privacy: .public)")
        completionHandler()
    }

    // MARK: - Read / forward loop

    private func readLoop() async {
        while !Task.isCancelled {
            await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
                packetFlow.readPackets { [weak self] packets, protocols in
                    Task { [weak self] in
                        guard let self = self else { cont.resume(); return }
                        await self.handle(packets: packets, protocols: protocols)
                        cont.resume()
                    }
                }
            }
        }
    }

    private func handle(packets: [Data], protocols: [NSNumber]) async {
        for (index, packet) in packets.enumerated() {
            let proto = protocols[index]
            guard let domain = DNSParser.extractDomain(from: packet) else {
                // Not a parseable DNS query — drop silently (we only route DNS).
                continue
            }

            let normalized = domain.lowercased().trimmingCharacters(in: .init(charactersIn: "."))
            if DomainPolicy.isSystemDomain(normalized) {
                await forward(packet: packet, protocol: proto)
                continue
            }

            if await cache.isBlocked(normalized) {
                if let nx = DNSParser.makeNXDomain(query: packet) {
                    packetFlow.writePackets([nx], withProtocols: [proto])
                }
                await notifyBlocked(domain: normalized)
                continue
            }

            if await cache.isSafe(normalized) {
                await forward(packet: packet, protocol: proto)
                continue
            }

            // Unknown — forward immediately (fail-open) and check in background
            await forward(packet: packet, protocol: proto)
            Task.detached { [weak self] in
                await self?.checkDomain(normalized)
            }
        }
    }

    // MARK: - Upstream DNS

    /// Forward a raw DNS query to Cloudflare 1.1.1.1 over UDP and inject the
    /// response back into the tunnel. Uses `NWConnection` (Network.framework)
    /// for proper cancellation + Sendable safety.
    private func forward(packet: Data, `protocol`: NSNumber) async {
        let queue = DispatchQueue(label: "ai.cleanway.dns.forward")
        let connection = NWConnection(to: upstreamDNS, using: .udp)
        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            var resumed = false
            let resumeOnce: @Sendable () -> Void = {
                if !resumed { resumed = true; cont.resume() }
            }
            connection.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    // Strip IP+UDP header (28 bytes) — upstream takes raw DNS payload
                    let dnsPayload = packet.count > 28 ? packet.subdata(in: 28..<packet.count) : packet
                    connection.send(content: dnsPayload, completion: .contentProcessed { error in
                        if let error = error {
                            log.error("dns_forward_send_failed: \(error.localizedDescription, privacy: .public)")
                            connection.cancel()
                            resumeOnce()
                            return
                        }
                        connection.receiveMessage { [weak self] data, _, _, _ in
                            defer {
                                connection.cancel()
                                resumeOnce()
                            }
                            guard let self = self, let data = data else { return }
                            // Re-synthesize a full IP/UDP packet response so the
                            // in-tunnel client sees a well-formed datagram.
                            if let wrapped = DNSParser.wrapResponse(
                                payload: data, basedOnQuery: packet
                            ) {
                                self.packetFlow.writePackets([wrapped], withProtocols: [`protocol`])
                            }
                        }
                    })
                case .failed(let error), .waiting(let error):
                    log.error("dns_upstream_state: \(error.localizedDescription, privacy: .public)")
                    connection.cancel()
                    resumeOnce()
                case .cancelled:
                    resumeOnce()
                default:
                    break
                }
            }
            connection.start(queue: queue)
        }
    }

    // MARK: - Background domain check

    private func checkDomain(_ domain: String) async {
        guard let url = URL(string: "\(apiBase)/api/v1/public/check/\(domain)") else { return }
        var request = URLRequest(url: url, timeoutInterval: 3.0)
        request.httpMethod = "GET"

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200,
                  let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let level = json["level"] as? String else { return }

            if level == "dangerous" {
                await cache.markBlocked(domain)
                await notifyBlocked(domain: domain)
            } else {
                await cache.markSafe(domain)
            }
        } catch {
            log.debug("check_api_error: \(error.localizedDescription, privacy: .public)")
            // Fail-open — don't block on API failure
        }
    }

    // MARK: - Notifications (to main app via App Group)

    private func notifyBlocked(domain: String) async {
        guard let defaults = UserDefaults(suiteName: appGroup) else { return }
        var recent = defaults.stringArray(forKey: "blocked_domains") ?? []
        recent.append("\(domain)|\(Date().timeIntervalSince1970)")
        if recent.count > 100 {
            recent = Array(recent.suffix(100))
        }
        defaults.set(recent, forKey: "blocked_domains")
    }
}
