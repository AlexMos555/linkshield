/**
 * Cleanway Android VPN Service
 *
 * DNS-only local VPN. Intercepts DNS queries, decides locally whether a
 * domain is blocked, otherwise forwards the query to Cloudflare's 1.1.1.1
 * resolver and relays the response back into the tunnel.
 *
 * Hardening over the v0.1 skeleton:
 * - Fixed the critical bug where `forwardToUpstream` wrote the query back
 *   as its own response — no domain would ever resolve. Now uses a
 *   DatagramSocket to actually round-trip against upstream.
 * - Thread-safe cache via `ConcurrentHashMap`-backed sets.
 * - Structured logging with `android.util.Log` (levels + tag) instead of
 *   swallowed exceptions.
 * - DNS parsing + NXDOMAIN construction extracted to `DnsUtil` for unit
 *   testing in JVM tests (no Android dependencies).
 * - Background checks use a bounded `ExecutorService` — the original
 *   `Thread{}` fire-and-forget could spawn unbounded threads under load.
 *
 * Privacy invariants:
 * - Traffic content is never read. Only DNS queries are parsed (QNAME only).
 * - Checked domains leave the device only as a GET to
 *   `/api/v1/public/check/{domain}`.
 * - All mutable caches cleared when the VPN stops.
 *
 * Setup: `AndroidManifest.xml` must declare:
 *   <uses-permission android:name="android.permission.BIND_VPN_SERVICE" />
 *   <service
 *     android:name="ai.cleanway.app.CleanwayVpnService"
 *     android:permission="android.permission.BIND_VPN_SERVICE"
 *     android:exported="false">
 *     <intent-filter><action android:name="android.net.VpnService" /></intent-filter>
 *   </service>
 */

package ai.cleanway.app

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.URL
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class CleanwayVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null

    @Volatile
    private var running = false

    // Thread-safe domain caches. Both live for the lifetime of the service;
    // cleared on `onDestroy`.
    private val blockedDomains = ConcurrentHashMap.newKeySet<String>()
    private val safeDomains = ConcurrentHashMap.newKeySet<String>()

    // Bounded pool for outbound /check calls. Each call is cheap but we
    // cap parallelism so a flood of unknown queries doesn't spawn thousands
    // of threads.
    private val checkExecutor = Executors.newFixedThreadPool(4)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }
        if (!running) startVpn()
        return START_STICKY
    }

    private fun startVpn() {
        val builder = Builder()
            .setSession("Cleanway")
            .addAddress(VPN_CLIENT_IP, 32)
            .addDnsServer(VPN_GATEWAY_IP)
            .addRoute(VPN_GATEWAY_IP, 32) // Only route DNS to us
            .setMtu(1500)
            .setBlocking(true)

        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Exception) {
            Log.w(TAG, "addDisallowedApplication(self) failed: ${e.message}")
        }

        vpnInterface = builder.establish() ?: run {
            Log.e(TAG, "establish() returned null — VPN permission likely revoked")
            stopSelf()
            return
        }
        running = true
        Log.i(TAG, "tunnel_started")

        Thread({ dnsProxyLoop() }, "Cleanway-DNS").start()
    }

    private fun stopVpn() {
        running = false
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.w(TAG, "vpn_close_error: ${e.message}")
        }
        vpnInterface = null
        stopSelf()
        Log.i(TAG, "tunnel_stopped")
    }

    private fun dnsProxyLoop() {
        val vpn = vpnInterface ?: return
        val input = FileInputStream(vpn.fileDescriptor)
        val output = FileOutputStream(vpn.fileDescriptor)
        val buffer = ByteArray(32767)

        while (running) {
            try {
                val length = input.read(buffer)
                if (length <= 0) continue

                val packet = buffer.copyOf(length)
                val domain = DnsUtil.extractDomain(packet, length)

                if (domain == null) {
                    // Not a parseable DNS query — drop silently. We only route
                    // DNS, so any non-DNS packet landing here is already wrong.
                    continue
                }

                val normalized = domain.lowercase().trimEnd('.')

                if (DomainPolicy.isSystemDomain(normalized)) {
                    forwardToUpstream(packet, length, output)
                    continue
                }

                if (blockedDomains.contains(normalized)) {
                    val nx = DnsUtil.makeNxDomain(packet, length)
                    if (nx != null) output.write(nx)
                    notifyBlocked(normalized)
                    continue
                }

                if (safeDomains.contains(normalized)) {
                    forwardToUpstream(packet, length, output)
                    continue
                }

                // Unknown — forward immediately (fail-open), check in background
                forwardToUpstream(packet, length, output)
                checkExecutor.submit { checkDomainAsync(normalized) }
            } catch (e: Exception) {
                if (!running) break
                Log.w(TAG, "dns_loop_error: ${e.message}")
            }
        }
    }

    /**
     * Round-trip a DNS query to 1.1.1.1 via UDP and write the response back
     * to the VPN tunnel.
     *
     * The packet on `input` is a complete IPv4+UDP+DNS datagram as observed
     * by the tunnel. Upstream only wants the DNS payload (bytes 28..N), so
     * we strip the headers on the way out and re-wrap on the way back using
     * `DnsUtil.wrapResponse`.
     */
    private fun forwardToUpstream(packet: ByteArray, length: Int, output: FileOutputStream) {
        if (length <= DnsUtil.IP_UDP_HEADER) return
        val dnsStart = DnsUtil.IP_UDP_HEADER
        val dnsLen = length - dnsStart

        try {
            DatagramSocket().use { socket ->
                protect(socket) // Prevent loopback through our own VPN
                socket.soTimeout = 3_000

                val upstream = InetAddress.getByName(UPSTREAM_DNS_HOST)
                val outgoing = DatagramPacket(packet, dnsStart, dnsLen, upstream, UPSTREAM_DNS_PORT)
                socket.send(outgoing)

                val replyBuffer = ByteArray(2048)
                val reply = DatagramPacket(replyBuffer, replyBuffer.size)
                socket.receive(reply)

                val response = DnsUtil.wrapResponse(
                    query = packet,
                    queryLength = length,
                    payload = reply.data,
                    payloadOffset = reply.offset,
                    payloadLength = reply.length,
                )
                if (response != null) {
                    output.write(response)
                }
            }
        } catch (e: Exception) {
            Log.v(TAG, "upstream_dns_error: ${e.message}")
            // Fail-open: drop this query. Client will retry.
        }
    }

    private fun checkDomainAsync(domain: String) {
        try {
            val url = URL("$API_BASE/api/v1/public/check/$domain")
            val conn = (url.openConnection() as java.net.HttpURLConnection).apply {
                connectTimeout = 3_000
                readTimeout = 3_000
                requestMethod = "GET"
            }

            try {
                if (conn.responseCode == 200) {
                    val body = conn.inputStream.bufferedReader().use { it.readText() }
                    if (body.contains("\"dangerous\"")) {
                        blockedDomains.add(domain)
                        notifyBlocked(domain)
                    } else {
                        if (safeDomains.size >= SAFE_CACHE_CAP) {
                            // Cheap eviction — drop an arbitrary entry.
                            safeDomains.firstOrNull()?.let(safeDomains::remove)
                        }
                        safeDomains.add(domain)
                    }
                }
            } finally {
                conn.disconnect()
            }
        } catch (e: Exception) {
            Log.v(TAG, "check_api_error: ${e.message}")
            // Fail-open
        }
    }

    private fun notifyBlocked(domain: String) {
        sendBroadcast(
            Intent(ACTION_DOMAIN_BLOCKED).apply {
                setPackage(packageName)
                putExtra(EXTRA_DOMAIN, domain)
                putExtra(EXTRA_TIMESTAMP, System.currentTimeMillis())
            }
        )
    }

    override fun onDestroy() {
        stopVpn()
        blockedDomains.clear()
        safeDomains.clear()
        checkExecutor.shutdown()
        try {
            if (!checkExecutor.awaitTermination(2, TimeUnit.SECONDS)) {
                checkExecutor.shutdownNow()
            }
        } catch (e: InterruptedException) {
            checkExecutor.shutdownNow()
            Thread.currentThread().interrupt()
        }
        super.onDestroy()
    }

    companion object {
        private const val TAG = "CleanwayVPN"
        const val ACTION_STOP = "ai.cleanway.VPN_STOP"
        const val ACTION_DOMAIN_BLOCKED = "ai.cleanway.DOMAIN_BLOCKED"
        const val EXTRA_DOMAIN = "domain"
        const val EXTRA_TIMESTAMP = "ts_ms"

        private const val VPN_CLIENT_IP = "10.0.0.2"
        private const val VPN_GATEWAY_IP = "10.0.0.1"
        private const val UPSTREAM_DNS_HOST = "1.1.1.1"
        private const val UPSTREAM_DNS_PORT = 53
        private const val API_BASE = "https://web-production-fe08.up.railway.app"
        private const val SAFE_CACHE_CAP = 10_000
    }
}

/**
 * Platform-independent allowlist of system suffixes that must NEVER be
 * blocked — losing these bricks connectivity. Keep in sync with the iOS
 * equivalent in `PacketTunnelProvider.swift::DomainPolicy.systemSuffixes`.
 */
object DomainPolicy {
    private val systemSuffixes = listOf(
        "google.com",
        "googleapis.com",
        "android.com",
        "cleanway.ai",
        "cloudflare-dns.com",
    )

    fun isSystemDomain(domain: String): Boolean {
        val lower = domain.lowercase()
        return systemSuffixes.any { lower == it || lower.endsWith(".$it") }
    }
}
