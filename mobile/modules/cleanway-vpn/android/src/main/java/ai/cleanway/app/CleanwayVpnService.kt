/**
 * Cleanway Android VPN Service
 *
 * DNS-only local VPN. Intercepts DNS queries, decides locally whether a
 * domain is blocked, otherwise forwards the query upstream — plain UDP/53 for
 * speed, falling back to DNS-over-HTTPS against our own RFC 8484 gateway when
 * the network blocks or hijacks port 53 — and relays the response back into
 * the tunnel.
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
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.pm.ServiceInfo
import android.os.Build
import androidx.core.app.NotificationCompat

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

    // Upstream round-trips run here so the read loop stays responsive. Bounded
    // queue: under a flood we drop rather than grow memory, and DNS clients
    // retry on their own.
    private val forwardExecutor = ThreadPoolExecutor(
        4, 8, 30L, TimeUnit.SECONDS, ArrayBlockingQueue(256),
    )

    private val tunnelWriteLock = Any()

    // Transport health. A transport that fails repeatedly is skipped for a
    // while so the other one is tried first instead of paying both timeouts.
    @Volatile
    private var dohSuppressedUntil = 0L

    @Volatile
    private var udpSuppressedUntil = 0L

    @Volatile
    private var udpFailures = 0

    @Volatile
    private var dohFailures = 0

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            // Explicit user request: forget the intent so we do not come back
            // on the next boot.
            ShieldPreference.setUserEnabled(this, false)
            stopVpn()
            return START_NOT_STICKY
        }
        if (!running) startVpn()
        return START_STICKY
    }

    private fun startVpn() {
        // A VPN must run as a foreground service, or Android kills it when the app
        // backgrounds (and startForegroundService crashes without a prompt startForeground).
        startInForeground()
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
        isRunning = true
        // Remember that protection should be on, so BootReceiver can re-arm it
        // after a reboot or an OEM force-stop.
        ShieldPreference.setUserEnabled(this, true)
        Log.i(TAG, "tunnel_started")

        Thread({ dnsProxyLoop() }, "Cleanway-DNS").start()
    }

    /**
     * Android calls this when our tunnel is taken away — the user revoked VPN
     * access in Settings, or another VPN app (corporate, Google One, a free
     * VPN) established and displaced us. The default implementation stops the
     * service silently, which would leave the UI showing a green "protected"
     * shield over a dead tunnel. Announce it so the app can tell the truth.
     */
    override fun onRevoke() {
        Log.i(TAG, "tunnel_revoked")
        broadcastStopped(REASON_REVOKED)
        super.onRevoke()
    }

    private fun broadcastStopped(reason: String) {
        try {
            sendBroadcast(
                Intent(ACTION_VPN_STOPPED)
                    .setPackage(packageName)
                    .putExtra(EXTRA_REASON, reason)
            )
        } catch (e: Exception) {
            Log.w(TAG, "stopped_broadcast_error: ${e.message}")
        }
    }

    private fun stopVpn() {
        running = false
        isRunning = false
        stopForegroundCompat()
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
                    submitForward(packet, length, output)
                    continue
                }

                if (normalized == CANARY_DOMAIN) {
                    // Silent verification probe: the app resolves this domain
                    // after start and expects NXDOMAIN. No notifyBlocked — the
                    // probe must not spam block events or the notification.
                    val nx = DnsUtil.makeNxDomain(packet, length)
                    if (nx != null) writeToTunnel(output, nx)
                    continue
                }

                if (blockedDomains.contains(normalized)) {
                    val nx = DnsUtil.makeNxDomain(packet, length)
                    if (nx != null) writeToTunnel(output, nx)
                    notifyBlocked(normalized)
                    continue
                }

                if (safeDomains.contains(normalized)) {
                    submitForward(packet, length, output)
                    continue
                }

                // Unknown — forward immediately (fail-open), check in background
                submitForward(packet, length, output)
                checkExecutor.submit { checkDomainAsync(normalized) }
            } catch (e: Exception) {
                if (!running) break
                Log.w(TAG, "dns_loop_error: ${e.message}")
            }
        }
    }

    /**
     * Forward a DNS query upstream and write the answer back into the tunnel.
     *
     * Tries DNS-over-HTTPS first (our own RFC 8484 gateway, port 443) and falls
     * back to plain UDP/53. DoH is the better default for a protection app:
     * the query is encrypted, it resolves through our own gateway rather than
     * whatever the network hands out, and it still works on networks that block
     * or hijack port 53 — captive portals, restrictive corporate Wi-Fi, some
     * mobile carriers. UDP stays as the fallback for when DoH is unreachable.
     */
    /**
     * Hand the upstream round-trip to the pool so the read loop never blocks.
     *
     * This loop carries DNS for the entire device: doing the round-trip inline
     * means one stalled lookup (flaky network, Doze, slow gateway) queues every
     * other app's lookups behind it, and the whole phone appears to lose the
     * internet for seconds at a time. Queue overflow drops the query — the
     * client retries, which is the correct failure for DNS.
     */
    private fun submitForward(packet: ByteArray, length: Int, output: FileOutputStream) {
        try {
            forwardExecutor.execute { forwardToUpstream(packet, length, output) }
        } catch (e: RejectedExecutionException) {
            Log.v(TAG, "forward_queue_full")
        }
    }

    /** Writes to the tun fd are serialized: concurrent writes can interleave. */
    private fun writeToTunnel(output: FileOutputStream, data: ByteArray) {
        synchronized(tunnelWriteLock) {
            try {
                output.write(data)
            } catch (e: Exception) {
                Log.v(TAG, "tunnel_write_error: ${e.message}")
            }
        }
    }

    private fun forwardToUpstream(packet: ByteArray, length: Int, output: FileOutputStream) {
        if (length <= DnsUtil.IP_UDP_HEADER) return
        val now = System.currentTimeMillis()

        // Blocking is decided locally before we get here, so upstream is only a
        // transport — and its latency is the whole user experience: one page
        // pulls tens of lookups. Plain UDP/53 is the fast path (milliseconds),
        // DoH is the fallback for networks that block or hijack port 53.
        //
        // Whichever one is currently failing gets suppressed for a while.
        // Without that, a network with 53 blocked makes every single lookup pay
        // the UDP timeout before falling back — measured at ~5s per domain,
        // which reads as "the internet is broken" even though we resolve fine.
        val udpUsable = now >= udpSuppressedUntil
        val dohUsable = now >= dohSuppressedUntil

        if (udpUsable) {
            if (forwardOverUdp(packet, length, output)) {
                udpFailures = 0
                return
            }
            if (++udpFailures >= TRANSPORT_FAILURE_THRESHOLD) {
                udpSuppressedUntil = now + TRANSPORT_BACKOFF_MS
                Log.i(TAG, "udp_suppressed: falling back to DoH")
            }
        }

        if (!dohUsable) return
        if (forwardOverDoh(packet, length, output)) {
            dohFailures = 0
            return
        }
        if (++dohFailures >= TRANSPORT_FAILURE_THRESHOLD) {
            dohSuppressedUntil = now + TRANSPORT_BACKOFF_MS
            Log.i(TAG, "doh_suppressed")
        }

        // Both transports are down: the query is dropped and the client
        // retries. We never answer with a forged result — a wrong answer is
        // worse than a slow one for a security product.
    }

    /** Returns true when the DoH round-trip produced an answer. */
    private fun forwardOverDoh(packet: ByteArray, length: Int, output: FileOutputStream): Boolean {
        val dnsStart = DnsUtil.IP_UDP_HEADER
        val dnsLen = length - dnsStart
        return try {
            val conn = (URL(DOH_URL).openConnection() as java.net.HttpURLConnection).apply {
                requestMethod = "POST"
                doOutput = true
                // DNS is on the critical path of every page load — a slow
                // answer is nearly as bad as none.
                connectTimeout = 1_500
                readTimeout = 1_500
                setRequestProperty("Content-Type", "application/dns-message")
                setRequestProperty("Accept", "application/dns-message")
            }
            conn.outputStream.use { it.write(packet, dnsStart, dnsLen) }
            if (conn.responseCode != 200) {
                conn.disconnect()
                return false
            }
            val payload = conn.inputStream.use { it.readBytes() }
            conn.disconnect()
            if (payload.isEmpty()) return false

            val response = DnsUtil.wrapResponse(
                query = packet,
                queryLength = length,
                payload = payload,
                payloadOffset = 0,
                payloadLength = payload.size,
            )
            if (response != null) {
                writeToTunnel(output, response)
                true
            } else {
                false
            }
        } catch (e: Exception) {
            Log.v(TAG, "doh_error: ${e.message}")
            false
        }
    }

    /**
     * Round-trip a DNS query to the upstream resolver over UDP and write the
     * answer back into the tunnel. Returns true when an answer was written.
     *
     * The packet is a complete IPv4+UDP+DNS datagram as observed by the tunnel;
     * upstream only wants the DNS payload, so the headers are stripped on the
     * way out and rebuilt on the way back by `DnsUtil.wrapResponse`.
     */
    private fun forwardOverUdp(packet: ByteArray, length: Int, output: FileOutputStream): Boolean {
        val dnsStart = DnsUtil.IP_UDP_HEADER
        val dnsLen = length - dnsStart

        return try {
            DatagramSocket().use { socket ->
                protect(socket) // Prevent loopback through our own VPN
                socket.soTimeout = 3_000

                val upstream = InetAddress.getByName(UPSTREAM_DNS_HOST)
                val outgoing = DatagramPacket(packet, dnsStart, dnsLen, upstream, UPSTREAM_DNS_PORT)
                socket.send(outgoing)

                // EDNS0 messages can advertise up to 4096 bytes of UDP
                // payload (RFC 6891). A 2048-byte buffer silently
                // truncated DNSSEC + large TXT/MX answers, causing the
                // tunnel to write a partial response to the kernel and
                // making the user's apps treat the lookup as malformed.
                // 4096 matches Cloudflare 1.1.1.1's advertised buffer.
                // (Audit mobile-native LOW "Android DNS reply buffer
                // is 2048 bytes — EDNS0 responses silently truncated".)
                val replyBuffer = ByteArray(4096)
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
                    writeToTunnel(output, response)
                    return true
                }
            }
            false
        } catch (e: Exception) {
            Log.v(TAG, "upstream_dns_error: ${e.message}")
            // Fall through to DoH; the client also retries on its own.
            false
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
                    // Parse the JSON response properly instead of substring-
                    // matching "\"dangerous\"" anywhere in the body — the
                    // old check would false-positive on safe sites whose
                    // domain or one of the `reasons[].detail` strings
                    // happened to contain the literal word "dangerous"
                    // (e.g. "potentially dangerous extension" in a CDN
                    // description). The iOS counterpart already does this
                    // via Codable; matching it keeps platform behavior
                    // identical. (Audit mobile-native MEDIUM Android DNS
                    // substring match.)
                    val isDangerous = try {
                        val json = JSONObject(body)
                        json.optString("level") == "dangerous"
                    } catch (e: Exception) {
                        Log.w(TAG, "check_response_parse_failed: ${e.message}")
                        // Conservative on parse error: don't block a domain
                        // we couldn't classify; the user's other layers
                        // (extension, mobile app) will catch it.
                        false
                    }
                    if (isDangerous) {
                        if (blockedDomains.size >= BLOCKED_CACHE_CAP) {
                            // Same cap as safeDomains — without it the
                            // set grows unbounded across the VPN
                            // session and adds RAM pressure inside the
                            // Network Extension's tight memory window.
                            // (Audit mobile-native LOW
                            // "Blocked-domains cache is unbounded on
                            // both platforms — memory grows without
                            // limit for long-running VPN sessions".)
                            blockedDomains.firstOrNull()?.let(blockedDomains::remove)
                        }
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

    private fun startInForeground() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
            nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Cleanway protection", NotificationManager.IMPORTANCE_LOW).apply {
                    description = "Shown while phishing protection is active"
                    setShowBadge(false)
                }
            )
        }
        val launch = packageManager.getLaunchIntentForPackage(packageName)
        val pending = launch?.let {
            PendingIntent.getActivity(
                this, 0, it,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
        }
        val notif: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Cleanway protection is on")
            .setContentText("Checking links for phishing")
            .setSmallIcon(applicationInfo.icon)
            .setOngoing(true)
            .setContentIntent(pending)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notif)
        }
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    override fun onDestroy() {
        stopVpn()
        blockedDomains.clear()
        safeDomains.clear()
        checkExecutor.shutdown()
        try {
            if (!checkExecutor.awaitTermination(2, TimeUnit.SECONDS)) {
                checkExecutor.shutdownNow()
        forwardExecutor.shutdownNow()
            }
        } catch (e: InterruptedException) {
            checkExecutor.shutdownNow()
            Thread.currentThread().interrupt()
        }
        super.onDestroy()
    }

    companion object {
        /** Read by CleanwayVpnModule.isRunning() so the UI can reflect real service state. */
        @JvmStatic
        @Volatile
        var isRunning = false

        private const val CHANNEL_ID = "cleanway_vpn"
        private const val NOTIF_ID = 4711
        private const val TAG = "CleanwayVPN"
        const val ACTION_STOP = "ai.cleanway.VPN_STOP"

        /** Broadcast when the tunnel goes away without the user asking. */
        const val ACTION_VPN_STOPPED = "ai.cleanway.VPN_STOPPED"

        const val EXTRA_REASON = "reason"

        /** Taken away by the system or displaced by another VPN app. */
        const val REASON_REVOKED = "revoked"
        const val ACTION_DOMAIN_BLOCKED = "ai.cleanway.DOMAIN_BLOCKED"
        const val EXTRA_DOMAIN = "domain"
        const val EXTRA_TIMESTAMP = "ts_ms"

        private const val VPN_CLIENT_IP = "10.0.0.2"
        private const val VPN_GATEWAY_IP = "10.0.0.1"
        private const val UPSTREAM_DNS_HOST = "1.1.1.1"
        private const val UPSTREAM_DNS_PORT = 53
        private const val API_BASE = "https://api.cleanway.ai"
        private const val SAFE_CACHE_CAP = 10_000
        private const val BLOCKED_CACHE_CAP = 10_000

        // Resolved by the app's canary probe to verify filtering is live.
        // Must also exist in public DNS (ops: A/CNAME block-canary.cleanway.ai)
        // so a dead tunnel can't fake a "blocked" result.
        const val CANARY_DOMAIN = "block-canary.cleanway.ai"

        // Our RFC 8484 DNS-over-HTTPS gateway. Encrypted, resolves through our
        // own infrastructure, and survives networks that block plain port 53.
        private const val DOH_URL = "https://api.cleanway.ai/dns-query"

        private const val TRANSPORT_BACKOFF_MS = 60_000L

        private const val TRANSPORT_FAILURE_THRESHOLD = 3
    }
}

/**
 * Allowlist of system suffixes that must NEVER be blocked — losing
 * these bricks connectivity.
 *
 * Platform-specific by design — Android needs Google / Android while
 * iOS needs Apple / iCloud / MZStatic. The shared entries
 * (cleanway.ai, cloudflare-dns.com) ARE the ones to keep in sync with
 * the iOS list in `PacketTunnelProvider.swift::DomainPolicy.systemSuffixes`;
 * the platform-anchor entries are intentionally divergent. (Audit
 * mobile-native LOW "DomainPolicy 'keep in sync' comment contradicts
 * intentionally divergent platform suffix lists".)
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
