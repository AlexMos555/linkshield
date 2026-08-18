/**
 * Cleanway Android VPN Service
 *
 * DNS-only local VPN. Intercepts DNS queries, decides locally whether a
 * domain is blocked, otherwise forwards the query upstream — plain UDP/53 for
 * speed, falling back to DNS-over-HTTPS (addressed by IP literal, so it needs
 * no bootstrap lookup) when the network blocks or hijacks port 53 — and relays
 * the response back into the tunnel.
 *
 * Design notes:
 * - Blocking is decided locally from an in-memory verdict cache; upstream is
 *   only a transport, which is why speed is chosen over routing through our
 *   own resolver.
 * - Upstream round-trips run on a bounded pool, never on the read loop: that
 *   loop carries DNS for the whole device, so a single stalled lookup would
 *   queue every other app's behind it.
 * - Writes back into the tun fd are serialized; concurrent replies would
 *   otherwise interleave.
 * - The IPv4 header checksum is recomputed on every reply we synthesise. A
 *   zeroed one is silently dropped by the kernel, which presents to the user
 *   as a broken internet connection while the shield claims to be on.
 * - DNS parsing and NXDOMAIN construction live in `DnsUtil` so they can be
 *   unit-tested on the JVM without Android.
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
import java.io.File
import java.util.concurrent.ScheduledExecutorService

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

    /** Unregisters the Private DNS setting observer; null while not watching. */
    private var stopPrivateDnsWatch: (() -> Unit)? = null

    @Volatile
    private var running = false

    // The on-device blocklist. Decided here, on the FIRST lookup, no network.
    // Swapped by BlocklistSync on refresh; the DNS loop only reads it.
    @Volatile
    private var blockList: BlockList = BlockList.empty()

    /**
     * Sites the person marked "not a scam". Read on the DNS thread on every
     * query, so it is kept as an immutable snapshot and swapped whole.
     */
    @Volatile
    private var allowedDomains: Set<String> = emptySet()
    private var blocklistSync: BlocklistSync? = null
    private val syncExecutor: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "Cleanway-Blocklist").apply { isDaemon = true }
    }

    // Upstream round-trips run here so the read loop stays responsive. Bounded
    // queue: under a flood we drop rather than grow memory, and DNS clients
    // retry on their own.
    private val forwardExecutor = ThreadPoolExecutor(
        4, 8, 30L, TimeUnit.SECONDS, ArrayBlockingQueue(256),
    )

    private val tunnelWriteLock = Any()

    // Transport health. A transport that fails repeatedly is demoted for a
    // while so the others are tried first instead of paying its timeout —
    // but never removed, and the chain is never empty. See TransportBreaker.
    private val breaker = TransportBreaker()

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

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

        // Re-claim the VPN "prepared" slot before establish().
        //
        // Android keeps VPN consent in two places. The user's grant lives in
        // AppOps (OP_ACTIVATE_VPN) and survives reboots. The *currently
        // prepared package* — the one establish() will accept — is in-memory
        // state of ConnectivityService and is empty after every boot. The
        // system consent dialog is shown only when the AppOps grant is
        // missing; when it is present, prepare() silently marks us prepared
        // and returns null. Without this call every restart from BootReceiver
        // died with "establish() returned null" — verified on a rebooted
        // emulator, where a single tap in the app then turned the shield
        // green with NO consent dialog. The consent was never lost; only the
        // in-memory owner was.
        //
        // If prepare() does return an Intent, consent is genuinely absent (the
        // user revoked it in Settings, or never granted it): stop honestly, the
        // app shows "protection stopped" and the next tap raises the dialog.
        if (prepare(this) != null) {
            Log.w(TAG, "consent_missing — not establishing")
            stopSelf()
            return
        }

        // Strict Private DNS + our tunnel = no DNS for any app on the phone
        // (see PrivateDnsGuard). Refuse rather than break the internet; the
        // app explains which setting to change and deep-links there.
        PrivateDnsGuard.strictHostname(this)?.let { host ->
            Log.w(TAG, "private_dns_strict host=$host — refusing to establish")
            broadcastStopped(REASON_PRIVATE_DNS)
            stopSelf()
            return
        }

        val builder = Builder()
            .setSession("Cleanway")
            .addAddress(VPN_CLIENT_IP, 32)
            .addDnsServer(VPN_GATEWAY_IP)
            .addRoute(VPN_GATEWAY_IP, 32) // Only route DNS to us
            .setMtu(1500)
            .setBlocking(true)

        // Deliberately NOT excluding our own app from the tunnel.
        //
        // addDisallowedApplication(packageName) used to sit here "to prevent
        // loops", and it silently broke the shield's proof of life: the app's
        // own canary DNS query bypassed the tunnel, so the service never saw
        // it, the stamp never moved, and verifyFiltering() could not return
        // true on any device — the green state was unreachable code.
        //
        // The loop it feared cannot happen with this routing:
        //   - the tunnel captures ONLY traffic to VPN_GATEWAY_IP/32 (DNS);
        //     every TCP connection to public IPs goes out the real interface
        //   - the upstream UDP DNS socket is protect()ed (forwardOverUdp)
        //   - the DoH fallback dials 1.1.1.1 by IP literal over TCP — no DNS
        //     needed, and 1.1.1.1/32 is not routed into the tunnel
        // The service's own hostname lookups (api.cleanway.ai in
        // checkDomainAsync) now transit the tunnel like any other app's and
        // are forwarded upstream on a different thread — that is the normal
        // path, not a loop.

        vpnInterface = builder.establish() ?: run {
            // Consent was present a moment ago (prepare() said so), so this is
            // something else: another VPN in lockdown, or the system refusing.
            Log.e(TAG, "establish() returned null after successful prepare()")
            stopSelf()
            return
        }
        running = true
        isRunning = true
        // Remember that protection should be on, so BootReceiver can re-arm it
        // after a reboot or an OEM force-stop.
        ShieldPreference.setUserEnabled(this, true)
        Log.i(TAG, "tunnel_started")

        // Load the stored blocklist synchronously (≈30 KB, milliseconds) so
        // the very first query after start is already filtered; then keep it
        // fresh in the background (every 2h ± jitter, backoff on failure).
        startBlocklist()

        Thread({ dnsProxyLoop() }, "Cleanway-DNS").start()

        // The user can switch Private DNS to strict while we run — from that
        // moment every lookup on the phone fails. Step aside immediately and
        // say why, rather than leaving a green shield over a dead internet.
        stopPrivateDnsWatch?.invoke()
        stopPrivateDnsWatch = PrivateDnsGuard.watch(this) {
            if (!running) return@watch
            PrivateDnsGuard.strictHostname(this)?.let { host ->
                Log.w(TAG, "private_dns_strict host=$host — stepping aside")
                broadcastStopped(REASON_PRIVATE_DNS)
                stopVpn()
            }
        }
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
        stopPrivateDnsWatch?.invoke()
        stopPrivateDnsWatch = null
        // The counter is monotonic and compared by delta in JS, so a value
        // from a previous tunnel cannot satisfy a new probe — no reset needed.
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

                when (DnsDecision.classify(normalized, blockList, allowedDomains)) {
                    DnsDecision.CANARY -> {
                        // Silent verification probe: the app resolves a RANDOM
                        // subdomain of the canary and expects NXDOMAIN. The
                        // random label defeats every resolver cache between
                        // the app and us — a cached answer would satisfy the
                        // fetch without any query reaching this loop, and the
                        // counter would honestly refuse to move. No
                        // notifyBlocked — the probe must not spam block events
                        // or the notification.
                        val nx = DnsUtil.makeNxDomain(packet, length)
                        if (nx != null) {
                            writeToTunnel(output, nx)
                            // Count only queries we actually answered. This is
                            // what the app reads back as proof that filtering
                            // is live right now, through THIS tunnel.
                            canaryAnswerCount += 1
                        }
                    }
                    DnsDecision.LIST_CANARY -> {
                        // Second proof of life: the loaded LIST is live, not just
                        // the tunnel. Answered only when the list contains the
                        // canary line; silent like the tunnel canary.
                        val nx = DnsUtil.makeNxDomain(packet, length)
                        if (nx != null) {
                            writeToTunnel(output, nx)
                            listCanaryAnswerCount += 1
                        }
                    }
                    DnsDecision.BLOCK -> {
                        val nx = DnsUtil.makeNxDomain(packet, length)
                        if (nx != null) writeToTunnel(output, nx)
                        // A real block, on the first lookup: the site never opened.
                        notifyBlocked(blockList.match(normalized) ?: normalized, BlockLog.KIND_BLOCKED)
                    }
                    DnsDecision.FORWARD -> submitForward(packet, length, output)
                }
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

        // Blocking is decided locally before we get here, so upstream is only
        // a transport — and its latency is the whole user experience: one page
        // pulls tens of lookups. Plain UDP/53 is the fast path (milliseconds);
        // a second public resolver covers networks that block the first by IP;
        // DoH covers networks that block or hijack port 53 entirely.
        for (transport in breaker.order(now)) {
            val ok = when (transport) {
                Transport.UDP_PRIMARY -> forwardOverUdp(packet, length, output, UPSTREAM_DNS_HOST)
                Transport.UDP_SECONDARY -> forwardOverUdp(packet, length, output, UPSTREAM_DNS_HOST_2)
                Transport.DOH -> forwardOverDoh(packet, length, output)
            }
            if (ok) {
                breaker.onSuccess(transport)
                return
            }
            breaker.onFailure(transport, now)
        }

        // Nothing answered. Say so — never leave the query unanswered.
        //
        // The old chain returned here, and with both transports suppressed it
        // dropped EVERY query on the device for a minute: every app sat on its
        // resolver timeout while the shield showed green. A SERVFAIL forges
        // nothing (it is not an answer and cannot be mistaken for a block —
        // that is NXDOMAIN) and lets the stub fail immediately.
        val servfail = DnsUtil.makeServfail(packet, length)
        if (servfail != null) {
            writeToTunnel(output, servfail)
            servfailCount += 1
            if (servfailCount % SERVFAIL_LOG_EVERY == 1L) {
                Log.w(TAG, "servfail_written: no upstream answered (total=$servfailCount)")
            }
        }
    }

    /** Returns true when the DoH round-trip produced an answer. */
    private fun forwardOverDoh(packet: ByteArray, length: Int, output: FileOutputStream): Boolean {
        val dnsStart = DnsUtil.IP_UDP_HEADER
        val dnsLen = length - dnsStart
        return try {
            val conn = (java.net.URL(DOH_URL).openConnection() as java.net.HttpURLConnection).apply {
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
    private fun forwardOverUdp(
        packet: ByteArray,
        length: Int,
        output: FileOutputStream,
        host: String,
    ): Boolean {
        val dnsStart = DnsUtil.IP_UDP_HEADER
        val dnsLen = length - dnsStart

        return try {
            DatagramSocket().use { socket ->
                protect(socket) // Prevent loopback through our own VPN
                socket.soTimeout = 3_000

                val upstream = InetAddress.getByName(host)
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
            Log.v(TAG, "upstream_dns_error($host): ${e.message}")
            // Fall through to the next transport in the chain.
            false
        }
    }

    /**
     * Make a block visible: persist it (so the app can count and list it
     * later, JS or no JS), tell the person now (localized notification from
     * the service), and broadcast for a live UI. [kind] keeps it honest — see
     * BlockLog for BLOCKED vs WARNED.
     */
    private fun notifyBlocked(domain: String, kind: String) {
        val now = System.currentTimeMillis()
        try {
            BlockLog.record(this, domain, now, kind)
            BlockNotifier.notify(this, domain, kind, now)
        } catch (e: Exception) {
            Log.w(TAG, "block_visibility_error: ${e.message}")
        }
        sendBroadcast(
            Intent(ACTION_DOMAIN_BLOCKED).apply {
                setPackage(packageName)
                putExtra(EXTRA_DOMAIN, domain)
                putExtra(EXTRA_TIMESTAMP, now)
                putExtra(EXTRA_KIND, kind)
            }
        )
    }

    private fun startInForeground() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
            nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    getString(expo.modules.cleanwayvpn.R.string.fg_channel),
                    NotificationManager.IMPORTANCE_LOW,
                ).apply {
                    description = getString(expo.modules.cleanwayvpn.R.string.fg_channel_desc)
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
            .setContentTitle(getString(expo.modules.cleanwayvpn.R.string.fg_title))
            .setContentText(getString(expo.modules.cleanwayvpn.R.string.fg_text))
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
        if (instance === this) instance = null
        stopVpn()
        blocklistSync?.stop()
        syncExecutor.shutdownNow()
        forwardExecutor.shutdownNow()
        super.onDestroy()
    }

    // ── Blocklist ────────────────────────────────────────────────────────

    private fun startBlocklist() {
        try {
            val veto = loadPopularVeto()
            blockList = BlockList.empty(veto)
            reloadAllowed()
            val store = BlocklistStore(File(filesDir, "cleanway"))
            val sync = BlocklistSync(
                store = store,
                fetcher = HttpBlocklistFetcher("Cleanway-Android"),
                popularVeto = veto,
                url = BLOCKLIST_URL,
                nowMs = { System.currentTimeMillis() },
                elapsedMs = { android.os.SystemClock.elapsedRealtime() },
                onSwap = { list -> blockList = list },
            )
            blocklistSync = sync
            val loaded = sync.loadFromDisk()
            Log.i(TAG, "blocklist_disk: " + (loaded?.let { "version=${it.version} count=${it.count}" } ?: "none"))
            sync.start(syncExecutor)
        } catch (e: Exception) {
            // Never let the list machinery take the tunnel down: no list means
            // nothing is blocked (and the card says so), not a dead DNS.
            Log.w(TAG, "blocklist_start_error: ${e.message}")
        }
    }

    /**
     * Popular-domain veto (assets/popular_veto.txt, GENERATED by
     * scripts/build_mobile_assets.py: Tranco top-10k minus public suffixes).
     * A listed name whose registrable is here never blocks — the last line of
     * defence against a bad publish.
     */
    private fun loadPopularVeto(): Set<String> = try {
        assets.open("popular_veto.txt").bufferedReader().useLines { lines ->
            lines.map { it.trim().lowercase() }.filter { it.isNotEmpty() && !it.startsWith("#") }.toHashSet()
        }
    } catch (e: Exception) {
        Log.w(TAG, "popular_veto_missing: ${e.message}")
        emptySet()
    }

    /** For the app: what list is loaded and how fresh it is. */
    fun blocklistStatus(): Map<String, Any?> {
        val now = System.currentTimeMillis()
        val elapsed = android.os.SystemClock.elapsedRealtime()
        val l = blockList
        return mapOf(
            "version" to l.version.toDouble(),
            "count" to l.count,
            "revoked" to l.revoked,
            "ageMs" to (if (l.count > 0 || l.revoked) l.ageMs(now, elapsed).toDouble() else null),
            "stale" to (l.count == 0 || l.isStale(now, elapsed)),
            "hasCanary" to l.hasListCanary(),
            "lastError" to blocklistSync?.lastError,
            "lastFetchAt" to (blocklistSync?.lastFetchAtMs ?: 0L).toDouble(),
        )
    }

    /** Re-read the person's allow list into the DNS thread's snapshot. */
    fun reloadAllowed() {
        allowedDomains = try {
            UserAllow.list(this).toHashSet()
        } catch (e: Exception) {
            Log.w(TAG, "allow_reload_error: ${e.message}")
            emptySet()
        }
    }

    /** For the app's pull-to-refresh: fetch now on the sync thread. */
    fun refreshBlocklistAsync() {
        val sync = blocklistSync ?: return
        syncExecutor.execute { runCatching { sync.refreshOnce() } }
    }

    companion object {
        /** Read by CleanwayVpnModule.isRunning() so the UI can reflect real service state. */
        @JvmStatic
        @Volatile
        var isRunning = false

        /** The live service, for the module's blocklist status/refresh calls. */
        @JvmStatic
        @Volatile
        var instance: CleanwayVpnService? = null

        /**
         * Number of canary queries THIS service has answered with NXDOMAIN
         * since the process started.
         *
         * This is the shield's proof of life, and it is positive evidence: the
         * app reads the counter, triggers a lookup of a random subdomain of
         * CANARY_DOMAIN, and asks whether the counter moved. Only a query that
         * actually reached this service can move it, so a dead tunnel, a
         * network with no DNS at all, and a competing VPN all fail to produce
         * proof — and none of them can fabricate it.
         *
         * A COUNTER, not a timestamp: the first version stamped
         * System.currentTimeMillis() and compared it against Date.now() in JS
         * — two independently steppable wall clocks. An NTP correction inside
         * the probe window could validate a stale stamp or fail a fresh one.
         * A delta on a monotonic counter has no clock semantics at all.
         */
        @JvmStatic
        @Volatile
        var canaryAnswerCount = 0L

        private const val CHANNEL_ID = "cleanway_vpn"
        private const val NOTIF_ID = 4711
        private const val TAG = "CleanwayVPN"
        const val ACTION_STOP = "ai.cleanway.VPN_STOP"

        /** Broadcast when the tunnel goes away without the user asking. */
        const val ACTION_VPN_STOPPED = "ai.cleanway.VPN_STOPPED"

        const val EXTRA_REASON = "reason"

        /** Taken away by the system or displaced by another VPN app. */
        const val REASON_REVOKED = "revoked"
        /**
         * Strict Private DNS is on; running would kill DNS for every app.
         * We stepped aside (or refused to start). See PrivateDnsGuard.
         */
        const val REASON_PRIVATE_DNS = "private_dns"
        const val ACTION_DOMAIN_BLOCKED = "ai.cleanway.DOMAIN_BLOCKED"
        const val EXTRA_DOMAIN = "domain"
        const val EXTRA_TIMESTAMP = "ts_ms"
        /** BlockLog.KIND_BLOCKED or KIND_WARNED. */
        const val EXTRA_KIND = "kind"

        private const val VPN_CLIENT_IP = "10.0.0.2"
        private const val VPN_GATEWAY_IP = "10.0.0.1"
        private const val UPSTREAM_DNS_HOST = "1.1.1.1"

        /**
         * Second public resolver, by IP literal. Some networks (and some
         * countries) block 1.1.1.1 specifically; without an alternative the
         * whole chain fell through to DoH on the same blocked address.
         * Quad9 is a non-logging, malware-filtering resolver — a reasonable
         * neighbour for a protection app.
         */
        private const val UPSTREAM_DNS_HOST_2 = "9.9.9.9"
        private const val UPSTREAM_DNS_PORT = 53
        /** The one thing the shield fetches from Cleanway: the blocklist artifact. */
        private const val BLOCKLIST_URL = "https://api.cleanway.ai/api/v1/blocklist/dns"

        /**
         * Count of list-canary queries answered — proof the LOADED LIST is
         * live (the tunnel canary only proves the tunnel). Monotonic; the app
         * compares by delta, like canaryAnswerCount.
         */
        @JvmStatic
        @Volatile
        var listCanaryAnswerCount: Long = 0L

        // Resolved by the app's canary probe to verify filtering is live.
        // Must also exist in public DNS (ops: A/CNAME block-canary.cleanway.ai)
        // so a dead tunnel can't fake a "blocked" result.
        const val CANARY_DOMAIN = "block-canary.cleanway.ai"

        // DoH fallback, addressed by IP literal on purpose.
        //
        // Reaching a DoH endpoint by hostname is a bootstrap trap: resolving it
        // needs DNS, which is exactly what is unavailable on the networks where
        // we need the fallback. Cloudflare's certificate carries 1.1.1.1 in its
        // SAN list, so TLS verifies against the literal and no lookup is
        // required to make the first query.
        //
        // We deliberately do NOT route this through our own gateway. Blocking
        // is decided locally before anything is forwarded, so upstream is only
        // a transport — and measured against the live gateway it was ~3.4s per
        // query versus ~0.04s here, on a path where every page load costs tens
        // of lookups. Sending device DNS through a public resolver also means
        // we never see it, which is a stronger privacy story than promising not
        // to look.
        private const val DOH_URL = "https://1.1.1.1/dns-query"


        /** How often to log the "nothing answered" condition (it can be hot). */
        private const val SERVFAIL_LOG_EVERY = 50L

        /**
         * How many queries we had to answer SERVFAIL because no upstream
         * replied. Surfaced to the app so "the internet feels broken" has a
         * number behind it instead of a guess.
         */
        @JvmStatic
        @Volatile
        var servfailCount: Long = 0L
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
/**
 * What the proxy loop does with one DNS query. Pulled out of the loop as a
 * pure function so the ORDER of the checks — the whole bug — is unit-testable
 * on the JVM without a tunnel.
 *
 * Order matters and is not obvious from the allowlist alone: the canary lives
 * under cleanway.ai, which is a system suffix. Tested after the allowlist, it
 * was classified "system → forward upstream" on every device, the canary
 * branch was unreachable, and the shield could never turn green. Tested first,
 * it works. DomainPolicyTest pins this.
 */
enum class DnsDecision {
    CANARY, LIST_CANARY, BLOCK, FORWARD;

    companion object {
        fun classify(
            normalized: String,
            list: BlockList,
            allowed: Set<String> = emptySet(),
        ): DnsDecision = when {
            normalized == CleanwayVpnService.CANARY_DOMAIN ||
                normalized.endsWith(".${CleanwayVpnService.CANARY_DOMAIN}") -> CANARY
            // Answered only when the loaded list carries the canary line —
            // that absence is exactly how the app learns "no list loaded".
            (normalized == BlockList.LIST_CANARY || normalized.endsWith(".${BlockList.LIST_CANARY}")) &&
                list.hasListCanary() -> LIST_CANARY
            DomainPolicy.isSystemDomain(normalized) -> FORWARD
            // The person said this one is fine. Their call outranks the list:
            // a false positive they cannot undo costs us the whole shield.
            UserAllow.covers(allowed, normalized) != null -> FORWARD
            list.match(normalized) != null -> BLOCK
            else -> FORWARD
        }
    }
}

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
