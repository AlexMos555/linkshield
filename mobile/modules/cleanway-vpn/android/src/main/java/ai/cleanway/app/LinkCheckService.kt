package ai.cleanway.app

import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.util.Log
import java.util.concurrent.Executors

/**
 * Checks, in the background, a link the link guard already let open.
 *
 * This used to run inside the VPN service, so with the "All apps" shield off
 * a tapped link was never checked at all — and it gave the server 5 s, so a
 * first check (often 10 s) timed out and a scam page that had opened got
 * neither a warning nor a line in History (report #3). Now:
 *
 *  - it runs whether or not the shield is on: this plain, short-lived service
 *    exists only while a check is in flight;
 *  - it waits up to ~12 s and retries a timeout once (LinkCheckRunner);
 *  - whenever the answer arrives, a warning is recorded in History and shown
 *    as a notification — late is still worth saying;
 *  - it warns on "caution" when the ML model is sure, never on an older
 *    server's heuristics-only "dangerous" (that is how real banks got called
 *    scams), and asks the DNS shield to block the site only when a threat
 *    feed listed it (LinkVerdictPolicy).
 *
 * Only the host leaves the phone, with the install number (InstallId).
 */
class LinkCheckService : Service() {
    private val executor = Executors.newSingleThreadExecutor { r ->
        Thread(r, "Cleanway-LinkCheck").apply { isDaemon = true }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val host = HostNames.normalize(intent?.getStringExtra(EXTRA_HOST))
        if (host == null) {
            stopSelf(startId)
            return START_NOT_STICKY
        }
        executor.execute {
            try {
                LinkCheck.run(applicationContext, host)
            } finally {
                // Stops only once the newest request is done.
                stopSelf(startId)
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        executor.shutdown()
        super.onDestroy()
    }

    companion object {
        const val EXTRA_HOST = "host"

        /**
         * Check [host] in the background. The link guard calls this while its
         * own activity is on screen, so starting the service is allowed; if an
         * OEM refuses anyway, the check still runs on a thread of this process
         * rather than not at all.
         */
        fun request(context: Context, host: String) {
            try {
                context.startService(Intent(context, LinkCheckService::class.java).putExtra(EXTRA_HOST, host))
            } catch (e: Exception) {
                Log.w(LinkCheck.TAG, "link_check_service_refused: ${e.javaClass.simpleName}")
                val app = context.applicationContext
                HostNames.normalize(host)?.let { h ->
                    Thread({ LinkCheck.run(app, h) }, "Cleanway-LinkCheck").apply { isDaemon = true }.start()
                }
            }
        }
    }
}

/** The check itself, shared by the service and its fallback thread. Blocks: call off the main thread. */
object LinkCheck {
    const val TAG = "CleanwayLinkGuard"
    private const val API_BASE = "https://api.cleanway.ai"

    fun run(context: Context, host: String, fetcher: CheckFetcher = HttpCheckFetcher(API_BASE) { installId(context) }) {
        try {
            if (!worthChecking(context, host)) return
            val answer = LinkCheckRunner.run(host, fetcher) ?: return
            when (LinkVerdictPolicy.decide(answer)) {
                LinkAction.NONE -> Unit
                LinkAction.WARN -> warn(context, host, answer.level)
                LinkAction.WARN_AND_BLOCK -> {
                    CleanwayVpnService.instance?.takeIf { CleanwayVpnService.isRunning }?.addDynamicBlock(host)
                    warn(context, host, answer.level)
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "link_check_error: ${e.javaClass.simpleName}")
        }
    }

    /** A system name, a site the person allowed, or one already stopped needs no server check. */
    private fun worthChecking(context: Context, host: String): Boolean {
        if (DomainPolicy.isSystemDomain(host)) return false
        val allowed = BlocklistHolder.allowed(context)
        if (UserAllow.covers(allowed, host) != null) return false
        if (LinkPolicy.listedSuffix(host, BlocklistHolder.current(context), allowed) != null) return false
        return CleanwayVpnService.instance?.isDynamicBlocked(host) != true
    }

    /**
     * The site is (probably) open already: say so now, and keep it in History
     * — a notification can be swiped away, the History entry stays. How loud
     * follows the server's [level]: "dangerous" pops up, "caution" waits in
     * the shade (BlockNotifier.severityOf).
     */
    private fun warn(context: Context, host: String, level: String) {
        val now = System.currentTimeMillis()
        val isNew = try {
            BlockLog.record(context, host, now, BlockLog.KIND_WARNED, BlockLog.SOURCE_LINK)
        } catch (e: Exception) {
            Log.w(TAG, "block_log_error: ${e.javaClass.simpleName}")
            true
        }
        BlockNotifier.notify(
            context, host, BlockLog.KIND_WARNED, now, BlockNotifier.severityOf(BlockLog.KIND_WARNED, level),
        )
        Log.i(TAG, "link_check_warned")
        if (!isNew) return
        CallGuard.noteEvent(context, CallGuard.EVENT_SITE_WARNED, now)
        try {
            context.sendBroadcast(
                Intent(CleanwayVpnService.ACTION_DOMAIN_BLOCKED)
                    .setPackage(context.packageName)
                    .putExtra(CleanwayVpnService.EXTRA_DOMAIN, host)
                    .putExtra(CleanwayVpnService.EXTRA_TIMESTAMP, now)
                    .putExtra(CleanwayVpnService.EXTRA_KIND, BlockLog.KIND_WARNED),
            )
        } catch (_: Exception) {
        }
    }

    private fun installId(context: Context): String? = try {
        InstallId.get(context)
    } catch (_: Exception) {
        null
    }
}
