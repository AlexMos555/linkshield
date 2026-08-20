package ai.cleanway.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Woken by [BlocklistAlarm] to refresh the blocklist on the wall-clock cadence.
 *
 * It does NOT do the fetch itself (a receiver has ~10s and no access to the
 * service's loaded list/store). It pokes the already-running VPN foreground
 * service, which owns the sync and reschedules the next alarm. If the service
 * is not running the shield is off, so there is nothing to keep fresh — we do
 * nothing rather than cold-start a tunnel the user did not ask for.
 */
class BlocklistRefreshReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != BlocklistAlarm.ACTION_REFRESH) return
        if (!CleanwayVpnService.isRunning) return
        try {
            context.startService(
                Intent(context, CleanwayVpnService::class.java).apply {
                    action = CleanwayVpnService.ACTION_REFRESH_BLOCKLIST
                }
            )
        } catch (e: Exception) {
            Log.w("CleanwayBlocklist", "refresh_receiver_start_failed: ${e.message}")
        }
    }
}
