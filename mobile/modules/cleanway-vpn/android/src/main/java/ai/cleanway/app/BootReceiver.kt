package ai.cleanway.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Re-arms the shield after a reboot.
 *
 * START_STICKY brings the service back after a low-memory kill but not after a
 * reboot, so without this the user has to remember to reopen the app and tap
 * "Turn on" again — which is precisely what the target user will not do.
 *
 * We only restart when the user had it on (see [ShieldPreference]); we never
 * turn protection on by ourselves. VpnService.prepare() consent survives
 * reboots, so no dialog is needed — but if it was revoked, establish() returns
 * null and the service stops itself rather than pretending.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != Intent.ACTION_MY_PACKAGE_REPLACED &&
            action != "android.intent.action.QUICKBOOT_POWERON"
        ) {
            return
        }
        if (!ShieldPreference.isUserEnabled(context)) return

        try {
            val start = Intent(context, CleanwayVpnService::class.java)
            context.startForegroundService(start)
            Log.i(TAG, "restarted_after=$action")
        } catch (e: Exception) {
            // Starting a foreground service from BOOT_COMPLETED is allowed, but
            // an OEM may still refuse. Staying off is correct — the app shows
            // "Set up" and never claims protection it does not have.
            Log.w(TAG, "boot_restart_failed: ${e.message}")
        }
    }

    private companion object {
        const val TAG = "CleanwayBoot"
    }
}
