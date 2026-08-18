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
 * turn protection on by ourselves. The user's VPN consent (AppOps) survives
 * reboots; what does not is ConnectivityService's in-memory "prepared package",
 * which is why the service calls VpnService.prepare() itself before
 * establish() — see CleanwayVpnService.startVpn(). If consent was actually
 * revoked, prepare() returns an Intent and the service stops itself rather
 * than pretending.
 *
 * Verified 2026-08-18 on a rebooted emulator: BOOT_COMPLETED → service →
 * tunnel_started → app opens straight to a canary-verified green shield, no
 * tap, no dialog. Note BOOT_COMPLETED is an ordered broadcast and can arrive
 * minutes after boot on a slow device; Always-on VPN closes that gap.
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
