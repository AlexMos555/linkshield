package ai.cleanway.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Re-arms the shield after a reboot, an app update, and the few other
 * system broadcasts that may still start a foreground service from the
 * background (time zone and language changes — exempt from the Android 12+
 * background-start rules and still delivered to manifest receivers).
 *
 * START_STICKY brings the service back after a low-memory kill but not after a
 * reboot, so without this the user has to remember to reopen the app and tap
 * "Turn on" again — which is precisely what the target user will not do.
 * Between these events [ShieldWatchdog] keeps watch.
 *
 * We only restart when the user had it on (see [ShieldPreference]); we never
 * turn protection on by ourselves, and never after Android took the tunnel
 * away (another VPN app, or the permission withdrawn) — the same
 * [KeepAlivePolicy.decideRearm] the watchdog uses. The user's VPN consent
 * (AppOps) survives reboots; what does not is ConnectivityService's in-memory
 * "prepared package", which is why the service calls VpnService.prepare()
 * itself before establish() — see CleanwayVpnService.startVpn(). If consent
 * was actually revoked, prepare() returns an Intent and the service stops
 * itself rather than pretending.
 *
 * USER_PRESENT (screen unlocked) would be the natural trigger, but Android 8+
 * no longer delivers it to manifest receivers; the watchdog covers that gap.
 *
 * Verified 2026-08-18 on a rebooted emulator: BOOT_COMPLETED → service →
 * tunnel_started → app opens straight to a canary-verified green shield, no
 * tap, no dialog. Note BOOT_COMPLETED is an ordered broadcast and can arrive
 * minutes after boot on a slow device; Always-on VPN closes that gap.
 *
 * Runs in the ":boot" process (see the manifest), where the service's live
 * flag cannot be read. A running tunnel of ours shows up as an active VPN, so
 * the "another VPN is up" rule also keeps a time-zone change from restarting
 * a shield that is already on.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action
        if (action !in TRIGGERS) return
        val decision = KeepAlivePolicy.decideRearm(
            userEnabled = ShieldPreference.isUserEnabled(context),
            running = false,
            stopReason = ShieldPreference.stopReason(context),
            privateDnsStrict = PrivateDnsGuard.strictHostname(context) != null,
            otherVpnActive = KeepAlive.otherVpnActive(context),
            budgetLeft = true,
        )
        // Keep the watchdog armed while waiting can help (a no-op when it
        // already is): the shield starting now may be killed again, and a VPN
        // in the way may go. Not after Android took the tunnel away or under
        // strict Private DNS — see ShieldWatchdog.
        if (decision == KeepAlivePolicy.Rearm.START ||
            decision == KeepAlivePolicy.Rearm.OTHER_VPN ||
            decision == KeepAlivePolicy.Rearm.BUDGET
        ) {
            ShieldWatchdog.ensureScheduled(context)
        }
        if (decision != KeepAlivePolicy.Rearm.START) {
            Log.i(TAG, "not_restarted_after=$action reason=$decision")
            return
        }

        try {
            val start = Intent(context, CleanwayVpnService::class.java)
            context.startForegroundService(start)
            Log.i(TAG, "restarted_after=$action")
        } catch (e: Exception) {
            // Starting a foreground service from these broadcasts is allowed,
            // but an OEM may still refuse. Staying off is correct — the app
            // shows "Protection stopped" and never claims protection it does not have.
            Log.w(TAG, "boot_restart_failed: ${e.message}")
        }
    }

    private companion object {
        const val TAG = "CleanwayBoot"
        val TRIGGERS = setOf(
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED,
            "android.intent.action.QUICKBOOT_POWERON",
            Intent.ACTION_TIMEZONE_CHANGED,
            Intent.ACTION_LOCALE_CHANGED,
        )
    }
}
