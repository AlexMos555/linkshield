package ai.cleanway.app

import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import android.util.Log

/**
 * The Android half of "keep protection on after the app is closed": what the
 * phone's battery settings say about us, and the settings screens that change
 * them. The decisions are [KeepAlivePolicy] (JVM-tested).
 *
 * Nothing here changes a setting by itself. Every function opens a screen
 * the person acts on, or reads a state.
 */
internal object KeepAlive {

    private const val TAG = "CleanwayKeepAlive"

    /**
     * True when Android's battery optimisation leaves this app alone
     * ("Unrestricted" / "Don't optimise"). That one switch does two things for
     * the shield: Doze and App Standby stop deferring its watchdog, and — a
     * documented exemption from the Android 12+ background-start rules — a
     * foreground service may be started from the background. Many OEM battery
     * managers (Samsung's among them) also honour it.
     */
    fun batteryUnrestricted(context: Context): Boolean {
        val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return false
        return try {
            pm.isIgnoringBatteryOptimizations(context.packageName)
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Ask Android to stop optimising this app's battery use. Opens, in order:
     *  1. the system's one-question dialog for this app
     *     (ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, needs the normal
     *     permission REQUEST_IGNORE_BATTERY_OPTIMIZATIONS — Play allows it for
     *     a "safety app" whose core function battery optimisation breaks; see
     *     docs/MOBILE_AUTO_PROTECTION.md "Keeping the shield alive");
     *  2. the list of all apps' battery optimisation, where some OEMs send
     *     that request instead (a few remove the dialog altogether);
     *  3. this app's page in Settings (App info → Battery).
     * Returns false only when none of them could be opened.
     */
    fun requestBatteryExemption(context: Context): Boolean {
        if (batteryUnrestricted(context)) return true
        val pkg = context.packageName
        return start(
            context,
            Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$pkg")),
            Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS),
            appDetails(context),
        )
    }

    /** The phone maker whose battery manager needs its own step, or null on stock-like Android. */
    fun oemFamily(): KeepAlivePolicy.OemFamily? = KeepAlivePolicy.oemFamily(Build.MANUFACTURER, Build.BRAND)

    /**
     * Open the phone maker's own "let this app run in the background" screen
     * (Samsung's battery page, MIUI Autostart, Huawei App launch, …), falling
     * back to this app's page in Settings. These screens are not public API
     * and move between firmware versions, so each is tried in turn; a
     * missing or non-exported one throws and the next is tried. False only
     * when not even App info could be opened.
     */
    fun openOemBackgroundSettings(context: Context): Boolean {
        val family = oemFamily()
        val oem = family?.let { KeepAlivePolicy.oemTargets(it) }.orEmpty().map { target ->
            Intent().setComponent(ComponentName(target.pkg, target.cls)).apply {
                if (target.packageExtras) {
                    putExtra("package_name", context.packageName)
                    putExtra("package_label", appLabel(context))
                }
            }
        }
        return start(context, *(oem + appDetails(context)).toTypedArray())
    }

    /**
     * Is a VPN other than ours up right now? Seen through the networks this
     * app can see: a VPN that applies to us shows up as a network with
     * TRANSPORT_VPN. Called only while our own tunnel is down, so any VPN
     * network found belongs to someone else. A VPN configured to exclude
     * this app is invisible here — a gap the TAKEN_AWAY rule mostly covers,
     * since that VPN taking the slot will have revoked ours.
     */
    @Suppress("DEPRECATION") // allNetworks: the one call that lists every network on API 24–36.
    fun otherVpnActive(context: Context): Boolean {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return false
        return try {
            cm.allNetworks.any { n -> cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true }
        } catch (e: Exception) {
            // Unknown is not "another VPN": the TAKEN_AWAY rule still guards the common case.
            Log.w(TAG, "vpn_scan_failed: ${e.javaClass.simpleName}")
            false
        }
    }

    private fun appDetails(context: Context): Intent =
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null))

    private fun appLabel(context: Context): String = try {
        context.packageManager.getApplicationLabel(context.applicationInfo).toString()
    } catch (e: Exception) {
        "Cleanway"
    }

    /** Start the first intent that opens. Never throws. */
    private fun start(context: Context, vararg intents: Intent): Boolean {
        for (intent in intents) {
            try {
                context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                return true
            } catch (e: ActivityNotFoundException) {
                continue
            } catch (e: SecurityException) {
                // An OEM activity that exists but is not exported to us.
                continue
            } catch (e: Exception) {
                Log.w(TAG, "settings_open_failed: ${e.javaClass.simpleName}")
                continue
            }
        }
        return false
    }
}
