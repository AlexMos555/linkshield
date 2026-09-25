package ai.cleanway.app

import android.app.Activity
import android.app.ActivityManager
import android.app.AppOpsManager
import android.app.NotificationManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Process
import android.provider.Settings
import android.util.Log
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import java.io.File

/**
 * Pure: what can honestly be said about the SMS permission. JVM-tested in
 * SmsShieldTest.
 *
 * Android does not tell an app whether its request was refused by the
 * person or by the system. On Android 15+ an app installed from a browser
 * download or a file (package source 4 or 3) is under "restricted settings":
 * the first SMS request shows "App was denied access" instead of a grant
 * dialog, and until the person allows restricted settings in App info every
 * later request is refused silently. Whether a RuStore install is exempt is
 * not known. So:
 *  - [GRANTED] — the permission is held;
 *  - [NOT_REQUESTED] — we never asked (the restriction, if any, shows only
 *    after a request);
 *  - [DENIED] — refused, and nothing points at the restriction: the person
 *    said no (Android 13/14 never restrict SMS), or a store install on 15+;
 *  - [RESTRICTED_MAYBE] — refused on 15+ where the restriction is likely:
 *    Android's own restriction state reads "dialog shown" or "restricted",
 *    or the install came from a file or a download, or its source is unknown.
 *    "Maybe": no public API says for sure, and OEMs differ.
 */
object SmsPermissionState {
    const val GRANTED = "granted"
    const val DENIED = "denied"
    const val RESTRICTED_MAYBE = "restricted_maybe"
    const val NOT_REQUESTED = "not_requested"

    /** Android 15 (API 35): restricted settings cover the SMS permissions from here on. */
    const val RESTRICTED_FROM_SDK = 35
    private val GUARDED_SOURCES = setOf(3, 4) // PACKAGE_SOURCE_LOCAL_FILE, PACKAGE_SOURCE_DOWNLOADED_FILE

    /**
     * [restrictedMode]: the app's own ACCESS_RESTRICTED_SETTINGS app-op mode
     * (AppOpsManager.MODE_*), or null when it could not be read.
     */
    fun of(
        granted: Boolean,
        asked: Boolean,
        rationale: Boolean,
        sdk: Int,
        packageSource: Int?,
        restrictedMode: Int?,
    ): String {
        if (granted) return GRANTED
        val restrictable = sdk >= RESTRICTED_FROM_SDK
        // IGNORED = the "denied access" dialog was shown: the system refused a request.
        if (restrictable && restrictedMode == AppOpsManager.MODE_IGNORED) return RESTRICTED_MAYBE
        if (rationale) return DENIED
        if (!asked) return NOT_REQUESTED
        if (!restrictable) return DENIED
        return when (restrictedMode) {
            AppOpsManager.MODE_ALLOWED -> DENIED // restricted settings were allowed: the person said no
            AppOpsManager.MODE_ERRORED -> RESTRICTED_MAYBE
            else -> if (packageSource == null || packageSource in GUARDED_SOURCES) RESTRICTED_MAYBE else DENIED
        }
    }
}

/**
 * Pure: which system screen turns the SMS warnings back on. JVM-tested in
 * SmsShieldTest.
 *
 * The screen the person lands on must hold the switch that is off, or they
 * are left looking for it: our channel's page when only the "Dangerous SMS"
 * channel was turned off; otherwise the app's notification page, whose main
 * switch also grants the Android 13+ permission. Before Android 8 there is
 * no notification page to open, only the app's own.
 */
enum class NotificationSettingsTarget {
    CHANNEL, APP_NOTIFICATIONS, APP_DETAILS;

    companion object {
        fun of(sdk: Int, appNotificationsOn: Boolean, channelBlocked: Boolean): NotificationSettingsTarget = when {
            sdk < Build.VERSION_CODES.O -> APP_DETAILS
            appNotificationsOn && channelBlocked -> CHANNEL
            else -> APP_NOTIFICATIONS
        }
    }
}

/**
 * The automatic SMS check's switch and state, for the app (main process).
 *
 * On/off is the SmsReceiver COMPONENT, not a preference the receiver would
 * have to read: disabled, Android never wakes the app for an SMS at all, and
 * the RECEIVE_SMS permission stays granted, so turning the check back on is
 * one tap, not another trip through the permission (and, on Android 15+,
 * the restricted-settings) screens. Declared disabled in the manifest, so
 * nothing is checked until the person turns it on. The system keeps the
 * choice across reboots and updates; uninstalling resets it.
 *
 * While on, BlocklistRefreshJob keeps the list fresh when the network shield
 * is off. Only the RuStore build has the receiver and the job; in the
 * browser APK every call here is a no-op that reports "not supported".
 */
object SmsShield {
    private const val TAG = "CleanwaySms"
    private const val RECEIVE_SMS = AppInstallInfo.RECEIVE_SMS
    /** Hidden op name (API 33+); its mode is the app's restricted-settings state. */
    private const val OPSTR_ACCESS_RESTRICTED_SETTINGS = "android:access_restricted_settings"

    private fun receiver(context: Context) = ComponentName(context.packageName, SmsReceiver::class.java.name)

    /** Marker that the app asked for RECEIVE_SMS once. A file, not a preference: it must not come back from a backup. */
    private fun askedMarker(context: Context) = File(BlocklistStore.dirFor(context.filesDir), "sms-permission-asked")

    fun isEnabled(context: Context): Boolean = try {
        context.packageManager.getComponentEnabledSetting(receiver(context)) ==
            PackageManager.COMPONENT_ENABLED_STATE_ENABLED
    } catch (e: Exception) {
        false
    }

    /**
     * Turn the automatic check on or off. False when this build cannot (the
     * browser APK) or the system refused. Turning on does not ask for any
     * permission; the app does that first ([markPermissionRequested]).
     */
    fun setEnabled(context: Context, enabled: Boolean): Boolean {
        if (!AppInstallInfo.smsAutoSupported(context)) return false
        return try {
            context.packageManager.setComponentEnabledSetting(
                receiver(context),
                if (enabled) PackageManager.COMPONENT_ENABLED_STATE_ENABLED else PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                // Without it Android kills the app to apply the change — the
                // screen the person just tapped on would vanish.
                PackageManager.DONT_KILL_APP,
            )
            if (enabled) SmsNotifier.ensureChannel(context)
            ListRefreshJobs.sync(context, enabled)
            true
        } catch (e: Exception) {
            Log.w(TAG, "sms_toggle_failed: ${e.javaClass.simpleName}")
            false
        }
    }

    /** Remember that the app asked for RECEIVE_SMS — before the dialog shows, so a kill mid-dialog still counts. */
    fun markPermissionRequested(context: Context) {
        try {
            val marker = askedMarker(context)
            marker.parentFile?.mkdirs()
            marker.createNewFile()
        } catch (e: Exception) {
            Log.w(TAG, "sms_asked_mark_failed: ${e.javaClass.simpleName}")
        }
    }

    /**
     * Everything the SMS screen needs to tell the truth, as plain values for
     * the bridge. Also brings the refresh job in line with the switch: re-armed
     * if the system dropped it (a force-stop), cancelled if it outlived the
     * check — so opening the app repairs either.
     */
    fun status(context: Context, activity: Activity?): Map<String, Any?> {
        val supported = AppInstallInfo.smsAutoSupported(context)
        val enabled = supported && isEnabled(context)
        ListRefreshJobs.sync(context, ListRefreshPolicy.shouldSchedule(supported, enabled))
        val log = SmsEventLog.of(context.filesDir).read()
        val rationale = supported && rationale(activity)
        return mapOf(
            "supported" to supported,
            "permission" to if (supported) permission(context, rationale) else SmsPermissionState.NOT_REQUESTED,
            // Android would show its SMS question again (it did before and the
            // person said no once). False after a second no, "don't ask
            // again", a restriction, or an installer that never allowed SMS
            // for this app — then only App info can help.
            "canAskAgain" to rationale,
            "enabled" to enabled,
            "notificationsEnabled" to SmsNotifier.canNotify(context),
            "backgroundRestricted" to backgroundRestricted(context),
            "checkedCount" to log.checked.toDouble(),
            "flaggedCount" to log.flagged.toDouble(),
            "lastCheckedAt" to log.lastCheckedAt.takeIf { it > 0L }?.toDouble(),
            "listAgeMs" to ListRefreshJobs.storedAgeMs(context)?.coerceAtLeast(0L)?.toDouble(),
        )
    }

    /** Newest first, at most [limit]: what History lists. */
    fun recentEvents(context: Context, limit: Int): List<Map<String, Any?>> =
        SmsEventLog.of(context.filesDir).read().events.take(limit.coerceAtLeast(0)).map { it.toWire() }

    /** Open this app's page in system Settings (permissions, "Allow restricted settings", battery). */
    fun openAppDetails(context: Context): Boolean = try {
        context.startActivity(
            Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
        true
    } catch (e: Exception) {
        Log.w(TAG, "app_details_failed: ${e.javaClass.simpleName}")
        false
    }

    /**
     * Open the screen where the SMS warnings can be switched back on
     * ([NotificationSettingsTarget]); the app's page if that one will not open
     * (some OEM builds drop the notification pages).
     */
    fun openNotificationSettings(context: Context): Boolean {
        val target = NotificationSettingsTarget.of(
            sdk = Build.VERSION.SDK_INT,
            appNotificationsOn = NotificationManagerCompat.from(context).areNotificationsEnabled(),
            channelBlocked = channelBlocked(context),
        )
        if (target == NotificationSettingsTarget.APP_DETAILS) return openAppDetails(context)
        val intent = if (target == NotificationSettingsTarget.CHANNEL) {
            Intent(Settings.ACTION_CHANNEL_NOTIFICATION_SETTINGS)
                .putExtra(Settings.EXTRA_CHANNEL_ID, SmsNotifier.CHANNEL_ID)
        } else {
            Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
        }
        return try {
            context.startActivity(
                intent.putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
            true
        } catch (e: Exception) {
            Log.w(TAG, "notification_settings_failed: ${e.javaClass.simpleName}")
            openAppDetails(context)
        }
    }

    /** The person turned the "Dangerous SMS" channel off (it exists once the check was turned on). */
    private fun channelBlocked(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return false
        return try {
            val channel = NotificationManagerCompat.from(context).getNotificationChannel(SmsNotifier.CHANNEL_ID)
            channel != null && channel.importance == NotificationManager.IMPORTANCE_NONE
        } catch (e: Exception) {
            false
        }
    }

    /** Would Android ask again? Needs the app's own screen; without one, "no" (the cautious answer). */
    private fun rationale(activity: Activity?): Boolean = activity != null && try {
        ActivityCompat.shouldShowRequestPermissionRationale(activity, RECEIVE_SMS)
    } catch (e: Exception) {
        false
    }

    private fun permission(context: Context, rationale: Boolean): String {
        val granted = ContextCompat.checkSelfPermission(context, RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED
        val source = try {
            AppInstallInfo.installSource(context).packageSource
        } catch (e: Exception) {
            null
        }
        return SmsPermissionState.of(
            granted = granted,
            asked = askedMarker(context).exists(),
            rationale = rationale,
            sdk = Build.VERSION.SDK_INT,
            packageSource = source,
            restrictedMode = restrictedSettingsMode(context),
        )
    }

    /**
     * The app's own restricted-settings state, where Android lets an app read
     * it: the op is hidden, and a version or OEM without it answers with an
     * exception, which reads as "unknown". Measured on an Android 15 emulator
     * (2026-09-25): after the person allowed restricted settings (the op read
     * "allow" from adb), the app's own read still did not see it — AOSP marks
     * this op read-restricted — so in practice this is null and the state
     * falls back to the install source. The app's guidance covers both ways
     * out (the ⋮ item, and Permissions → SMS) for that reason.
     */
    private fun restrictedSettingsMode(context: Context): Int? {
        if (Build.VERSION.SDK_INT < SmsPermissionState.RESTRICTED_FROM_SDK) return null
        return try {
            val ops = context.getSystemService(AppOpsManager::class.java) ?: return null
            ops.unsafeCheckOpNoThrow(OPSTR_ACCESS_RESTRICTED_SETTINGS, Process.myUid(), context.packageName)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * "Restricted" battery usage (Android 9+): the system may hold back the
     * refresh job and, on some phones, the SMS broadcast itself.
     */
    private fun backgroundRestricted(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return false
        return try {
            (context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager).isBackgroundRestricted
        } catch (e: Exception) {
            false
        }
    }
}
