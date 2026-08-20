package ai.cleanway.app

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.SystemClock
import android.util.Log

/**
 * Wall-clock heartbeat that keeps the blocklist fresh even in Doze.
 *
 * The in-process ScheduledExecutorService measures its delay with
 * System.nanoTime(), which does NOT advance while the CPU is suspended in deep
 * Doze — so on an idle phone (screen off for hours, app never opened: exactly
 * the grandma case the shield is for) a "refresh in 6h" task stretches to
 * whenever the device next wakes on its own. The whole delta-update work
 * exists so those phones stay current; without a wake-based schedule it never
 * reaches them.
 *
 * AlarmManager.setAndAllowWhileIdle fires on the RTC wall clock and is allowed
 * to run once per app during a Doze window (~every 9+ min the OS permits, then
 * it batches), which is far finer than our 6h cadence needs. It wakes the
 * device, delivers to [BlocklistRefreshReceiver], which pokes the already-
 * running VPN service to run one fetch and arm the next alarm.
 *
 * This is a backstop, not the only path: the service also refreshes on start
 * (reboot, first launch) and the app refreshes on foreground. Belt and
 * suspenders against the OEMs that kill either mechanism.
 */
object BlocklistAlarm {
    private const val TAG = "CleanwayBlocklist"
    private const val REQUEST_CODE = 0x7A12
    const val ACTION_REFRESH = "ai.cleanway.BLOCKLIST_REFRESH"

    private fun pendingIntent(context: Context): PendingIntent {
        val intent = Intent(context, BlocklistRefreshReceiver::class.java).apply {
            action = ACTION_REFRESH
            setPackage(context.packageName)
        }
        var flags = PendingIntent.FLAG_UPDATE_CURRENT
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) flags = flags or PendingIntent.FLAG_IMMUTABLE
        return PendingIntent.getBroadcast(context, REQUEST_CODE, intent, flags)
    }

    /** Arm the next refresh [delayMs] from now, surviving Doze. */
    fun schedule(context: Context, delayMs: Long) {
        val am = context.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: return
        val triggerAt = System.currentTimeMillis() + delayMs.coerceAtLeast(60_000L)
        try {
            // Inexact-while-idle: we do NOT need second precision, and an exact
            // alarm would need a special permission on Android 12+ and cost
            // more battery. This still fires within the OS's Doze window.
            am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, triggerAt, pendingIntent(context))
            Log.i(TAG, "alarm_scheduled in ${delayMs / 60_000}min")
        } catch (e: Exception) {
            Log.w(TAG, "alarm_schedule_failed: ${e.message}")
        }
    }

    fun cancel(context: Context) {
        val am = context.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: return
        try { am.cancel(pendingIntent(context)) } catch (_: Exception) {}
    }
}
