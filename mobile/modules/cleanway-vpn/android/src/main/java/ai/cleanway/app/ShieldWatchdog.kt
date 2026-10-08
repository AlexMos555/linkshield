package ai.cleanway.app

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import java.io.File

/**
 * Brings the shield back when something other than the person stopped it.
 *
 * START_STICKY asks Android to restart a killed service, but OEM battery
 * managers (Samsung, Xiaomi, Oppo, vivo, Huawei) kill the whole process and
 * many of them do not honour it — the tunnel was simply gone until the person
 * happened to open the app, and the target user does not. This job looks
 * every ~15 minutes (JobScheduler's floor; Doze defers it to maintenance
 * windows) and re-arms the service when [KeepAlivePolicy.decideRearm] says so.
 *
 * Never without consent: it acts only while ShieldPreference says the person
 * last turned protection ON, never after Android took the tunnel away
 * (another VPN, or the permission withdrawn — prepare() would silently take
 * the slot back from that other VPN), and the service still re-checks the
 * VPN permission itself (prepare()) and stops if it is gone.
 *
 * Background-start rules (Android 12+): a foreground service may not be
 * started from the background, with exemptions. Two cover us here — the app
 * holds the VPN permission (AppOps OP_ACTIVATE_VPN; ActivityManager logs
 * "Background started FGS: Allowed … code:OP_ACTIVATE_VPN"), and, once the
 * person has allowed it, the battery-optimisation exemption (documented).
 * If a start is refused anyway, the exception is logged and the next run
 * tries again; nothing crashes. Android 14's FGS types: ours is specialUse,
 * which has no runtime prerequisite; Android 15's BOOT_COMPLETED limits do not
 * include specialUse.
 *
 * What it cannot do: a FORCE-STOP (Settings → Force stop, and the "deep
 * sleep" of several OEM managers) cancels this job, every alarm and every
 * broadcast to the app until it is opened again. That is Android's
 * guarantee to the person, not something an app may work around; the battery
 * and OEM steps in the app's "Keep protection on" list are what keep a phone
 * from doing it, and Always-on VPN is restarted by the system itself.
 *
 * Runs in the main process (no android:process): when the service is up the
 * process is alive anyway, and when it is not, starting the service needs
 * that process. The job is scheduled when the tunnel comes up and cancelled
 * when the person turns protection off — and whenever waiting cannot help
 * (Android took the tunnel away, strict Private DNS, no VPN permission), so a
 * phone in one of those states is not woken every 15 minutes for nothing.
 */
class ShieldWatchdog : JobService() {

    override fun onStartJob(params: JobParameters?): Boolean {
        rearm(applicationContext, "watchdog")
        // Synchronous: the decision is a few file reads; the service does the rest.
        return false
    }

    override fun onStopJob(params: JobParameters?): Boolean = false

    companion object {
        private const val TAG = "CleanwayWatchdog"
        private const val JOB_ID = 0x7A14
        private const val PERIOD_MS = 15L * 60_000
        private const val FLEX_MS = 5L * 60_000
        private const val HISTORY_FILE = "cleanway_rearm_history"

        /**
         * Make sure the job exists. Idempotent and cheap: a pending job is left
         * alone, so its period is not reset every time the tunnel comes up.
         * Persisted, so it survives a reboot (RECEIVE_BOOT_COMPLETED is
         * already held for BootReceiver).
         */
        fun ensureScheduled(context: Context) {
            val js = context.getSystemService(Context.JOB_SCHEDULER_SERVICE) as? JobScheduler ?: return
            try {
                if (js.getPendingJob(JOB_ID) != null) return
                val job = JobInfo.Builder(JOB_ID, ComponentName(context, ShieldWatchdog::class.java))
                    .setPeriodic(PERIOD_MS, FLEX_MS)
                    .setPersisted(true)
                    .build()
                val result = js.schedule(job)
                Log.i(TAG, if (result == JobScheduler.RESULT_SUCCESS) "watchdog_scheduled" else "watchdog_schedule_refused")
            } catch (e: Exception) {
                Log.w(TAG, "watchdog_schedule_failed: ${e.javaClass.simpleName}")
            }
        }

        /** The person turned protection off: nothing may bring it back. */
        fun cancel(context: Context) {
            val js = context.getSystemService(Context.JOB_SCHEDULER_SERVICE) as? JobScheduler ?: return
            try { js.cancel(JOB_ID) } catch (_: Exception) {}
        }

        /**
         * Start the shield if [KeepAlivePolicy.decideRearm] says so and the VPN
         * permission is still granted. Main process only (reads the service's
         * live flag and the restart budget).
         */
        internal fun rearm(context: Context, trigger: String): KeepAlivePolicy.Rearm {
            val wanted = ShieldPreference.isUserEnabled(context)
            val running = CleanwayVpnService.isRunning
            // Cheap checks first; the ConnectivityManager scan only when it can matter.
            val pre = KeepAlivePolicy.decideRearm(wanted, running, null, false, false, true)
            if (pre != KeepAlivePolicy.Rearm.START) {
                if (pre == KeepAlivePolicy.Rearm.NOT_WANTED) cancel(context)
                return pre
            }
            val historyFile = File(context.noBackupFilesDir, HISTORY_FILE)
            val history = readHistory(historyFile)
            val now = System.currentTimeMillis()
            val decision = KeepAlivePolicy.decideRearm(
                userEnabled = wanted,
                running = running,
                stopReason = ShieldPreference.stopReason(context),
                privateDnsStrict = PrivateDnsGuard.strictHostname(context) != null,
                otherVpnActive = KeepAlive.otherVpnActive(context),
                budgetLeft = KeepAlivePolicy.budgetLeft(history, now),
            )
            if (decision != KeepAlivePolicy.Rearm.START) {
                Log.i(TAG, "rearm_skipped trigger=$trigger reason=$decision")
                // Taken away stays taken away until the person turns it on
                // (which schedules the job again); no point waking for it.
                // Strict Private DNS is the person's own setting and can stay
                // for months: rather than cold-start the app's process four
                // times an hour to find it unchanged, stop — opening the app
                // after changing it back re-arms at once (the conflict card
                // says to come back).
                if (decision == KeepAlivePolicy.Rearm.TAKEN_AWAY || decision == KeepAlivePolicy.Rearm.PRIVATE_DNS) {
                    cancel(context)
                }
                return decision
            }
            // Last, and only now: prepare() is the one way to ask whether the
            // VPN permission is still granted, and when it is, it also takes
            // the VPN slot — harmless here, since no other VPN is up (checked
            // above) and the service is about to take it anyway. Without the
            // permission it only returns the consent Intent: then we stop, and
            // the person's next "Turn on" asks again. A phone restored from a
            // backup has "protection was on" without the permission — this
            // keeps it from flashing a start-and-stop every few minutes.
            val consented = try {
                VpnService.prepare(context) == null
            } catch (e: Exception) {
                Log.w(TAG, "consent_check_failed: ${e.javaClass.simpleName}")
                false
            }
            if (!consented) {
                Log.i(TAG, "rearm_skipped trigger=$trigger reason=${KeepAlivePolicy.Rearm.NO_CONSENT}")
                cancel(context)
                return KeepAlivePolicy.Rearm.NO_CONSENT
            }
            writeHistory(historyFile, KeepAlivePolicy.recordRearm(history, now))
            try {
                // No START_BY_PERSON action: this is the shield coming back by
                // itself, so a timed pause from before is kept, not ended.
                context.startForegroundService(Intent(context, CleanwayVpnService::class.java))
                Log.i(TAG, "rearmed trigger=$trigger")
            } catch (e: Exception) {
                // ForegroundServiceStartNotAllowedException (Android 12+) if no
                // exemption applied, or an OEM refusing. Next run tries again.
                Log.w(TAG, "rearm_failed trigger=$trigger: ${e.javaClass.simpleName}")
            }
            return decision
        }

        private fun readHistory(file: File): List<Long> = try {
            KeepAlivePolicy.parseHistory(file.takeIf { it.isFile }?.readText())
        } catch (e: Exception) {
            emptyList()
        }

        private fun writeHistory(file: File, history: List<Long>) {
            try {
                file.writeText(KeepAlivePolicy.formatHistory(history))
            } catch (e: Exception) {
                Log.w(TAG, "history_write_failed: ${e.javaClass.simpleName}")
            }
        }
    }
}
