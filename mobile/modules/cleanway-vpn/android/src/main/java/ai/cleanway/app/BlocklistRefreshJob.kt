package ai.cleanway.app

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.net.ConnectivityManager
import android.os.SystemClock
import android.util.Log

/**
 * Pure: when the SMS check's list needs a fetch of its own. JVM-tested in
 * ListRefreshPolicyTest.
 *
 * The list used to be refreshed only by the running network shield (the VPN
 * service and its alarm). The SMS check reads the same list with the shield
 * off — often the ONLY shield on, for someone who never wanted a VPN — and
 * would have judged links against whatever was synced the day the shield was
 * last on. So while the SMS check is on, a periodic job keeps the list
 * fresh, and stands aside whenever the shield is running and owns it.
 */
object ListRefreshPolicy {
    enum class Action {
        /** The network shield runs: it refreshes the list itself on its own alarm. */
        SKIP_SHIELD_OWNS_LIST,
        /** Fetched recently enough — by the shield before it stopped, or the last run. */
        SKIP_FRESH,
        FETCH,
    }

    /** Same cadence as the shield's (SyncPolicy.REFRESH_MS): six hours. */
    const val PERIOD_MS = SyncPolicy.REFRESH_MS
    /** Let the system batch the run within the last hour of each period. */
    const val FLEX_MS = 60L * 60 * 1000
    /** First retry after a failed fetch; the system backs off exponentially from there. */
    const val BACKOFF_MS = 5L * 60 * 1000

    /** The periodic job exists exactly while this is true. */
    fun shouldSchedule(supported: Boolean, smsCheckOn: Boolean): Boolean = supported && smsCheckOn

    /**
     * On each run. A list stamped in the future (negative age: the clock was
     * set back) is fetched, not trusted as fresh — otherwise it would stay
     * "fresh" until the clock caught up.
     */
    fun onRun(shieldRunning: Boolean, storedAgeMs: Long?): Action = when {
        shieldRunning -> Action.SKIP_SHIELD_OWNS_LIST
        storedAgeMs != null && storedAgeMs in 0 until PERIOD_MS / 2 -> Action.SKIP_FRESH
        else -> Action.FETCH
    }

    /** When the SMS check is switched on: fetch at once if there is no list or it is not fresh. */
    fun fetchNowOnEnable(storedAgeMs: Long?): Boolean =
        storedAgeMs == null || storedAgeMs < 0 || storedAgeMs >= PERIOD_MS / 2

    /**
     * Ask the system to retry sooner only when the fetch FAILED. A fetch
     * skipped on a metered network (see SyncPolicy) is a decision, not a
     * failure: retrying it would only burn battery until the next period.
     */
    fun wantsRetry(ok: Boolean, consecutiveFailures: Int): Boolean = !ok && consecutiveFailures > 0

    /**
     * A delta that did not apply leaves the sync without a base version:
     * fetch the list in full right away, in the same run. Each run builds a
     * fresh sync from the file on disk, so leaving it to the next run would
     * ask for the same delta from the same base, and fail the same way, for
     * as long as the SMS check is on.
     */
    fun refetchInFull(ok: Boolean, hadBase: Boolean, hasBaseNow: Boolean): Boolean = !ok && hadBase && !hasBaseNow
}

/**
 * Keeps the list fresh for the SMS check while the network shield is off
 * (see [ListRefreshPolicy]). Declared, like SmsReceiver, only in the RuStore
 * manifest overlay (mobile/plugins/withRustoreVariant.js), and in the main
 * process: the shield's state lives there, and the two syncs share
 * BlocklistStore's in-process write lock.
 *
 * Same BlocklistSync as the shield — ETag, 304, deltas from the version on
 * disk, the publisher's sha256, atomic writes — so a refresh here costs what
 * the shield's does (a few KB of changes). It fetches the list and nothing
 * else: no SMS, no host, nothing about the person is sent.
 */
class BlocklistRefreshJob : JobService() {
    @Volatile private var worker: Thread? = null

    /**
     * Everything, the decision included, runs on a worker: onStartJob is
     * called on the main thread, and even the small meta read is disk I/O.
     */
    override fun onStartJob(params: JobParameters): Boolean {
        val thread = Thread({
            val retry = try {
                runOnce()
            } catch (e: Exception) {
                Log.w(TAG, "list_job_failed: ${e.javaClass.simpleName}")
                true
            }
            jobFinished(params, retry)
        }, "Cleanway-ListJob")
        worker = thread
        thread.start()
        return true
    }

    /** The system took the job's network or time away: stop, and run it again later. */
    override fun onStopJob(params: JobParameters): Boolean {
        worker?.interrupt()
        return true
    }

    /** Decide, then fetch when it is needed. Returns whether the system should retry sooner. */
    private fun runOnce(): Boolean {
        val action = ListRefreshPolicy.onRun(CleanwayVpnService.isRunning, ListRefreshJobs.storedAgeMs(this))
        if (action != ListRefreshPolicy.Action.FETCH) {
            Log.i(TAG, "list_job_skipped: $action")
            return false
        }
        val sync = newSync()
        // The version on disk is the base a delta applies to.
        sync.loadFromDisk()
        val hadBase = sync.hasBaseVersion
        var ok = sync.refreshOnce()
        if (ListRefreshPolicy.refetchInFull(ok, hadBase, sync.hasBaseVersion)) ok = sync.refreshOnce()
        return ListRefreshPolicy.wantsRetry(ok, sync.consecutiveFailures)
    }

    private fun newSync() = BlocklistSync(
        store = BlocklistStore.of(filesDir),
        fetcher = HttpBlocklistFetcher("Cleanway-Android"),
        popularVeto = BlocklistHolder.readNameAsset(this, "popular_veto.txt") ?: emptySet(),
        sharedSuffixes = BlocklistHolder.readNameAsset(this, "shared_suffixes.txt") ?: emptySet(),
        url = CleanwayVpnService.BLOCKLIST_URL,
        nowMs = { System.currentTimeMillis() },
        elapsedMs = { SystemClock.elapsedRealtime() },
        // Nothing to swap into: the SMS check and the link guard read the
        // file (BlocklistHolder), keyed by its fetch stamp.
        onSwap = {},
        isMetered = {
            try {
                (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager).isActiveNetworkMetered
            } catch (e: Exception) {
                false
            }
        },
    )

    private companion object {
        const val TAG = "CleanwayBlocklist"
    }
}

/** Schedules and cancels [BlocklistRefreshJob]. Main process (SmsShield). */
object ListRefreshJobs {
    private const val TAG = "CleanwayBlocklist"
    /** Near the module's other request codes (0x7A11-0x7A13); unique among the app's jobs. */
    private const val PERIODIC_JOB_ID = 0x7A14
    private const val NOW_JOB_ID = 0x7A15

    /** Age of the list on disk by its fetch stamp, or null when none is stored. Reads only the small meta file. */
    fun storedAgeMs(context: Context, now: Long = System.currentTimeMillis()): Long? =
        BlocklistStore.of(context.filesDir).fetchedAtMs()?.let { now - it }

    /**
     * Make the jobs match [wanted] (ListRefreshPolicy.shouldSchedule): arm
     * them, or cancel what is left — e.g. after the SMS check was turned off,
     * or this APK replaced the RuStore one and no longer has the job service.
     */
    fun sync(context: Context, wanted: Boolean) {
        if (wanted) ensureScheduled(context) else cancel(context)
    }

    /**
     * The periodic job (persisted: it survives reboots), and a one-off fetch
     * as soon as there is a network when the list is missing or old.
     * Idempotent: an existing periodic job is left as it is, so reopening the
     * app never pushes the next refresh further away.
     */
    fun ensureScheduled(context: Context) {
        val scheduler = scheduler(context) ?: return
        val component = ComponentName(context, BlocklistRefreshJob::class.java)
        try {
            if (scheduler.getPendingJob(PERIODIC_JOB_ID) == null) {
                scheduler.schedule(
                    JobInfo.Builder(PERIODIC_JOB_ID, component)
                        .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                        .setPeriodic(ListRefreshPolicy.PERIOD_MS, ListRefreshPolicy.FLEX_MS)
                        .setBackoffCriteria(ListRefreshPolicy.BACKOFF_MS, JobInfo.BACKOFF_POLICY_EXPONENTIAL)
                        .setPersisted(true)
                        .build()
                )
            }
            if (ListRefreshPolicy.fetchNowOnEnable(storedAgeMs(context)) && scheduler.getPendingJob(NOW_JOB_ID) == null) {
                scheduler.schedule(
                    JobInfo.Builder(NOW_JOB_ID, component)
                        .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                        .setBackoffCriteria(ListRefreshPolicy.BACKOFF_MS, JobInfo.BACKOFF_POLICY_EXPONENTIAL)
                        .build()
                )
            }
        } catch (e: Exception) {
            // The browser APK does not declare the job service: schedule() throws.
            Log.w(TAG, "list_job_schedule_failed: ${e.javaClass.simpleName}")
        }
    }

    fun cancel(context: Context) {
        val scheduler = scheduler(context) ?: return
        try {
            scheduler.cancel(PERIODIC_JOB_ID)
            scheduler.cancel(NOW_JOB_ID)
        } catch (e: Exception) {
            Log.w(TAG, "list_job_cancel_failed: ${e.javaClass.simpleName}")
        }
    }

    private fun scheduler(context: Context): JobScheduler? =
        context.getSystemService(Context.JOB_SCHEDULER_SERVICE) as? JobScheduler
}
