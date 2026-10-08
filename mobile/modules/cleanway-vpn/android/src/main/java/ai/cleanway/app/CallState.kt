package ai.cleanway.app

import android.content.Context
import android.media.AudioManager
import android.os.Build
import android.util.Log
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/**
 * Is the person on the phone right now — and when did the last call end?
 *
 * Why this exists: the main way money is lost is a phone call, and every
 * script ends the same way — "switch off the antivirus", "open this site",
 * "install the support app". Cleanway cannot hear the call, cannot see the
 * number and must not ask for the permissions that would (READ_PHONE_STATE,
 * the call-screening role — see the manifest guard in PolicyGuardTest). What
 * it CAN see, with no permission at all, is the phone's audio mode:
 * [AudioManager.MODE_IN_CALL] for a SIM call, [AudioManager.MODE_IN_COMMUNICATION]
 * for a call in WhatsApp/Telegram/MAX, [AudioManager.MODE_RINGTONE] while it
 * rings. That is enough for the stop screen ("you are on the phone — if the
 * caller asks you to switch protection off, it's a scam") and for the
 * post-call notice (CallGuard).
 *
 * Two parts:
 *  - [Machine]: pure, JVM-tested. Turns a stream of audio modes into
 *    "in a call since T", "ringing", "last call ended at T" and the
 *    [AFTER_CALL_WINDOW_MS] window that follows a call ("hang up, I'll call
 *    you back" is the standard move, so the window is long).
 *  - the process-wide watcher: on Android 12+ the system calls
 *    [AudioManager.OnModeChangedListener] on every change; before that the
 *    mode is polled every few seconds, but only while something holds the
 *    watcher ([acquire] / [release]) — the VPN service while the tunnel is
 *    up, the app while its screens are open. Nothing runs otherwise.
 *
 * The last call's start and end are kept in SharedPreferences: the service
 * can be restarted mid-window, and the app can be opened minutes after a
 * call with no JS having seen it end.
 */
object CallState {

    /** How long after a call ends the stop screen and the post-call notice still apply. */
    const val AFTER_CALL_WINDOW_MS = 30L * 60_000

    /** Before Android 12 the mode is polled at this interval while the watcher is held. */
    const val POLL_INTERVAL_MS = 3_000L

    private const val PREFS = "cleanway_call_state"
    private const val KEY_STARTED = "call_started_at"
    private const val KEY_ENDED = "call_ended_at"
    private const val TAG = "CleanwayCall"

    /** What the audio mode says about the phone. */
    enum class Phase { IDLE, RINGING, IN_CALL }

    /** A snapshot for the service, the module and JS. Times are epoch ms; 0 = never. */
    data class Snapshot(
        val phase: Phase,
        val callStartedAt: Long,
        val callEndedAt: Long,
    ) {
        val inCall: Boolean get() = phase == Phase.IN_CALL
        val ringing: Boolean get() = phase == Phase.RINGING

        /** Within [AFTER_CALL_WINDOW_MS] of the last call's end, and not in a call. */
        fun inAfterCallWindow(now: Long): Boolean =
            !inCall && callEndedAt > 0L && now - callEndedAt in 0 until AFTER_CALL_WINDOW_MS

        /** The stop screen applies: on the phone, or a call ended less than 30 minutes ago. */
        fun guardActive(now: Long): Boolean = inCall || inAfterCallWindow(now)

        /** When the after-call window closes (epoch ms), 0 when no call ended yet. */
        fun windowEndsAt(): Long = if (callEndedAt > 0L) callEndedAt + AFTER_CALL_WINDOW_MS else 0L
    }

    /** Pure: the phase an audio mode means. Unknown modes (a vendor's own) read as idle. */
    fun phaseOf(mode: Int): Phase = when (mode) {
        AudioManager.MODE_IN_CALL, AudioManager.MODE_IN_COMMUNICATION -> Phase.IN_CALL
        AudioManager.MODE_RINGTONE -> Phase.RINGING
        else -> Phase.IDLE
    }

    /**
     * Pure state machine. Ringing that is never answered is not a call: the
     * window starts only after a conversation ([Phase.IN_CALL]), which is
     * what a scammer needs.
     */
    class Machine(startedAt: Long = 0L, endedAt: Long = 0L) {
        @Volatile
        var snapshot: Snapshot = Snapshot(Phase.IDLE, startedAt, endedAt)
            private set

        /** Feed a mode; returns the new snapshot when something changed, else null. */
        @Synchronized
        fun onMode(mode: Int, now: Long): Snapshot? {
            val phase = phaseOf(mode)
            val was = snapshot
            if (phase == was.phase) return null
            val next = when {
                phase == Phase.IN_CALL -> was.copy(phase = phase, callStartedAt = now)
                was.phase == Phase.IN_CALL -> was.copy(phase = phase, callEndedAt = now)
                else -> was.copy(phase = phase)
            }
            snapshot = next
            return next
        }
    }

    // ── process-wide watcher ─────────────────────────────────────────

    private val lock = Any()
    private var machine: Machine? = null
    private var holders = 0
    private var listeners: List<(Snapshot) -> Unit> = emptyList()
    private var modeListener: Any? = null
    /** The listener's executor (Android 12+) or the poller (older): one daemon thread while held. */
    private var poller: ScheduledExecutorService? = null
    private var pollTask: ScheduledFuture<*>? = null

    /** The current snapshot, from the watcher when it runs, else from what was stored. */
    fun snapshot(context: Context): Snapshot {
        synchronized(lock) { machine?.let { return it.snapshot } }
        val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return Snapshot(Phase.IDLE, prefs.getLong(KEY_STARTED, 0L), prefs.getLong(KEY_ENDED, 0L))
    }

    /** Be told of every change while [acquire]d. Runs on the audio manager's or the poller's thread. */
    fun addListener(listener: (Snapshot) -> Unit) {
        synchronized(lock) { listeners = listeners + listener }
    }

    fun removeListener(listener: (Snapshot) -> Unit) {
        synchronized(lock) { listeners = listeners - listener }
    }

    /**
     * Start watching (idempotent, reference counted). The first holder wires
     * the listener or the poller; the mode is read once right away so a call
     * already in progress is seen.
     */
    fun acquire(context: Context) {
        val app = context.applicationContext
        // Outside [lock]: attach takes CallGuard's own lock, and CallGuard.evaluate
        // holds that lock while it reads [snapshot] (which takes [lock]) — taking
        // them in the opposite order here could deadlock a block that lands at
        // service start. attach is idempotent, so calling it every time is safe.
        CallGuard.attach(app)
        synchronized(lock) {
            holders += 1
            if (machine != null) return
            val stored = snapshot(app)
            val m = Machine(stored.callStartedAt, stored.callEndedAt)
            machine = m
            try {
                val am = app.getSystemService(Context.AUDIO_SERVICE) as AudioManager
                feed(app, m, am.mode)
                val exec = Executors.newSingleThreadScheduledExecutor { r ->
                    Thread(r, "Cleanway-CallState").apply { isDaemon = true }
                }
                poller = exec
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    val l = AudioManager.OnModeChangedListener { mode -> feed(app, m, mode) }
                    am.addOnModeChangedListener(exec, l)
                    modeListener = l
                } else {
                    pollTask = exec.scheduleWithFixedDelay(
                        { try { feed(app, m, am.mode) } catch (_: Exception) {} },
                        POLL_INTERVAL_MS, POLL_INTERVAL_MS, TimeUnit.MILLISECONDS,
                    )
                }
            } catch (e: Exception) {
                // No call awareness on this phone; everything else works.
                Log.w(TAG, "call_state_unavailable: ${e.javaClass.simpleName}")
            }
        }
    }

    /** The last holder stops the listener or the poller. */
    fun release(context: Context) {
        val app = context.applicationContext
        synchronized(lock) {
            if (holders > 0) holders -= 1
            if (holders > 0 || machine == null) return
            machine = null
            try {
                val am = app.getSystemService(Context.AUDIO_SERVICE) as AudioManager
                val l = modeListener
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && l is AudioManager.OnModeChangedListener) {
                    am.removeOnModeChangedListener(l)
                }
            } catch (_: Exception) {
            }
            modeListener = null
            pollTask?.cancel(false)
            pollTask = null
            poller?.shutdownNow()
            poller = null
        }
    }

    private fun feed(app: Context, m: Machine, mode: Int) {
        val now = System.currentTimeMillis()
        val changed = m.onMode(mode, now) ?: return
        persist(app, changed)
        Log.i(TAG, "phase=${changed.phase}")
        val ls = synchronized(lock) { listeners }
        for (l in ls) {
            try { l(changed) } catch (e: Exception) { Log.w(TAG, "listener_error: ${e.javaClass.simpleName}") }
        }
    }

    private fun persist(app: Context, s: Snapshot) {
        try {
            app.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putLong(KEY_STARTED, s.callStartedAt)
                .putLong(KEY_ENDED, s.callEndedAt)
                .apply()
        } catch (_: Exception) {
        }
    }
}
