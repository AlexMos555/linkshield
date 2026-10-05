package ai.cleanway.app

import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.core.app.NotificationCompat
import expo.modules.cleanwayvpn.R
import org.json.JSONArray
import org.json.JSONObject

/**
 * The notice after a call — only when Cleanway saw something.
 *
 * "You were just called, and at the same time Cleanway stopped a dangerous
 * site. If the caller asked for a code, a transfer or an app, it's a scam."
 * The reason is what makes it worth reading: a notice after EVERY call would
 * be swiped away with the important one (warning fatigue is measurable from
 * the second show). So there is no notice after an ordinary call — no event,
 * no noise — and at most one per call.
 *
 * What counts as "something", in this order of weight ([Event]): the shield
 * stopped a site; the link guard warned about a site that had opened; the
 * person checked a message that came back dangerous; the person tried to
 * switch protection off (pause, allow a site, "open anyway") and met the stop
 * screen. A new app install is reserved for a later build.
 *
 * When it fires ([decide], pure):
 *  - an event DURING the call: [AFTER_CALL_DELAY_MS] after the call ends
 *    (the hang-up screen is still on; a minute later she is looking at the
 *    phone) — provided nothing has been said about these events yet;
 *  - an event within [CallState.AFTER_CALL_WINDOW_MS] after the call: at
 *    once, unless a notice for this call already went out.
 *
 * Nothing here ever carries a link or a phone number. The one action is
 * "call a close one" — the number the person saved (CloseContact), dialled
 * through the phone app's own screen, never shown in the text.
 *
 * Events are kept in SharedPreferences (a short ring, [MAX_EVENTS]) so a
 * service restart between the event and the call's end loses nothing.
 */
object CallGuard {
    /** The shield or the link guard stopped a site (BlockLog KIND_BLOCKED). */
    const val EVENT_SITE_BLOCKED = "site_blocked"
    /** The link guard warned about a site that had already opened (KIND_WARNED). */
    const val EVENT_SITE_WARNED = "site_warned"
    /** A message the person checked came back dangerous. */
    const val EVENT_MESSAGE_DANGEROUS = "message_dangerous"
    /** The person tried to pause, allow a site or open one anyway, and saw the stop screen. */
    const val EVENT_PROTECTION_OFF_ASKED = "protection_off_asked"
    /** Reserved: a remote-access app was installed during the call (needs the package list — later). */
    const val EVENT_APP_INSTALLED = "app_installed"

    /** Heaviest first: the notice names the heaviest event of the call. */
    val EVENTS = listOf(
        EVENT_SITE_BLOCKED, EVENT_SITE_WARNED, EVENT_MESSAGE_DANGEROUS, EVENT_PROTECTION_OFF_ASKED, EVENT_APP_INSTALLED,
    )

    /** How long after the call ends the notice about events during it waits. */
    const val AFTER_CALL_DELAY_MS = 60_000L
    const val MAX_EVENTS = 50
    /**
     * The notice's key prefix in the alert budget ([budgetKey]): one key per
     * call, so the 6-hour per-site rule never silences the notice for a
     * second call an hour later ("hang up, I'll call you back") — the 3/hour
     * and 10/day caps still bound it.
     */
    const val ALERT_KEY = "after-call"
    private const val NOTIF_ID = 4712

    private const val PREFS = "cleanway_call_guard"
    private const val KEY_EVENTS = "events"
    /** When the last notice went out; events at or before it are spoken for. */
    private const val KEY_ALERTED_AT = "alerted_at"
    private const val TAG = "CleanwayCall"

    data class Event(val kind: String, val ts: Long)

    /** What to do now (pure, from [decide]). */
    sealed class Decision {
        /** Post the notice naming [reason] (an [EVENTS] kind). */
        data class Alert(val reason: String) : Decision()
        /** Check again after the call ends — events were seen during it. */
        object AfterCall : Decision()
        object Nothing : Decision()
    }

    /**
     * Pure. [events] are what Cleanway saw (any order); [alertedAt] is when
     * the last notice went out (0 = never); [call] is the phone's state now.
     *
     * "During the call" is from its start; "after" is the 30-minute window.
     * A notice consumes the events up to its time, so a second one needs a
     * new event — and inside one after-call window there is at most one:
     * a site an app keeps polling must not become a notice every ten minutes.
     */
    fun decide(events: List<Event>, alertedAt: Long, call: CallState.Snapshot, now: Long): Decision {
        if (call.callStartedAt <= 0L) return Decision.Nothing
        val fresh = events.filter { it.ts > alertedAt && it.ts >= call.callStartedAt && it.ts <= now }
        if (fresh.isEmpty()) return Decision.Nothing
        if (call.inCall) return Decision.AfterCall
        if (!call.inAfterCallWindow(now)) return Decision.Nothing
        // One notice per after-call window.
        if (alertedAt > call.callEndedAt) return Decision.Nothing
        val reason = EVENTS.firstOrNull { kind -> fresh.any { it.kind == kind } } ?: return Decision.Nothing
        return Decision.Alert(reason)
    }

    /**
     * Pure: does an event of [kind] tell [decide] anything it does not know
     * yet? Not when one of the same kind is already stored since the call
     * began and since the last notice — then storing a repeat (an app polling
     * a blocked host, one per lookup) changes nothing. Asked here, not of
     * BlockLog's "is it new": BlockLog coalesces a site tried again within
     * ten minutes, and a site first stopped just BEFORE the call and tried
     * again during it is new for the call.
     */
    fun isNewForCall(events: List<Event>, kind: String, alertedAt: Long, callStartedAt: Long): Boolean =
        kind in EVENTS && events.none { it.kind == kind && it.ts > alertedAt && it.ts >= callStartedAt }

    /**
     * Pure: after a process restart, when to run the after-call check the
     * hang-up scheduled ([AFTER_CALL_DELAY_MS] after it) — that runnable died
     * with the process. Null when there is nothing to pick up: on the phone
     * (the hang-up will schedule it), no ended call in the stored state, or
     * its window is over. 0 = at once. Running it twice is harmless:
     * [decide] allows one notice per call.
     */
    fun resumeDelay(call: CallState.Snapshot, now: Long): Long? {
        if (call.inCall || call.callEndedAt <= 0L || call.callEndedAt < call.callStartedAt) return null
        if (!call.inAfterCallWindow(now)) return null
        return maxOf(0L, call.callEndedAt + AFTER_CALL_DELAY_MS - now)
    }

    /** How the notice goes out under the budget's verdict ([route], pure). */
    enum class Route { HEADS_UP, SILENT, SUMMARY, NONE }

    /**
     * Pure. Over the cap the after-call notice is one more "N more
     * suspicious" in the single collapsed summary, like any other danger —
     * not a second full notice beside it.
     */
    fun route(verdict: AlertBudget.Verdict): Route = when (verdict) {
        AlertBudget.Verdict.HEADS_UP -> Route.HEADS_UP
        AlertBudget.Verdict.SILENT -> Route.SILENT
        is AlertBudget.Verdict.SUMMARY -> Route.SUMMARY
        AlertBudget.Verdict.DROP -> Route.NONE
    }

    /** Pure: the budget key of the notice for the call that began at [callStartedAt]. */
    fun budgetKey(callStartedAt: Long): String = "$ALERT_KEY:$callStartedAt"

    /** Pure: the reason line for a notice ([EVENTS] kind → string resource). */
    fun reasonRes(kind: String): Int = when (kind) {
        EVENT_SITE_BLOCKED -> R.string.after_call_reason_site_blocked
        EVENT_SITE_WARNED -> R.string.after_call_reason_site_warned
        EVENT_MESSAGE_DANGEROUS -> R.string.after_call_reason_message
        EVENT_PROTECTION_OFF_ASKED -> R.string.after_call_reason_protection_off
        else -> R.string.after_call_reason_app_installed
    }

    /** Pure: where a tap on the notice lands — the "you were called" screen in the app. */
    const val DEEP_LINK = "cleanway:///call-guard?after=1"

    // ── persistence (pure helpers, JVM-tested) ───────────────────────

    fun parseEvents(json: String?): List<Event> {
        if (json.isNullOrBlank()) return emptyList()
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).mapNotNull { i ->
                val o = arr.optJSONObject(i) ?: return@mapNotNull null
                val k = o.optString("k")
                if (k !in EVENTS) return@mapNotNull null
                Event(k, o.optLong("t"))
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    /** Newest first, capped; an unknown kind is dropped rather than kept as garbage. */
    fun appendJson(json: String?, event: Event, cap: Int = MAX_EVENTS): String {
        val next = if (event.kind in EVENTS) listOf(event) + parseEvents(json) else parseEvents(json)
        val arr = JSONArray()
        next.take(cap).forEach { arr.put(JSONObject().put("k", it.kind).put("t", it.ts)) }
        return arr.toString()
    }

    // ── runtime ──────────────────────────────────────────────────────

    private val lock = Any()
    private var attached = false
    // Lazy: the pure functions above are JVM-tested, where there is no Looper.
    private val main by lazy { Handler(Looper.getMainLooper()) }

    /** Called once by CallState when the watcher starts: follow calls from then on. */
    internal fun attach(app: Context) {
        synchronized(lock) {
            if (attached) return
            attached = true
        }
        CallState.addListener { s ->
            // The call ended: a minute later, say what happened during it.
            if (!s.inCall && s.callEndedAt > 0L) {
                main.postDelayed({ evaluate(app) }, AFTER_CALL_DELAY_MS)
            }
        }
        // A restart between a hang-up and that check lost the runnable, and
        // the watcher's first read is no transition: pick it up from the
        // stored end. Outside [lock] (snapshot takes CallState's lock).
        try {
            resumeDelay(CallState.snapshot(app), System.currentTimeMillis())?.let { delay ->
                main.postDelayed({ evaluate(app) }, delay)
            }
        } catch (e: Exception) {
            Log.w(TAG, "resume_error: ${e.javaClass.simpleName}")
        }
    }

    /**
     * Record that Cleanway saw [kind] at [now], and post the notice if this is
     * the moment for it. Callers report every occurrence — this decides what
     * is new for the call ([isNewForCall]), so a repeat costs one read and no
     * write. Safe from any thread; never throws into a caller.
     */
    fun noteEvent(context: Context, kind: String, now: Long = System.currentTimeMillis()) {
        if (kind !in EVENTS) return
        val app = context.applicationContext
        try {
            val prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            // Before [lock]: lock order is CallState → CallGuard (see evaluate).
            val call = CallState.snapshot(app)
            val stored = synchronized(lock) {
                val json = prefs.getString(KEY_EVENTS, null)
                if (!isNewForCall(parseEvents(json), kind, prefs.getLong(KEY_ALERTED_AT, 0L), call.callStartedAt)) {
                    false
                } else {
                    prefs.edit().putString(KEY_EVENTS, appendJson(json, Event(kind, now))).apply()
                    true
                }
            }
            if (stored) evaluate(app, now)
        } catch (e: Exception) {
            Log.w(TAG, "note_event_error: ${e.javaClass.simpleName}")
        }
    }

    private fun evaluate(app: Context, now: Long = System.currentTimeMillis()) {
        try {
            val prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            // Read the phone's state BEFORE taking [lock]: snapshot takes
            // CallState's lock, and CallState.acquire must never need ours
            // while holding its own (lock order: CallState → CallGuard, never
            // the reverse).
            val call = CallState.snapshot(app)
            val decision = synchronized(lock) {
                decide(parseEvents(prefs.getString(KEY_EVENTS, null)), prefs.getLong(KEY_ALERTED_AT, 0L), call, now)
            }
            if (decision is Decision.Alert) {
                synchronized(lock) { prefs.edit().putLong(KEY_ALERTED_AT, now).apply() }
                notify(app, decision.reason, now, budgetKey(call.callStartedAt))
            }
        } catch (e: Exception) {
            Log.w(TAG, "evaluate_error: ${e.javaClass.simpleName}")
        }
    }

    /** The notice itself. Goes through the same budget as block alerts (AlertBudget), under [key]; over the cap it is counted in the one summary. */
    fun notify(context: Context, reason: String, now: Long = System.currentTimeMillis(), key: String = ALERT_KEY) {
        val verdict = BlockNotifier.decide(context, AlertBudget.Severity.DANGER, key, now)
        when (route(verdict)) {
            Route.NONE -> return
            Route.SUMMARY -> {
                BlockNotifier.notifySummary(context, (verdict as AlertBudget.Verdict.SUMMARY).count)
                return
            }
            Route.HEADS_UP, Route.SILENT -> Unit
        }
        try {
            BlockNotifier.ensureChannel(context)
            val loc = LocalizedContext.of(context)
            val text = loc.getString(R.string.after_call_text, loc.getString(reasonRes(reason)))
            val channel = if (verdict == AlertBudget.Verdict.HEADS_UP) BlockNotifier.ALERT_CHANNEL_ID else BlockNotifier.CAUTION_CHANNEL_ID
            val open = Intent(Intent.ACTION_VIEW, Uri.parse(DEEP_LINK)).apply {
                component = ComponentName(context.packageName, "ai.cleanway.app.MainActivity")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            }
            val builder = NotificationCompat.Builder(context, channel)
                .setContentTitle(loc.getString(R.string.after_call_title))
                .setContentText(text)
                .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                .setSmallIcon(BlockNotifier.SMALL_ICON)
                .setColor(BlockNotifier.ACCENT_COLOR)
                .setContentIntent(PendingIntent.getActivity(
                    context, NOTIF_ID, open, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                ))
                .setAutoCancel(true)
                .setPriority(if (verdict == AlertBudget.Verdict.HEADS_UP) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_LOW)
            // "Call a close one" only when a number is saved — and the number
            // itself stays out of the text: the phone app shows it.
            CloseContact.dialIntent(context)?.let { dial ->
                builder.addAction(
                    0, loc.getString(R.string.after_call_call_close_one),
                    PendingIntent.getActivity(context, NOTIF_ID + 1, dial, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT),
                )
            }
            (context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).notify(NOTIF_ID, builder.build())
            Log.i(TAG, "after_call_notice reason=$reason")
        } catch (e: Exception) {
            Log.w(TAG, "after_call_notice_error: ${e.javaClass.simpleName}")
        }
    }
}
