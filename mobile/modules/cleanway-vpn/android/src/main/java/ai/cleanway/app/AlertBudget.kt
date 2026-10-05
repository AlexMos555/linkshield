package ai.cleanway.app

import org.json.JSONArray
import org.json.JSONObject

/**
 * How many pop-ups a person gets — fewer, louder, clearer.
 *
 * A third needless notification is swiped away together with the one that
 * mattered, so the budget is deliberately small (plan №7, thresholds for the
 * founder to approve):
 *
 *  - "Dangerous" ([Severity.DANGER]: a site stopped, the after-call notice)
 *    pops up at most [MAX_HEADS_UP_PER_HOUR] times an hour and
 *    [MAX_HEADS_UP_PER_DAY] a day. Past that, one collapsed, silent
 *    "N more suspicious" ([Verdict.SUMMARY]) stands in for the rest and is
 *    updated in place; every event is still in History.
 *  - "Careful" ([Severity.CAUTION]: a site that had opened looks like a
 *    scam) never pops up and makes no sound — it waits in the shade.
 *  - One pop-up per site (or sender) in [PER_KEY_HEADS_UP_WINDOW_MS]. A
 *    repeat inside that window still refreshes the same notification —
 *    silently — so a second try at the site never looks like the shield did
 *    nothing (1.0.3 moved from a 6 h silence to exactly this complaint).
 *  - The burst window stays: lookups of one site closer together than
 *    [BURST_WINDOW_MS] (A, AAAA, HTTPS records, the browser's retries) are
 *    one attempt and are [Verdict.DROP]ped after the first.
 *
 * Pure, one instance per process, JVM-tested (AlertBudgetTest). Time is
 * passed in, never read here. Android restarts the sticky VPN service
 * whenever it likes, so the caller saves [toJson] after every pop-up or
 * summary and [restore]s it into the next process (BlockNotifier) — the caps
 * are per person, not per process.
 */
class AlertBudget {
    enum class Severity { DANGER, CAUTION }

    sealed class Verdict {
        /** Post on the high-importance channel: a pop-up with sound. */
        object HEADS_UP : Verdict()
        /** Post (or refresh) on the silent channel: no pop-up, no sound. */
        object SILENT : Verdict()
        /** Over the cap: post or update the one collapsed "N more suspicious" notice. */
        data class SUMMARY(val count: Int) : Verdict()
        /** Part of a burst already alerted: nothing to post. */
        object DROP : Verdict()
    }

    // Last LOOKUP of each key, alerted or not (the burst window runs from it).
    private val lastSeen = mutableMapOf<String, Long>()
    // Last HEADS-UP per key.
    private val lastHeadsUp = mutableMapOf<String, Long>()
    // Every heads-up in the last day, oldest first.
    private val headsUps = ArrayDeque<Long>()
    // Suppressed since the cap was hit; cleared once a heads-up is allowed again.
    private var summarised = 0

    @Synchronized
    fun decide(severity: Severity, key: String, now: Long): Verdict {
        val seen = lastSeen[key]
        lastSeen[key] = now
        if (seen != null && now - seen in 0 until BURST_WINDOW_MS) return Verdict.DROP
        trim(now)
        if (severity == Severity.CAUTION) return Verdict.SILENT
        val lastPop = lastHeadsUp[key]
        if (lastPop != null && now - lastPop in 0 until PER_KEY_HEADS_UP_WINDOW_MS) return Verdict.SILENT
        val lastHour = headsUps.count { now - it < HOUR_MS }
        if (lastHour >= MAX_HEADS_UP_PER_HOUR || headsUps.size >= MAX_HEADS_UP_PER_DAY) {
            summarised += 1
            return Verdict.SUMMARY(summarised)
        }
        summarised = 0
        headsUps.addLast(now)
        lastHeadsUp[key] = now
        return Verdict.HEADS_UP
    }

    /**
     * What a restarted process needs to keep the caps: the heads-ups of the
     * last day, the per-key pop-ups of the last six hours and the summary
     * count. The 45-second burst window is not kept — a restart takes longer.
     */
    @Synchronized
    fun toJson(): String {
        val keys = JSONObject()
        lastHeadsUp.forEach { (k, t) -> keys.put(k, t) }
        return JSONObject()
            .put("h", JSONArray().apply { headsUps.forEach { put(it) } })
            .put("k", keys)
            .put("s", summarised)
            .toString()
    }

    /**
     * Load what [toJson] saved, keeping only what can still matter at [now]
     * (nothing from the future: a clock stepped back must not tighten the
     * caps). Garbage is ignored — a budget that forgot is the worst case.
     */
    @Synchronized
    fun restore(json: String?, now: Long) {
        if (json.isNullOrBlank()) return
        try {
            val o = JSONObject(json)
            o.optJSONArray("h")?.let { arr ->
                val kept = (0 until arr.length()).map { arr.optLong(it, -1L) }
                    .filter { it in 0..now && now - it < DAY_MS }
                    .sorted()
                headsUps.clear()
                headsUps.addAll(kept)
            }
            o.optJSONObject("k")?.let { keys ->
                keys.keys().forEach { k ->
                    val t = keys.optLong(k, -1L)
                    if (t in 0..now && now - t < PER_KEY_HEADS_UP_WINDOW_MS) lastHeadsUp[k] = t
                }
            }
            summarised = o.optInt("s", 0).coerceAtLeast(0)
        } catch (_: Exception) {
        }
    }

    /** Keep the maps from growing forever on a long session. */
    private fun trim(now: Long) {
        while (headsUps.isNotEmpty() && now - headsUps.first() >= DAY_MS) headsUps.removeFirst()
        if (lastSeen.size > 512) {
            lastSeen.entries.filter { now - it.value >= HOUR_MS }.map { it.key }.forEach { lastSeen.remove(it) }
        }
        if (lastHeadsUp.size > 512) {
            lastHeadsUp.entries.filter { now - it.value >= PER_KEY_HEADS_UP_WINDOW_MS }.map { it.key }.forEach { lastHeadsUp.remove(it) }
        }
    }

    companion object {
        const val MAX_HEADS_UP_PER_HOUR = 3
        const val MAX_HEADS_UP_PER_DAY = 10
        const val PER_KEY_HEADS_UP_WINDOW_MS = 6L * 60 * 60_000
        const val BURST_WINDOW_MS = 45_000L
        private const val HOUR_MS = 60 * 60_000L
        private const val DAY_MS = 24 * HOUR_MS
    }
}
