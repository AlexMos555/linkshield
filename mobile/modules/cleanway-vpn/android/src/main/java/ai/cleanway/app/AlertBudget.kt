package ai.cleanway.app

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
 * passed in, never read here.
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
