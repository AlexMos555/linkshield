package ai.cleanway.app

/**
 * Loop brake for LinkGuardActivity.
 *
 * The guard is exported and handles every http/https VIEW intent on the phone.
 * A page or app that re-fires the same intent (a redirect loop, a hostile app
 * spamming startActivity) would make it open the browser — or the warning
 * screen — again and again, faster than the person can get out.
 *
 * Two limits, both on a monotonic clock the caller passes in (elapsedRealtime
 * in the app, plain numbers in LinkGuardThrottleTest):
 *  - the SAME host again within [sameHostWindowMs] is dropped, and the drop
 *    refreshes the window, so a sustained loop stays suppressed until it has
 *    been quiet that long. 2.5 s: longer than any double-tap or app re-delivery
 *    of one tap (well under a second), shorter than a person going back and
 *    deliberately tapping the same link again;
 *  - at most [burstMax] launches in any [burstWindowMs], across all hosts, so
 *    a loop that rotates hosts is capped too. Every attempt fills the window,
 *    so a rotating loop also stays capped until it stops. 8 in 10 s is far
 *    above what a person taps.
 *
 * Memory is bounded: at most [maxHosts] hosts (least recently seen evicted)
 * and [burstMax] timestamps.
 */
class LinkGuardThrottle(
    private val sameHostWindowMs: Long = 2_500,
    private val burstWindowMs: Long = 10_000,
    private val burstMax: Int = 8,
    private val maxHosts: Int = 32,
) {
    private val lastByHost = object : LinkedHashMap<String, Long>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?): Boolean =
            size > maxHosts
    }
    private val recent = ArrayDeque<Long>()

    /** True when this launch may proceed; false means "finish without acting". */
    @Synchronized
    fun admit(host: String, nowMs: Long): Boolean {
        while (recent.isNotEmpty() && nowMs - recent.first() >= burstWindowMs) recent.removeFirst()

        val last = lastByHost[host]
        // A negative gap (clock went backwards) never counts as "too soon".
        val repeat = last != null && nowMs - last in 0 until sameHostWindowMs
        val burst = recent.size >= burstMax

        lastByHost[host] = nowMs
        recent.addLast(nowMs)
        while (recent.size > burstMax) recent.removeFirst()

        return !repeat && !burst
    }

    @Synchronized
    fun trackedHosts(): Int = lastByHost.size
}
