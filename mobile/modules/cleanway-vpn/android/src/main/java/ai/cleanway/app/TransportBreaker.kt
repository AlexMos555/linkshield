package ai.cleanway.app

/** Upstream transports, in preference order. */
enum class Transport { UDP_PRIMARY, UDP_SECONDARY, DOH }

/**
 * Which upstream to try, and when to stop trying a broken one.
 *
 * Pure state machine (JVM-tested) so the DNS loop keeps no policy of its own.
 *
 * Two invariants, both learned the hard way:
 *  - **The chain is never empty.** The old code suppressed UDP and DoH
 *    independently and, with both suppressed, simply returned — dropping every
 *    query on the device for a full minute. Here, when everything is
 *    suppressed the transport closest to recovery is still offered as a
 *    half-open trial. One query pays the timeout; the rest of the device does
 *    not sit in the dark.
 *  - **A demoted transport is demoted, not deleted.** Order changes; nothing
 *    disappears. A network where 1.1.1.1:53 is blocked but 9.9.9.9 works, or
 *    where only DoH survives, keeps resolving.
 *
 * Backoff grows with consecutive failure rounds (5s → 15s → 60s) so a flapping
 * network is not hammered, and a single blip recovers within seconds instead
 * of the old blind 60.
 */
class TransportBreaker {
    private val failures = IntArray(Transport.values().size)
    private val rounds = IntArray(Transport.values().size)
    private val suppressedUntil = LongArray(Transport.values().size)

    /** Transports to try now, best first. Never empty. */
    fun order(nowMs: Long): List<Transport> {
        val all = Transport.values().toList()
        val healthy = all.filter { nowMs >= suppressedUntil[it.ordinal] }
        if (healthy.isNotEmpty()) {
            // Healthy ones in preference order, then the suppressed ones as a
            // last resort (a suppressed transport may still work; we simply
            // stop paying its timeout first).
            return healthy + all.filter { nowMs < suppressedUntil[it.ordinal] }
        }
        // Everything is suppressed: half-open the one that recovers soonest.
        return all.sortedBy { suppressedUntil[it.ordinal] }
    }

    fun onSuccess(t: Transport) {
        failures[t.ordinal] = 0
        rounds[t.ordinal] = 0
        suppressedUntil[t.ordinal] = 0
    }

    fun onFailure(t: Transport, nowMs: Long) {
        val i = t.ordinal
        failures[i] += 1
        if (failures[i] >= FAILURE_THRESHOLD) {
            failures[i] = 0
            val step = BACKOFF_MS[minOf(rounds[i], BACKOFF_MS.size - 1)]
            rounds[i] = minOf(rounds[i] + 1, BACKOFF_MS.size)
            suppressedUntil[i] = nowMs + step
        }
    }

    /** For tests and logging. */
    fun suppressedUntil(t: Transport): Long = suppressedUntil[t.ordinal]

    fun isSuppressed(t: Transport, nowMs: Long): Boolean = nowMs < suppressedUntil[t.ordinal]

    companion object {
        const val FAILURE_THRESHOLD = 3
        val BACKOFF_MS = longArrayOf(5_000L, 15_000L, 60_000L)
    }
}
