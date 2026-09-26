package ai.cleanway.app

/**
 * Upstream transports, in preference order.
 *
 * [NETWORK] is the resolver of the network the phone is actually on — the
 * operator's or the router's, the one it would use without Cleanway. It comes
 * first: it is the closest, it keeps working where foreign resolvers are
 * throttled or intercepted, and it keeps the operator's own anti-phishing DNS
 * filtering in force instead of silently replacing it with ours. The public
 * resolvers after it are the fallback for when it fails.
 */
enum class Transport { NETWORK, UDP_PRIMARY, UDP_SECONDARY, DOH }

/**
 * Which upstream to try, and when to stop trying a broken one.
 *
 * Pure state machine (JVM-tested) so the DNS loop keeps no policy of its own.
 * Every forwarding thread calls it at once, hence the locks.
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

    /**
     * Transports to try now, best first. Never empty. [networkDns] says
     * whether the underlying network's resolver is known right now; without
     * it the chain is the public one alone.
     */
    @Synchronized
    fun order(nowMs: Long, networkDns: Boolean = false): List<Transport> {
        val all = Transport.values().filter { networkDns || it != Transport.NETWORK }
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

    @Synchronized
    fun onSuccess(t: Transport) {
        failures[t.ordinal] = 0
        rounds[t.ordinal] = 0
        suppressedUntil[t.ordinal] = 0
    }

    @Synchronized
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

    /**
     * Forget [t]'s history. The phone moved to another network: the resolver
     * behind [Transport.NETWORK] is a different server now, and the old one's
     * failures say nothing about it.
     */
    fun reset(t: Transport) = onSuccess(t)

    /** For tests and logging. */
    @Synchronized
    fun suppressedUntil(t: Transport): Long = suppressedUntil[t.ordinal]

    @Synchronized
    fun isSuppressed(t: Transport, nowMs: Long): Boolean = nowMs < suppressedUntil[t.ordinal]

    companion object {
        const val FAILURE_THRESHOLD = 3
        val BACKOFF_MS = longArrayOf(5_000L, 15_000L, 60_000L)
    }
}
