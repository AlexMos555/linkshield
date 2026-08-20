package ai.cleanway.app

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * Persistent, newest-first log of the shield's block events.
 *
 * The service blocks while no JavaScript is alive (screen off, app killed),
 * and a broadcast nobody is listening to is lost. Without this the app could
 * never truthfully say "stopped 3 dangerous sites today" — the number is what
 * turns an invisible DNS filter into something a person can see working.
 *
 * Two kinds, kept honest:
 *  - [KIND_BLOCKED]: the query was answered NXDOMAIN — the site never opened.
 *  - [KIND_WARNED]:  the first lookup had already been forwarded (fail-open)
 *    when the verdict arrived; future lookups are blocked, but THIS visit may
 *    have opened. The app must not call that "blocked".
 *
 * Storage is a JSON array in SharedPreferences (cap [DEFAULT_CAP]); the pure
 * functions are JVM-tested in BlockLogTest.
 */
object BlockLog {
    const val KIND_BLOCKED = "blocked"
    const val KIND_WARNED = "warned"
    /** The person said "not a scam" and allowed it — recorded so it is never silent. */
    const val KIND_ALLOWED = "allowed"
    const val DEFAULT_CAP = 200

    private const val PREFS = "cleanway_block_log"
    private const val KEY = "entries"
    // Lifetime totals live OUTSIDE the ring buffer: the recent list is
    // trimmed to DEFAULT_CAP, but "Blocked N sites" must count every block
    // ever, or a heavy user's number silently freezes at 200.
    private const val COUNTS_KEY = "counts"
    private val KINDS = listOf(KIND_BLOCKED, KIND_WARNED, KIND_ALLOWED)
    private val lock = Any()

    data class Entry(val domain: String, val ts: Long, val kind: String)

    fun parse(json: String?): List<Entry> {
        if (json.isNullOrBlank()) return emptyList()
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).mapNotNull { i ->
                val o = arr.optJSONObject(i) ?: return@mapNotNull null
                val d = o.optString("d")
                if (d.isBlank()) null else Entry(d, o.optLong("t"), o.optString("k", KIND_BLOCKED))
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    /** Pure: prepend one entry, trim to [cap], return the new JSON. */
    fun appendJson(json: String?, domain: String, ts: Long, kind: String, cap: Int = DEFAULT_CAP): String {
        val existing = parse(json)
        val merged = (listOf(Entry(domain, ts, kind)) + existing).take(cap)
        val arr = JSONArray()
        merged.forEach { e ->
            arr.put(JSONObject().put("d", e.domain).put("t", e.ts).put("k", e.kind))
        }
        return arr.toString()
    }

    /** Pure: how many entries have ts >= sinceMs. */
    fun countSince(json: String?, sinceMs: Long): Int = parse(json).count { it.ts >= sinceMs }

    /** Pure: read the lifetime counters, defaulting every kind to 0. */
    fun parseCounts(json: String?): Map<String, Int> {
        val out = KINDS.associateWith { 0 }.toMutableMap()
        if (json.isNullOrBlank()) return out
        try {
            val o = JSONObject(json)
            for (k in KINDS) out[k] = o.optInt(k, 0).coerceAtLeast(0)
        } catch (_: Exception) {
            // Corrupt counters read as zero rather than crashing the service.
        }
        return out
    }

    /** Pure: increment one kind's lifetime counter, return the new JSON. */
    fun bumpCounts(json: String?, kind: String): String {
        val counts = parseCounts(json).toMutableMap()
        counts[kind] = (counts[kind] ?: 0) + 1
        val o = JSONObject()
        for (k in KINDS) o.put(k, counts[k] ?: 0)
        return o.toString()
    }

    fun record(context: Context, domain: String, ts: Long, kind: String) {
        synchronized(lock) {
            val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val nextEntries = appendJson(prefs.getString(KEY, null), domain, ts, kind)
            val nextCounts = bumpCounts(prefs.getString(COUNTS_KEY, null), kind)
            prefs.edit().putString(KEY, nextEntries).putString(COUNTS_KEY, nextCounts).apply()
        }
    }

    /** Lifetime totals per kind — the source of truth for "Blocked N". */
    fun lifetimeCounts(context: Context): Map<String, Int> {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return parseCounts(prefs.getString(COUNTS_KEY, null))
    }

    fun recent(context: Context, limit: Int): List<Entry> {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return parse(prefs.getString(KEY, null)).take(limit.coerceAtLeast(0))
    }

    fun countSince(context: Context, sinceMs: Long): Int {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return countSince(prefs.getString(KEY, null), sinceMs)
    }
}
