package ai.cleanway.app

import android.content.Context
import android.content.SharedPreferences
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
 * Three kinds, kept honest:
 *  - [KIND_BLOCKED]: the site never opened — the DNS query was answered
 *    NXDOMAIN, or the link guard stopped a tapped link to a listed site.
 *  - [KIND_WARNED]: the link guard let a tapped link open (not on the list)
 *    and the background check of its site came back dangerous afterwards —
 *    "this may already be open, close it". Never called a block.
 *  - [KIND_ALLOWED]: the person said "not a scam".
 *
 * Each entry also says WHERE it happened ([SOURCE_DNS] / [SOURCE_LINK]), so
 * History can name the shield that acted. Entries written before the field
 * existed read back with the only source that could have written them.
 *
 * One entry per EVENT, not per DNS packet: a single page visit asks for A,
 * AAAA and HTTPS records, a browser retries, and an app can poll a blocked
 * host all day. Recorded raw, one visit read as "Blocked 3" and a polling app
 * pushed every real event out of the 200-entry ring within hours. A repeat of
 * the same site, kind and source within [COALESCE_WINDOW_MS] of its last
 * entry refreshes that entry's time instead (see [recordJson]). A log
 * written before that is brought up to date once, on first use
 * ([migrateJson]).
 *
 * Storage is a JSON array in SharedPreferences (cap [DEFAULT_CAP]); the pure
 * functions are JVM-tested in BlockLogTest.
 */
object BlockLog {
    const val KIND_BLOCKED = "blocked"
    const val KIND_WARNED = "warned"
    /** The person said "not a scam" and allowed it — recorded so it is never silent. */
    const val KIND_ALLOWED = "allowed"

    /** The network shield: the DNS query for the site was refused. */
    const val SOURCE_DNS = "dns"
    /** The link guard: a tapped link was stopped, or checked after it opened. */
    const val SOURCE_LINK = "link"

    const val DEFAULT_CAP = 200
    /** Repeats of one site closer together than this are one event. */
    const val COALESCE_WINDOW_MS = 10L * 60 * 1000

    private const val PREFS = "cleanway_block_log"
    private const val KEY = "entries"
    // Lifetime totals live OUTSIDE the ring buffer: the recent list is
    // trimmed to DEFAULT_CAP, but "Blocked N sites" must count every block
    // ever, or a heavy user's number silently freezes at 200.
    private const val COUNTS_KEY = "counts"
    // 1 (or absent): one entry and one count per DNS query. 2: per event.
    private const val VERSION_KEY = "version"
    private const val VERSION = 2
    private val KINDS = listOf(KIND_BLOCKED, KIND_WARNED, KIND_ALLOWED)
    private val SOURCES = setOf(SOURCE_DNS, SOURCE_LINK)
    private val lock = Any()

    data class Entry(val domain: String, val ts: Long, val kind: String, val source: String? = null) {
        /** Same site, same outcome, same shield — a repeat, not a new event. */
        fun sameEventAs(other: Entry): Boolean =
            domain == other.domain && kind == other.kind && source == other.source
    }

    fun parse(json: String?): List<Entry> {
        if (json.isNullOrBlank()) return emptyList()
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).mapNotNull { i ->
                val o = arr.optJSONObject(i) ?: return@mapNotNull null
                val d = o.optString("d")
                if (d.isBlank()) return@mapNotNull null
                val kind = o.optString("k", KIND_BLOCKED)
                Entry(d, o.optLong("t"), kind, sourceOf(o.optString("s"), kind))
            }
        } catch (_: Exception) {
            emptyList()
        }
    }

    /**
     * An entry without a source predates the field. Until then only the DNS
     * loop recorded blocks and only the link guard's background check recorded
     * warnings, so those are the honest defaults. An unknown value (written by
     * a newer build) is shown without a source rather than a wrong one.
     */
    private fun sourceOf(raw: String, kind: String): String? = when {
        raw.isBlank() -> when (kind) {
            KIND_BLOCKED -> SOURCE_DNS
            KIND_WARNED -> SOURCE_LINK
            else -> null
        }
        raw in SOURCES -> raw
        else -> null
    }

    private fun render(entries: List<Entry>): String {
        val arr = JSONArray()
        entries.forEach { e ->
            val o = JSONObject().put("d", e.domain).put("t", e.ts).put("k", e.kind)
            if (e.source != null) o.put("s", e.source)
            arr.put(o)
        }
        return arr.toString()
    }

    /** Pure: prepend one entry, trim to [cap], return the new JSON. */
    fun appendJson(
        json: String?,
        domain: String,
        ts: Long,
        kind: String,
        cap: Int = DEFAULT_CAP,
        source: String? = null,
    ): String = render((listOf(Entry(domain, ts, kind, source)) + parse(json)).take(cap))

    /**
     * Pure: record one event, newest first, trimmed to [cap].
     *
     * A repeat of an entry ([Entry.sameEventAs]) within [windowMs] of it is the
     * same event: that entry moves to the front with the new time, nothing is
     * added, and the second value is false so the lifetime counter is not
     * bumped. The window slides — a site polled every few minutes stays one
     * entry that keeps its latest time. The comparison is on the absolute gap,
     * so a clock stepped backwards cannot mint a new event either.
     */
    fun recordJson(
        json: String?,
        entry: Entry,
        cap: Int = DEFAULT_CAP,
        windowMs: Long = COALESCE_WINDOW_MS,
    ): Pair<String, Boolean> {
        val existing = parse(json)
        val repeat = existing.indexOfFirst { it.sameEventAs(entry) && kotlin.math.abs(entry.ts - it.ts) < windowMs }
        val rest = if (repeat < 0) existing else existing.filterIndexed { i, _ -> i != repeat }
        return render((listOf(entry) + rest).take(cap)) to (repeat < 0)
    }

    /**
     * Pure: collapse repeats in a newest-first list the way [recordJson]
     * would have — each run of the same event, every step closer than
     * [windowMs], becomes its newest entry.
     */
    fun coalesce(entries: List<Entry>, windowMs: Long = COALESCE_WINDOW_MS): List<Entry> {
        val lastSeen = HashMap<Entry, Long>()
        val out = ArrayList<Entry>(entries.size)
        for (e in entries) {
            val key = e.copy(ts = 0L)
            val newer = lastSeen[key]
            lastSeen[key] = e.ts
            if (newer == null || kotlin.math.abs(newer - e.ts) >= windowMs) out.add(e)
        }
        return out
    }

    /**
     * Pure: bring a log written before coalescing up to date — the ring
     * collapsed to events, and the lifetime counts recounted from it. The
     * recount is exact only while the ring never overflowed (then every event
     * ever is still in it). A full ring keeps its counts: what fell off it
     * cannot be recounted, and a guess would be a made-up number.
     */
    fun migrateJson(
        entriesJson: String?,
        countsJson: String?,
        cap: Int = DEFAULT_CAP,
        windowMs: Long = COALESCE_WINDOW_MS,
    ): Pair<String, String> {
        val raw = parse(entriesJson)
        val events = coalesce(raw, windowMs)
        val counts = if (raw.size < cap) {
            KINDS.associateWith { k -> events.count { it.kind == k } }
        } else {
            parseCounts(countsJson)
        }
        val o = JSONObject()
        for (k in KINDS) o.put(k, counts[k] ?: 0)
        return render(events) to o.toString()
    }

    /** Once per install: apply [migrateJson]. Call under [lock]. */
    private fun migrated(context: Context): SharedPreferences {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (prefs.getInt(VERSION_KEY, 1) >= VERSION) return prefs
        val (entries, counts) = migrateJson(prefs.getString(KEY, null), prefs.getString(COUNTS_KEY, null))
        prefs.edit().putString(KEY, entries).putString(COUNTS_KEY, counts).putInt(VERSION_KEY, VERSION).apply()
        return prefs
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

    /**
     * Record one event (see [recordJson]). Returns true when it was a new
     * event, false when it only refreshed a recent entry for the same site.
     */
    fun record(context: Context, domain: String, ts: Long, kind: String, source: String? = null): Boolean {
        synchronized(lock) {
            val prefs = migrated(context)
            val (nextEntries, isNew) = recordJson(prefs.getString(KEY, null), Entry(domain, ts, kind, source))
            val edit = prefs.edit().putString(KEY, nextEntries)
            if (isNew) edit.putString(COUNTS_KEY, bumpCounts(prefs.getString(COUNTS_KEY, null), kind))
            edit.apply()
            return isNew
        }
    }

    /** Lifetime totals per kind — the source of truth for "Blocked N". */
    fun lifetimeCounts(context: Context): Map<String, Int> = synchronized(lock) {
        parseCounts(migrated(context).getString(COUNTS_KEY, null))
    }

    fun recent(context: Context, limit: Int): List<Entry> = synchronized(lock) {
        parse(migrated(context).getString(KEY, null)).take(limit.coerceAtLeast(0))
    }

    fun countSince(context: Context, sinceMs: Long): Int = synchronized(lock) {
        countSince(migrated(context).getString(KEY, null), sinceMs)
    }
}
