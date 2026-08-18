package ai.cleanway.app

/**
 * The on-device DNS blocklist — decided on the phone, on the FIRST lookup.
 *
 * Before this the shield forwarded every unknown name fail-open and asked the
 * server afterwards; Android's resolver then cached the fail-open answer for
 * the record's whole TTL, so time-to-block equalled the phishing record's TTL
 * (30 s … 1 h+) and 12/12 live phishing domains resolved on first, second and
 * third lookup (measured 2026-08-18). A listed name now gets NXDOMAIN before
 * anything opens, with no network round-trip and nothing leaving the phone.
 *
 * Format (api/services/blocklist_artifact.py — the ONE definition):
 *   # cleanway-dns-blocklist v1 generated=<epoch> count=<n> status=ok|revoked
 *   <name>            (lowercase punycode, sorted, one per line)
 * Every name means "block it and all its subdomains".
 *
 * Strictness: a file with any bad line, a wrong count, a bare TLD, or too many
 * entries is rejected WHOLE — the previous list stays. A last line of defence
 * against a bad publish is the popular veto: a listed name whose registrable
 * domain is in the bundled top-10k asset (minus public suffixes, so tenant
 * sites like evil.github.io stay blockable) never blocks.
 *
 * Immutable; the service swaps a @Volatile reference on refresh.
 */
class BlockList private constructor(
    private val names: Set<String>,
    val version: Long,
    val count: Int,
    val revoked: Boolean,
    private val loadedAtWallMs: Long,
    private val loadedAtElapsedMs: Long,
    private val popularVeto: Set<String>,
) {
    /**
     * Longest listed suffix of [qname] (with at least two labels), or null.
     * Vetoed when the match's registrable domain is popular.
     */
    fun match(qname: String): String? {
        if (revoked || names.isEmpty()) return null
        val q = qname.lowercase().trimEnd('.')
        val parts = q.split('.')
        if (parts.size < 2) return null
        // Walk from the full name down to the 2-label suffix; a bare TLD is
        // never consulted. Longest match wins, which is also the first hit.
        for (i in 0..parts.size - 2) {
            val suffix = parts.subList(i, parts.size).joinToString(".")
            if (suffix in names) {
                return if (RegistrableDomain.of(suffix) in popularVeto) null else suffix
            }
        }
        return null
    }

    fun hasListCanary(): Boolean = LIST_CANARY in names

    /**
     * Stale = older than [STALE_AFTER_MS] by EITHER clock. Wall clock alone
     * can be rolled back to keep a dead list "fresh"; monotonic alone misses a
     * phone that slept for a day. Take the larger age.
     */
    fun isStale(nowMs: Long, elapsedMs: Long): Boolean {
        val wallAge = nowMs - loadedAtWallMs
        val monoAge = elapsedMs - loadedAtElapsedMs
        return maxOf(wallAge, monoAge) > STALE_AFTER_MS
    }

    fun ageMs(nowMs: Long, elapsedMs: Long): Long = maxOf(nowMs - loadedAtWallMs, elapsedMs - loadedAtElapsedMs)

    companion object {
        const val LIST_CANARY = "list-canary.cleanway.ai"
        const val MAX_ENTRIES = 50_000
        const val MAX_BYTES = 2 * 1024 * 1024
        const val STALE_AFTER_MS = 24L * 60 * 60 * 1000

        private val HEADER = Regex(
            """^# cleanway-dns-blocklist v1 generated=(\d+) count=(\d+) status=(ok|revoked)$"""
        )
        // LDH labels, 1..63 chars, no leading/trailing hyphen; 2..253 total.
        private val LABEL = Regex("""^(?!-)[a-z0-9-]{1,63}(?<!-)$""")

        /** Empty list (nothing blocked) — the state before any sync. */
        fun empty(popularVeto: Set<String> = emptySet()): BlockList =
            BlockList(emptySet(), 0L, 0, false, 0L, 0L, popularVeto)

        /**
         * Strict parse. Returns null (reject WHOLE) on any malformed input.
         * [nowMs]/[elapsedMs] stamp when the list was loaded (both clocks).
         */
        fun parse(text: String, popularVeto: Set<String>, nowMs: Long, elapsedMs: Long = 0L): BlockList? {
            if (text.length > MAX_BYTES) return null
            val lines = text.split('\n')
            val header = HEADER.matchEntire(lines.firstOrNull()?.trim() ?: return null) ?: return null
            val generated = header.groupValues[1].toLongOrNull() ?: return null
            val declared = header.groupValues[2].toIntOrNull() ?: return null
            val revoked = header.groupValues[3] == "revoked"
            if (declared > MAX_ENTRIES) return null

            val names = HashSet<String>(declared * 2 + 16)
            for (raw in lines.drop(1)) {
                val line = raw.trim()
                if (line.isEmpty()) continue
                val name = line.lowercase()
                if (name.length > 253) return null
                val labels = name.split('.')
                if (labels.size < 2) return null           // bare TLD: never
                if (labels.any { !LABEL.matches(it) }) return null
                names.add(name)
            }
            if (revoked) {
                if (names.isNotEmpty() || declared != 0) return null
                return BlockList(emptySet(), generated, 0, true, nowMs, elapsedMs, popularVeto)
            }
            if (names.size != declared) return null
            return BlockList(names, generated, names.size, false, nowMs, elapsedMs, popularVeto)
        }
    }
}

/**
 * Registrable domain (eTLD+1), phone-side mirror of the server heuristic:
 * last two labels, or three under a compound / generic-SLD ccTLD. Used ONLY
 * for the popular veto (is this listed name a popular org's?), so the cheap
 * heuristic is enough — a full PSL on the phone buys nothing here.
 */
object RegistrableDomain {
    private val COMPOUND = setOf(
        "co.uk", "ac.uk", "gov.uk", "org.uk", "co.jp", "co.in", "com.au", "com.br",
        "com.mx", "co.kr", "co.za", "com.sg", "com.tr", "co.id", "com.ar", "com.co",
    )
    private val CCTLD_SLD = setOf(
        "com", "co", "org", "net", "gov", "gob", "edu", "ac", "ne", "or", "go", "in",
        "nom", "gen", "ltd", "plc", "sch", "asn", "id", "biz", "info", "web", "gv",
        "govt", "mil", "nic", "int", "art", "name", "pro", "tv", "mobi", "priv",
    )

    fun of(host: String): String {
        val parts = host.lowercase().trimEnd('.').split('.')
        if (parts.size <= 2) return parts.joinToString(".")
        val lastTwo = parts.takeLast(2).joinToString(".")
        if (lastTwo in COMPOUND) return parts.takeLast(3).joinToString(".")
        val tld = parts.last()
        val sld = parts[parts.size - 2]
        if (tld.length == 2 && sld in CCTLD_SLD) return parts.takeLast(3).joinToString(".")
        return lastTwo
    }
}
