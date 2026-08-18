package ai.cleanway.app

import java.security.MessageDigest

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
 * ## Why hashes, not names (format v2)
 *
 * The feeds that give real coverage carry ~500k names: 13 MB of text, and
 * ~500k Java strings in a HashSet is ~50 MB of heap inside a VpnService. The
 * artifact instead ships the first [HASH_BYTES] bytes of SHA-256(name),
 * sorted; the phone holds a `LongArray` (~3 MB) and answers by binary search.
 * With ~5·10^5 entries in a 2^48 space a random query collides with
 * probability ~2·10^-9 per suffix lookup — one spurious block per ~300 years
 * per phone — and the popular-domain veto below still sits on top of that.
 *
 * Layout (api/services/blocklist_artifact.py is the other half of this
 * contract; BlockListTest pins the hashes against values computed there):
 *
 *     "CWBL2\n"
 *     "# cleanway-dns-blocklist v2 generated=<epoch> count=<n> status=ok\n"
 *     n × 6 bytes, big-endian, ascending
 *
 * Strictness: a file with bad magic, a bad header, a wrong count, a truncated
 * or unsorted body is rejected WHOLE — the previous list stays. Sorting is
 * verified because the match is a binary search: an unsorted body would not
 * be a smaller list, it would be a randomly wrong one.
 *
 * Immutable; the service swaps a @Volatile reference on refresh.
 */
class BlockList private constructor(
    private val hashes: LongArray,
    val version: Long,
    val count: Int,
    val revoked: Boolean,
    private val loadedAtWallMs: Long,
    private val loadedAtElapsedMs: Long,
    private val popularVeto: Set<String>,
) {
    /**
     * The listed suffix of [qname] that blocks it, or null. A listed name
     * covers itself and all its subdomains, so the walk goes from the full
     * name down to the two-label suffix; a bare TLD is never consulted.
     *
     * The popular veto is plaintext and applies to the match's registrable
     * domain: even a bad publish (or a hash collision) cannot darken a
     * top-10k site.
     */
    fun match(qname: String): String? {
        if (revoked || hashes.isEmpty()) return null
        val q = qname.lowercase().trimEnd('.')
        val parts = q.split('.')
        if (parts.size < 2) return null
        for (i in 0..parts.size - 2) {
            val suffix = parts.subList(i, parts.size).joinToString(".")
            if (contains(hashOf(suffix))) {
                return if (RegistrableDomain.of(suffix) in popularVeto) null else suffix
            }
        }
        return null
    }

    fun contains(hash: Long): Boolean = hashes.binarySearch(hash) >= 0

    fun hasListCanary(): Boolean = contains(hashOf(LIST_CANARY))

    /**
     * Stale = older than [STALE_AFTER_MS] by EITHER clock. Wall clock alone
     * can be rolled back to keep a dead list "fresh"; monotonic alone misses a
     * phone that slept for a day. Take the larger age.
     */
    fun isStale(nowMs: Long, elapsedMs: Long): Boolean =
        maxOf(nowMs - loadedAtWallMs, elapsedMs - loadedAtElapsedMs) > STALE_AFTER_MS

    fun ageMs(nowMs: Long, elapsedMs: Long): Long =
        maxOf(nowMs - loadedAtWallMs, elapsedMs - loadedAtElapsedMs)

    companion object {
        const val LIST_CANARY = "list-canary.cleanway.ai"
        const val HASH_BYTES = 6
        const val MAX_ENTRIES = 2_000_000
        const val MAX_BYTES = 32 * 1024 * 1024
        const val STALE_AFTER_MS = 48L * 60 * 60 * 1000

        private val MAGIC = "CWBL2\n".toByteArray(Charsets.US_ASCII)
        private val HEADER = Regex(
            """^# cleanway-dns-blocklist v2 generated=(\d+) count=(\d+) status=(ok|revoked)$"""
        )

        /** SHA-256(name) truncated to [HASH_BYTES], big-endian. */
        fun hashOf(name: String): Long {
            val digest = MessageDigest.getInstance("SHA-256")
                .digest(name.lowercase().trimEnd('.').toByteArray(Charsets.UTF_8))
            var v = 0L
            for (i in 0 until HASH_BYTES) v = (v shl 8) or (digest[i].toLong() and 0xFF)
            return v
        }

        /** Empty list (nothing blocked) — the state before any sync. */
        fun empty(popularVeto: Set<String> = emptySet()): BlockList =
            BlockList(LongArray(0), 0L, 0, false, 0L, 0L, popularVeto)

        /**
         * Strict parse. Returns null (reject WHOLE) on any malformed input.
         * [nowMs]/[elapsedMs] stamp when the list was loaded (both clocks).
         */
        fun parse(blob: ByteArray, popularVeto: Set<String>, nowMs: Long, elapsedMs: Long = 0L): BlockList? {
            if (blob.size > MAX_BYTES || blob.size < MAGIC.size) return null
            for (i in MAGIC.indices) if (blob[i] != MAGIC[i]) return null
            var nl = -1
            for (i in MAGIC.size until minOf(blob.size, MAGIC.size + 200)) {
                if (blob[i] == '\n'.code.toByte()) { nl = i; break }
            }
            if (nl < 0) return null
            val header = String(blob, MAGIC.size, nl - MAGIC.size, Charsets.US_ASCII)
            val m = HEADER.matchEntire(header) ?: return null
            val generated = m.groupValues[1].toLongOrNull() ?: return null
            val declared = m.groupValues[2].toIntOrNull() ?: return null
            val revoked = m.groupValues[3] == "revoked"
            if (declared > MAX_ENTRIES || declared < 0) return null

            val bodyStart = nl + 1
            val bodyLen = blob.size - bodyStart
            if (bodyLen % HASH_BYTES != 0) return null
            val entries = bodyLen / HASH_BYTES
            if (revoked) {
                if (entries != 0 || declared != 0) return null
                return BlockList(LongArray(0), generated, 0, true, nowMs, elapsedMs, popularVeto)
            }
            if (entries != declared || entries == 0) return null

            val out = LongArray(entries)
            var prev = -1L
            var p = bodyStart
            for (i in 0 until entries) {
                var v = 0L
                for (b in 0 until HASH_BYTES) v = (v shl 8) or (blob[p + b].toLong() and 0xFF)
                // Ascending order is load-bearing: match() binary-searches.
                if (v <= prev) return null
                out[i] = v
                prev = v
                p += HASH_BYTES
            }
            return BlockList(out, generated, entries, false, nowMs, elapsedMs, popularVeto)
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
