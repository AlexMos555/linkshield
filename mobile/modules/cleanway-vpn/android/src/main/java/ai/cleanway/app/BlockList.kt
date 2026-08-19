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
    internal val hashes: LongArray,
    val version: Long,
    val count: Int,
    val revoked: Boolean,
    private val loadedAtWallMs: Long,
    private val loadedAtElapsedMs: Long,
    private val popularVeto: Set<String>,
    /**
     * Suffixes under which a name is ONE TENANT's site
     * (assets/shared_suffixes.txt). Without them the veto cancelled real
     * blocks: `best10cdn.blob.core.windows.net` has registrable
     * `windows.net`, which is top-10k, so a bucket someone filled with
     * phishing was silently un-blocked — 783 of the 1,548 tenant suffixes the
     * publisher targets behaved that way.
     */
    private val sharedSuffixes: Set<String> = emptySet(),
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
                return if (isVetoed(suffix)) null else suffix
            }
        }
        return null
    }

    /**
     * Does the popular-domain veto cancel a block on [name]?
     *
     * Yes when the name belongs to a popular ORGANISATION (its registrable is
     * top-10k) — that is the guard against a bad publish darkening
     * paypal.com. No when the name is a TENANT under a shared platform: a
     * bucket, a Pages site or a Blob container is not the platform's own
     * name, and the platform's popularity says nothing about it.
     */
    private fun isVetoed(name: String): Boolean {
        if (tenantSuffixOf(name) != null) return false
        return RegistrableDomain.of(name) in popularVeto
    }

    /** The longest shared suffix strictly shorter than [name], or null. */
    private fun tenantSuffixOf(name: String): String? {
        if (sharedSuffixes.isEmpty()) return null
        val parts = name.split('.')
        for (k in parts.size - 1 downTo 2) {
            val suffix = parts.takeLast(k).joinToString(".")
            if (suffix in sharedSuffixes) return suffix
        }
        return null
    }

    fun contains(hash: Long): Boolean = hashes.binarySearch(hash) >= 0

    fun hasListCanary(): Boolean = contains(hashOf(LIST_CANARY))

    /**
     * How old the list is, by the most pessimistic honest measure.
     *
     * Three candidates, each clamped at zero so a wrong clock can never make
     * the list look NEWER than it is:
     *  - wall clock since the fetch (can be rolled back to fake freshness);
     *  - monotonic since the fetch (can't be faked, but resets on reboot);
     *  - wall clock since the publisher generated the data — what a person
     *    actually means by "how old is this list", and the only one that
     *    survives a reinstall of the same file.
     *
     * Clamping matters: after a reboot the stored monotonic base is
     * back-dated into the negative, and the card read "updated 17h ago" for a
     * list fetched 40 minutes earlier (seen on a device, 2026-08-19).
     */
    fun ageMs(nowMs: Long, elapsedMs: Long): Long {
        val wall = (nowMs - loadedAtWallMs).coerceAtLeast(0L)
        val mono = (elapsedMs - loadedAtElapsedMs).coerceAtLeast(0L)
        val generated = if (version > 0L) (nowMs - version * 1000L).coerceAtLeast(0L) else 0L
        return maxOf(wall, mono, generated)
    }

    fun isStale(nowMs: Long, elapsedMs: Long): Boolean = ageMs(nowMs, elapsedMs) > STALE_AFTER_MS

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

        private val DELTA_MAGIC = "CWBD1\n".toByteArray(Charsets.US_ASCII)
        private val DELTA_HEADER = Regex(
            """^# cleanway-dns-blocklist-delta v2 from=(\d+) to=(\d+) added=(\d+) removed=(\d+) sha256=([0-9a-f]{64})$"""
        )

        /** Is this blob a delta rather than a full artifact? */
        fun isDelta(blob: ByteArray): Boolean {
            if (blob.size < DELTA_MAGIC.size) return false
            for (i in DELTA_MAGIC.indices) if (blob[i] != DELTA_MAGIC[i]) return false
            return true
        }

        /**
         * Apply a delta to this list and return the FULL artifact bytes the
         * result corresponds to, or null if anything is off.
         *
         * The rebuild is the point: a delta is only trusted once the merged
         * set reproduces the exact bytes the publisher hashed. A delta that
         * quietly produced a different set would be a blocklist nobody could
         * audit — and the phone would be blocking things the server never
         * published.
         */
        fun applyDelta(current: BlockList, blob: ByteArray): ByteArray? {
            if (!isDelta(blob)) return null
            var nl = -1
            for (i in DELTA_MAGIC.size until minOf(blob.size, DELTA_MAGIC.size + 300)) {
                if (blob[i] == '\n'.code.toByte()) { nl = i; break }
            }
            if (nl < 0) return null
            val m = DELTA_HEADER.matchEntire(
                String(blob, DELTA_MAGIC.size, nl - DELTA_MAGIC.size, Charsets.US_ASCII)
            ) ?: return null
            val from = m.groupValues[1].toLongOrNull() ?: return null
            val to = m.groupValues[2].toLongOrNull() ?: return null
            val addedCount = m.groupValues[3].toIntOrNull() ?: return null
            val removedCount = m.groupValues[4].toIntOrNull() ?: return null
            val targetSha = m.groupValues[5]
            // Only applicable to exactly the list we hold.
            if (from != current.version || current.revoked) return null
            if (addedCount + removedCount > MAX_ENTRIES) return null

            val body = blob.size - (nl + 1)
            if (body != (addedCount + removedCount) * HASH_BYTES) return null
            fun read(index: Int): Long {
                var v = 0L
                val p = nl + 1 + index * HASH_BYTES
                for (b in 0 until HASH_BYTES) v = (v shl 8) or (blob[p + b].toLong() and 0xFF)
                return v
            }
            val added = LongArray(addedCount) { read(it) }
            val removed = LongArray(removedCount) { read(addedCount + it) }

            val merged = java.util.TreeSet<Long>()
            for (h in current.hashes) merged.add(h)
            for (h in removed) merged.remove(h)
            for (h in added) merged.add(h)

            val rebuilt = render(merged.toLongArray(), to)
            val sha = MessageDigest.getInstance("SHA-256").digest(rebuilt)
                .joinToString("") { "%02x".format(it) }
            return if (sha == targetSha) rebuilt else null
        }

        /** The publisher's exact byte layout, so a merge can be verified. */
        fun render(hashes: LongArray, generated: Long): ByteArray {
            val header = "# cleanway-dns-blocklist v2 generated=$generated count=${hashes.size} status=ok\n"
                .toByteArray(Charsets.US_ASCII)
            val out = ByteArray(MAGIC.size + header.size + hashes.size * HASH_BYTES)
            System.arraycopy(MAGIC, 0, out, 0, MAGIC.size)
            System.arraycopy(header, 0, out, MAGIC.size, header.size)
            var p = MAGIC.size + header.size
            for (h in hashes) {
                for (b in HASH_BYTES - 1 downTo 0) out[p++] = ((h shr (8 * b)) and 0xFF).toByte()
            }
            return out
        }

        /** Empty list (nothing blocked) — the state before any sync. */
        fun empty(popularVeto: Set<String> = emptySet(), sharedSuffixes: Set<String> = emptySet()): BlockList =
            BlockList(LongArray(0), 0L, 0, false, 0L, 0L, popularVeto, sharedSuffixes)

        /**
         * Strict parse. Returns null (reject WHOLE) on any malformed input.
         * [nowMs]/[elapsedMs] stamp when the list was loaded (both clocks).
         */
        fun parse(
            blob: ByteArray,
            popularVeto: Set<String>,
            nowMs: Long,
            elapsedMs: Long = 0L,
            sharedSuffixes: Set<String> = emptySet(),
        ): BlockList? {
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
                return BlockList(LongArray(0), generated, 0, true, nowMs, elapsedMs, popularVeto, sharedSuffixes)
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
            return BlockList(out, generated, entries, false, nowMs, elapsedMs, popularVeto, sharedSuffixes)
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
