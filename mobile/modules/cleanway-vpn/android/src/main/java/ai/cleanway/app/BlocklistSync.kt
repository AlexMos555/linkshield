package ai.cleanway.app

import android.util.Log
import java.io.File
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPInputStream
import org.json.JSONObject

/** What one fetch of the artifact produced. */
sealed class FetchResult {
    data class Ok(val body: ByteArray, val etag: String?) : FetchResult()
    object NotModified : FetchResult()
    data class Failed(val reason: String) : FetchResult()
}

/** HTTP abstraction so BlocklistSync is JVM-testable with a fake. */
fun interface BlocklistFetcher {
    fun fetch(url: String, etag: String?): FetchResult
}

/**
 * Persistence: the artifact text + a small meta file, written atomically
 * (tmp + rename) so a crash mid-write can never leave a half list — a half
 * list would fail BlockList's count check and be rejected anyway, but the
 * previous good list should survive regardless.
 */
class BlocklistStore(private val dir: File) {
    companion object {
        /**
         * The ONE place that decides where the synced list lives.
         *
         * It used to be spelled out at each call site, and the two drifted: the
         * service wrote to filesDir/cleanway while the link guard read filesDir.
         * `load()` then returned null for the guard on every launch, so it took
         * the fast path for KNOWN-malicious links and opened them in a browser
         * instead of showing the block screen — the guard silently protected
         * nobody. Construct via `BlocklistStore.of(context.filesDir)` so a
         * mismatch like that cannot be written again.
         */
        fun dirFor(filesDir: File): File = File(filesDir, "cleanway")

        fun of(filesDir: File): BlocklistStore = BlocklistStore(dirFor(filesDir))
    }

    data class Saved(val body: ByteArray, val etag: String?, val fetchedAtMs: Long)

    private val blobFile get() = File(dir, "dns-blocklist-v2.bin")
    private val metaFile get() = File(dir, "dns-blocklist-v2.meta.json")
    private val revokedFile get() = File(dir, "dns-blocklist-v2.revoked")

    fun load(): Saved? = try {
        if (!blobFile.exists()) null else {
            val meta = if (metaFile.exists()) JSONObject(metaFile.readText()) else JSONObject()
            Saved(blobFile.readBytes(), meta.optString("etag").ifEmpty { null }, meta.optLong("fetchedAt", 0L))
        }
    } catch (_: Exception) {
        null
    }

    /**
     * The fetch stamp alone, from the small meta file — lets a reader tell
     * "same list as last time" without re-reading the ~2.6 MB body. Null
     * when no list is stored.
     */
    fun fetchedAtMs(): Long? = try {
        when {
            !blobFile.exists() -> null
            metaFile.exists() -> JSONObject(metaFile.readText()).optLong("fetchedAt", 0L)
            else -> 0L
        }
    } catch (_: Exception) {
        null
    }

    fun save(body: ByteArray, etag: String?, fetchedAtMs: Long) {
        dir.mkdirs()
        writeAtomicBytes(blobFile, body)
        writeAtomic(metaFile, JSONObject().put("etag", etag ?: "").put("fetchedAt", fetchedAtMs).toString())
        revokedFile.delete()
    }

    /**
     * The publisher revoked the list. Remembered on its own, after the list
     * itself is cleared: without it, the next start finds no synced list and
     * falls back to the seed bundled in the APK — switching back on exactly
     * the blocking the kill switch turned off. A later good list clears it.
     */
    fun markRevoked() {
        dir.mkdirs()
        writeAtomic(revokedFile, "revoked\n")
    }

    fun isRevoked(): Boolean = revokedFile.exists()

    /** 304: same content, just refresh the fetch time. */
    fun touch(fetchedAtMs: Long) {
        val meta = if (metaFile.exists()) runCatching { JSONObject(metaFile.readText()) }.getOrNull() ?: JSONObject() else JSONObject()
        writeAtomic(metaFile, meta.put("fetchedAt", fetchedAtMs).toString())
    }

    fun clear() {
        blobFile.delete(); metaFile.delete()
    }

    private fun writeAtomicBytes(target: File, content: ByteArray) {
        val tmp = File(target.parentFile, target.name + ".tmp")
        tmp.writeBytes(content)
        if (!tmp.renameTo(target)) {
            target.delete()
            tmp.renameTo(target)
        }
    }

    private fun writeAtomic(target: File, content: String) {
        val tmp = File(target.parentFile, target.name + ".tmp")
        tmp.writeText(content)
        if (!tmp.renameTo(target)) {
            target.delete()
            tmp.renameTo(target)
        }
    }
}

/**
 * Pure scheduling policy (JVM-tested): when to fetch, how to back off.
 *  - on start: fetch if the stored list is older than [REFRESH_MS]/2
 *  - steady state: every [REFRESH_MS] ± 10 % jitter (phones must not
 *    synchronise on the server)
 *  - failures: 5 → 15 → 60 min, then every 60 min
 *  - a network coming back after a failure: once, sooner, as soon as
 *    Android confirms it reaches the internet ([retryOnReconnect])
 */
object SyncPolicy {
    const val REFRESH_MS = 6L * 60 * 60 * 1000

    /**
     * Metered networks used to hold refreshes back for 24h, because a full
     * artifact is ~2.5 MB and that is real money on a prepaid bundle. Deltas
     * removed the trade: a refresh now carries the CHANGES (measured 0.2% per
     * half day, about 6 KB), so a phone can stay current on cellular for the
     * price of a small image. The only expensive case left is a phone that
     * has been off long enough for its base version's delta to expire, which
     * is rare and still better than running an old blocklist.
     */
    const val METERED_MIN_AGE_MS = 24L * 60 * 60 * 1000

    private val BACKOFF_MS = longArrayOf(5L * 60_000, 15L * 60_000, 60L * 60_000)

    fun shouldFetchOnStart(storedAgeMs: Long?, refreshMs: Long = REFRESH_MS): Boolean = storedAgeMs == null || storedAgeMs > refreshMs / 2

    /**
     * Is this fetch worth the person's data right now? Always yes with no
     * list at all — an unprotected phone is the worse trade.
     */
    fun shouldFetchNow(storedAgeMs: Long?, metered: Boolean, hasBaseVersion: Boolean = false): Boolean {
        if (storedAgeMs == null) return true          // no list: protection first
        if (!metered) return true
        if (hasBaseVersion) return true               // a delta costs kilobytes
        return storedAgeMs >= METERED_MIN_AGE_MS
    }

    /** [refreshMs] is the steady-state cadence: 6 h as shipped, a week in the shield's BASIC mode. Failures back off the same way. */
    fun nextDelayMs(consecutiveFailures: Int, jitterSeed: Long = 0L, refreshMs: Long = REFRESH_MS): Long {
        if (consecutiveFailures > 0) return BACKOFF_MS[minOf(consecutiveFailures, BACKOFF_MS.size) - 1]
        // ±10 % deterministic jitter from the seed (tests pass a fixed seed).
        val spread = refreshMs / 10
        val offset = (Math.floorMod(jitterSeed, 2 * spread + 1)) - spread
        return refreshMs + offset
    }

    /**
     * A network just appeared, or Android just confirmed that it reaches the
     * internet: fetch now instead of waiting out the backoff?
     *
     * Only when the last attempt failed BEFORE that — the phone was offline,
     * on another network, or on this one before Android had confirmed it. A
     * fetch that failed on this very, confirmed network says the server is
     * out of reach from here (throttled, or blocked from Russia), and the
     * backoff already paces that.
     *
     * Not while the network is unconfirmed ([networkValidated] false): a
     * Wi-Fi still on its sign-in page, a cellular link still attaching in a
     * basement. A fetch there fails and would spend the one retry just before
     * the connection starts working; the confirmation is the arrival that
     * counts. A network that is never confirmed is left to the backoff.
     *
     * And never more often than the backoff itself: at the edge of coverage a
     * phone can lose and regain its network every few seconds. All times
     * monotonic.
     */
    fun retryOnReconnect(
        consecutiveFailures: Int,
        lastFailureAtMs: Long,
        networkSinceMs: Long,
        networkValidated: Boolean,
        lastReconnectRetryAtMs: Long?,
        nowMs: Long,
    ): Boolean {
        if (consecutiveFailures == 0 || !networkValidated || lastFailureAtMs >= networkSinceMs) return false
        return lastReconnectRetryAtMs == null || nowMs - lastReconnectRetryAtMs >= nextDelayMs(consecutiveFailures)
    }

    /** How long a network gets to settle (its DNS, routes) after it arrives or is confirmed, before that retry. */
    const val RECONNECT_SETTLE_MS = 10_000L
}

/**
 * Keeps the service's BlockList fresh. Owns nothing on the DNS thread: the
 * DNS loop only ever reads the @Volatile reference the [onSwap] callback sets.
 */
class BlocklistSync(
    private val store: BlocklistStore,
    private val fetcher: BlocklistFetcher,
    private val popularVeto: Set<String>,
    private val sharedSuffixes: Set<String>,
    private val url: String,
    private val nowMs: () -> Long,
    private val elapsedMs: () -> Long,
    private val onSwap: (BlockList) -> Unit,
    /** True when the active network charges for data (ConnectivityManager). */
    private val isMetered: () -> Boolean = { false },
    /**
     * When the next attempt is due, [delayMs] from now; the service arms its
     * wake-up alarm here. Called around every attempt (see [attempt]) and
     * after a start that needed none.
     */
    private val onNextDue: (delayMs: Long) -> Unit = {},
    /**
     * The steady-state cadence right now: 6 h as shipped, a week in the
     * shield's BASIC mode (ProtectionPolicy.refreshMs). Read at every
     * scheduling decision, so a mode change takes effect at the next one.
     */
    private val refreshMs: () -> Long = { SyncPolicy.REFRESH_MS },
) {
    @Volatile var lastError: String? = null; private set
    @Volatile var consecutiveFailures = 0; private set
    @Volatile var currentEtag: String? = null; private set
    @Volatile var lastFetchAtMs: Long = 0L; private set
    /** Bytes moved by the last successful fetch — surfaced so "it eats my data" is answerable. */
    @Volatile var lastFetchBytes: Int = 0; private set
    @Volatile private var currentVersion: Long = 0L
    /** The pending retry after a network arrived (see [onNetworkArrived]). */
    private var future: ScheduledFuture<*>? = null
    /** Monotonic times for [SyncPolicy.retryOnReconnect]. */
    @Volatile private var lastFailureAtMs = 0L
    @Volatile private var networkSinceMs = 0L
    @Volatile private var networkValidated = true
    @Volatile private var lastReconnectRetryAtMs: Long? = null
    /** The list we hold, so a delta has something to apply to. */
    @Volatile private var currentList: BlockList? = null
    /**
     * The seed's bytes while the seed is what we hold. If the server answers
     * 304 — the seed IS the current list — they are stored as the synced
     * list, and the phone never downloads 2.6 MB it already carries.
     */
    @Volatile private var seedBody: ByteArray? = null

    /** Load what is on disk (fast, synchronous — call before the DNS loop). */
    fun loadFromDisk(): BlockList? {
        val saved = store.load() ?: return null
        // Back-date the monotonic clock to the fetch, but never below zero:
        // after a reboot the phone has been up for less time than the list has
        // existed, and a negative base inflated the reported age.
        val sinceFetch = (nowMs() - saved.fetchedAtMs).coerceAtLeast(0L)
        val list = BlockList.parse(
            saved.body, popularVeto, nowMs = saved.fetchedAtMs,
            elapsedMs = (elapsedMs() - sinceFetch).coerceAtLeast(0L), sharedSuffixes = sharedSuffixes,
        )
        if (list == null) {
            Log.w(TAG, "stored blocklist rejected — clearing")
            store.clear()
            return null
        }
        currentEtag = saved.etag
        lastFetchAtMs = saved.fetchedAtMs
        currentVersion = list.version
        currentList = list
        onSwap(list)
        return list
    }

    /**
     * Start from the list bundled in the APK ([SeedBlocklist]) because none
     * was ever synced. The seed is held like a synced list — a delta can
     * apply to it — but it is not one: lastFetchAtMs stays 0, so [start]
     * fetches at once, and the first list the server sends replaces it.
     */
    fun adoptSeed(list: BlockList, body: ByteArray) {
        currentEtag = "\"" + sha256Hex(body) + "\""
        currentVersion = list.version
        currentList = list
        seedBody = body
        onSwap(list)
    }

    /** One fetch. Returns true if a new list was applied or confirmed fresh. */
    fun refreshOnce(force: Boolean = false): Boolean {
        val age = if (lastFetchAtMs > 0) nowMs() - lastFetchAtMs else null
        if (!force && !SyncPolicy.shouldFetchNow(age, isMetered(), hasBaseVersion = currentVersion > 0L)) {
            Log.i(TAG, "blocklist_fetch_skipped: metered network, list is ${(age ?: 0) / 3_600_000}h old")
            return false
        }
        // Name the version we already hold: the server answers with a few KB
        // of changes instead of 2.5 MB. Measured 0.2% churn per half day.
        val requestUrl = if (currentVersion > 0L) "$url?from=$currentVersion" else url
        return when (val res = fetcher.fetch(requestUrl, currentEtag)) {
            is FetchResult.NotModified -> {
                lastFetchAtMs = nowMs(); consecutiveFailures = 0; lastError = null
                val seed = seedBody
                if (seed != null) {
                    // The bundled seed is the list the server publishes now.
                    store.save(seed, currentEtag, lastFetchAtMs)
                    seedBody = null
                } else {
                    store.touch(lastFetchAtMs)
                }
                Log.i(TAG, "blocklist_not_modified")
                true
            }
            is FetchResult.Ok -> {
                val expected = etagSha(res.etag)
                if (expected != null && sha256Hex(res.body) != expected) {
                    fail("sha256 mismatch"); return false
                }
                // A delta is only trusted once the merge reproduces the exact
                // bytes the publisher hashed; anything else falls back to a
                // full fetch rather than running on a set nobody published.
                val full: ByteArray = if (BlockList.isDelta(res.body)) {
                    val base = currentList
                    val rebuilt = if (base == null) null else BlockList.applyDelta(base, res.body)
                    if (rebuilt == null) {
                        fail("delta did not apply — refetching in full")
                        currentVersion = 0L
                        currentEtag = null
                        return false
                    }
                    Log.i(TAG, "blocklist_delta_applied bytes=${res.body.size} -> full=${rebuilt.size}")
                    rebuilt
                } else {
                    res.body
                }
                val list = BlockList.parse(full, popularVeto, nowMs = nowMs(), elapsedMs = elapsedMs(),
                                           sharedSuffixes = sharedSuffixes)
                if (list == null) { fail("artifact rejected by parser"); return false }
                lastFetchAtMs = nowMs(); consecutiveFailures = 0; lastError = null
                lastFetchBytes = res.body.size
                // The stored ETag belongs to the FULL artifact, so a later
                // conditional request compares like with like.
                currentEtag = if (BlockList.isDelta(res.body)) null else res.etag
                currentVersion = if (list.revoked) 0L else list.version
                currentList = list
                seedBody = null
                if (list.revoked) {
                    store.clear()
                    store.markRevoked()
                } else {
                    store.save(full, currentEtag, lastFetchAtMs)
                }
                onSwap(list)
                Log.i(TAG, "blocklist_loaded version=${list.version} count=${list.count} revoked=${list.revoked}")
                true
            }
            is FetchResult.Failed -> { fail(res.reason); false }
        }
    }

    private fun fail(reason: String) {
        consecutiveFailures += 1
        lastError = reason
        lastFailureAtMs = elapsedMs()
        Log.w(TAG, "blocklist_fetch_failed: $reason (fail #$consecutiveFailures)")
    }

    /**
     * One fetch, with the wake-up for the next one armed on both sides of it.
     * Every path that fetches goes through here — start, the alarm,
     * pull-to-refresh, a network coming back.
     *
     * Before the fetch: the next failure step, so a fetch that never reports
     * back still has a wake-up behind it. Nothing keeps the phone awake while
     * it runs; a CPU that suspends mid-download leaves it hanging until
     * something else wakes the phone. After the fetch: from its result — 6 h
     * ± jitter after a good one, the next backoff step after a failed one.
     * 1.0.2 armed it only before the queued fetch had run, from the previous
     * attempt's failure count: a phone that started offline (or could not
     * reach the server) waited six hours for its next try, not five minutes.
     *
     * Anything thrown is a failed fetch, an Error too: an OutOfMemoryError
     * while a delta is merged into the ~2.6 MB list on a small phone would
     * otherwise vanish inside the executor and leave no wake-up after it.
     */
    fun attempt(force: Boolean = false): Boolean {
        onNextDue(SyncPolicy.nextDelayMs(consecutiveFailures + 1))
        val ok = try {
            refreshOnce(force)
        } catch (e: Throwable) {
            fail("unexpected: ${e.javaClass.simpleName}: ${e.message}")
            false
        }
        onNextDue(nextDelayMs())
        return ok
    }

    /**
     * Kick the initial fetch if the stored list is old/absent. The recurring
     * cadence is driven by AlarmManager (BlocklistAlarm) so it survives Doze;
     * this only handles "get something fresh now that the shield came up".
     */
    fun start(executor: Executor) {
        val age = if (lastFetchAtMs > 0) nowMs() - lastFetchAtMs else null
        if (SyncPolicy.shouldFetchOnStart(age, refreshMs())) {
            executor.execute { attempt() }
        } else {
            onNextDue(nextDelayMs())
        }
    }

    /**
     * A network appeared, the phone moved to another one, or Android has just
     * confirmed that the network reaches the internet ([validated] — see
     * [UnderlyingDns.isArrival]). If the last fetch failed before that, try
     * again once the network has settled — not at the end of a backoff that
     * was counting a dead connection. Debounced: a burst of network callbacks
     * makes one retry.
     */
    @Synchronized
    fun onNetworkArrived(
        executor: ScheduledExecutorService,
        validated: Boolean,
        settleMs: Long = SyncPolicy.RECONNECT_SETTLE_MS,
    ) {
        networkSinceMs = elapsedMs()
        networkValidated = validated
        future?.cancel(false)
        future = try {
            executor.schedule({ retryIfReconnected() }, settleMs, TimeUnit.MILLISECONDS)
        } catch (e: RejectedExecutionException) {
            null // the service is shutting down
        }
    }

    /** The settled half of [onNetworkArrived]. True when it fetched. */
    fun retryIfReconnected(): Boolean {
        val now = elapsedMs()
        val retry = SyncPolicy.retryOnReconnect(
            consecutiveFailures, lastFailureAtMs, networkSinceMs, networkValidated, lastReconnectRetryAtMs, now,
        )
        if (!retry) return false
        lastReconnectRetryAtMs = now
        Log.i(TAG, "blocklist_retry_on_reconnect after fail #$consecutiveFailures")
        attempt()
        return true
    }

    /** How long until the next scheduled refresh should fire (Doze-safe alarm). */
    fun nextDelayMs(): Long = SyncPolicy.nextDelayMs(consecutiveFailures, nowMs(), refreshMs())

    @Synchronized
    fun stop() { future?.cancel(false); future = null }

    companion object {
        private const val TAG = "CleanwayBlocklist"

        /**
         * The sha256 carried by an ETag. Edges that gzip the body rewrite our
         * strong ETag into a weak one (`W/"<sha>"`) — same content, different
         * representation — so strip the weak marker and the quotes. Null when
         * the header is missing or not a sha (then no verification is done).
         */
        fun etagSha(etag: String?): String? {
            val t = etag?.trim()?.removePrefix("W/")?.trim('"')?.lowercase() ?: return null
            return if (Regex("^[0-9a-f]{64}$").matches(t)) t else null
        }

        fun sha256Hex(body: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(body)
                .joinToString("") { "%02x".format(it) }
    }
}

/**
 * The real fetcher: plain HttpURLConnection, conditional GET, gzip, hard caps.
 * No cookies, no identifiers — the only header that says who we are is the
 * User-Agent, and it says only "Cleanway-Android".
 */
class HttpBlocklistFetcher(private val userAgent: String = "Cleanway-Android") : BlocklistFetcher {
    override fun fetch(url: String, etag: String?): FetchResult {
        var conn: HttpURLConnection? = null
        return try {
            conn = (URL(url).openConnection() as HttpURLConnection).apply {
                connectTimeout = 5_000
                readTimeout = 10_000
                requestMethod = "GET"
                instanceFollowRedirects = false
                setRequestProperty("Accept", "application/octet-stream")
                setRequestProperty("Accept-Encoding", "gzip")
                setRequestProperty("User-Agent", userAgent)
                if (etag != null) setRequestProperty("If-None-Match", etag)
            }
            when (val code = conn.responseCode) {
                304 -> FetchResult.NotModified
                200 -> {
                    val stream: InputStream = if (conn.contentEncoding == "gzip") GZIPInputStream(conn.inputStream) else conn.inputStream
                    val bytes = stream.use { readCapped(it, BlockList.MAX_BYTES) } ?: return FetchResult.Failed("body over ${BlockList.MAX_BYTES} bytes")
                    FetchResult.Ok(bytes, conn.getHeaderField("ETag"))
                }
                else -> FetchResult.Failed("http $code")
            }
        } catch (e: Exception) {
            FetchResult.Failed(e.javaClass.simpleName + ": " + (e.message ?: ""))
        } finally {
            conn?.disconnect()
        }
    }

    private fun readCapped(input: InputStream, cap: Int): ByteArray? {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(16 * 1024)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            out.write(buf, 0, n)
            if (out.size() > cap) return null
        }
        return out.toByteArray()
    }
}
