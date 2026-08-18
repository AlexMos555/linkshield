package ai.cleanway.app

import android.util.Log
import java.io.File
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPInputStream
import org.json.JSONObject

/** What one fetch of the artifact produced. */
sealed class FetchResult {
    data class Ok(val text: String, val etag: String?) : FetchResult()
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
    data class Saved(val text: String, val etag: String?, val fetchedAtMs: Long)

    private val textFile get() = File(dir, "dns-blocklist-v1.txt")
    private val metaFile get() = File(dir, "dns-blocklist-v1.meta.json")

    fun load(): Saved? = try {
        if (!textFile.exists()) null else {
            val meta = if (metaFile.exists()) JSONObject(metaFile.readText()) else JSONObject()
            Saved(textFile.readText(), meta.optString("etag").ifEmpty { null }, meta.optLong("fetchedAt", 0L))
        }
    } catch (_: Exception) {
        null
    }

    fun save(text: String, etag: String?, fetchedAtMs: Long) {
        dir.mkdirs()
        writeAtomic(textFile, text)
        writeAtomic(metaFile, JSONObject().put("etag", etag ?: "").put("fetchedAt", fetchedAtMs).toString())
    }

    /** 304: same content, just refresh the fetch time. */
    fun touch(fetchedAtMs: Long) {
        val meta = if (metaFile.exists()) runCatching { JSONObject(metaFile.readText()) }.getOrNull() ?: JSONObject() else JSONObject()
        writeAtomic(metaFile, meta.put("fetchedAt", fetchedAtMs).toString())
    }

    fun clear() {
        textFile.delete(); metaFile.delete()
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
 */
object SyncPolicy {
    const val REFRESH_MS = 2L * 60 * 60 * 1000
    private val BACKOFF_MS = longArrayOf(5L * 60_000, 15L * 60_000, 60L * 60_000)

    fun shouldFetchOnStart(storedAgeMs: Long?): Boolean = storedAgeMs == null || storedAgeMs > REFRESH_MS / 2

    fun nextDelayMs(consecutiveFailures: Int, jitterSeed: Long = 0L): Long {
        if (consecutiveFailures > 0) return BACKOFF_MS[minOf(consecutiveFailures, BACKOFF_MS.size) - 1]
        // ±10 % deterministic jitter from the seed (tests pass a fixed seed).
        val spread = REFRESH_MS / 10
        val offset = (Math.floorMod(jitterSeed, 2 * spread + 1)) - spread
        return REFRESH_MS + offset
    }
}

/**
 * Keeps the service's BlockList fresh. Owns nothing on the DNS thread: the
 * DNS loop only ever reads the @Volatile reference the [onSwap] callback sets.
 */
class BlocklistSync(
    private val store: BlocklistStore,
    private val fetcher: BlocklistFetcher,
    private val popularVeto: Set<String>,
    private val url: String,
    private val nowMs: () -> Long,
    private val elapsedMs: () -> Long,
    private val onSwap: (BlockList) -> Unit,
) {
    @Volatile var lastError: String? = null; private set
    @Volatile var consecutiveFailures = 0; private set
    @Volatile var currentEtag: String? = null; private set
    @Volatile var lastFetchAtMs: Long = 0L; private set
    private var future: ScheduledFuture<*>? = null

    /** Load what is on disk (fast, synchronous — call before the DNS loop). */
    fun loadFromDisk(): BlockList? {
        val saved = store.load() ?: return null
        val list = BlockList.parse(saved.text, popularVeto, nowMs = saved.fetchedAtMs, elapsedMs = elapsedMs() - (nowMs() - saved.fetchedAtMs))
        if (list == null) {
            Log.w(TAG, "stored blocklist rejected — clearing")
            store.clear()
            return null
        }
        currentEtag = saved.etag
        lastFetchAtMs = saved.fetchedAtMs
        onSwap(list)
        return list
    }

    /** One fetch. Returns true if a new list was applied or confirmed fresh. */
    fun refreshOnce(): Boolean {
        return when (val res = fetcher.fetch(url, currentEtag)) {
            is FetchResult.NotModified -> {
                lastFetchAtMs = nowMs(); consecutiveFailures = 0; lastError = null
                store.touch(lastFetchAtMs)
                Log.i(TAG, "blocklist_not_modified")
                true
            }
            is FetchResult.Ok -> {
                val expected = etagSha(res.etag)
                if (expected != null && sha256Hex(res.text) != expected) {
                    fail("sha256 mismatch"); return false
                }
                val list = BlockList.parse(res.text, popularVeto, nowMs = nowMs(), elapsedMs = elapsedMs())
                if (list == null) { fail("artifact rejected by parser"); return false }
                lastFetchAtMs = nowMs(); consecutiveFailures = 0; lastError = null
                currentEtag = res.etag
                if (list.revoked) store.clear() else store.save(res.text, res.etag, lastFetchAtMs)
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
        Log.w(TAG, "blocklist_fetch_failed: $reason (fail #$consecutiveFailures)")
    }

    /** Schedule: maybe fetch now, then keep going with the policy's delays. */
    fun start(executor: ScheduledExecutorService) {
        val age = if (lastFetchAtMs > 0) nowMs() - lastFetchAtMs else null
        val first = if (SyncPolicy.shouldFetchOnStart(age)) 0L else SyncPolicy.nextDelayMs(0, nowMs())
        schedule(executor, first)
    }

    private fun schedule(executor: ScheduledExecutorService, delayMs: Long) {
        future?.cancel(false)
        future = executor.schedule({
            try { refreshOnce() } catch (e: Exception) { fail("unexpected: ${e.message}") }
            schedule(executor, SyncPolicy.nextDelayMs(consecutiveFailures, nowMs()))
        }, delayMs, TimeUnit.MILLISECONDS)
    }

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

        fun sha256Hex(text: String): String =
            MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8))
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
                setRequestProperty("Accept", "text/plain")
                setRequestProperty("Accept-Encoding", "gzip")
                setRequestProperty("User-Agent", userAgent)
                if (etag != null) setRequestProperty("If-None-Match", etag)
            }
            when (val code = conn.responseCode) {
                304 -> FetchResult.NotModified
                200 -> {
                    val stream: InputStream = if (conn.contentEncoding == "gzip") GZIPInputStream(conn.inputStream) else conn.inputStream
                    val bytes = stream.use { readCapped(it, BlockList.MAX_BYTES) } ?: return FetchResult.Failed("body over ${BlockList.MAX_BYTES} bytes")
                    FetchResult.Ok(String(bytes, Charsets.UTF_8), conn.getHeaderField("ETag"))
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
