package ai.cleanway.app

import java.util.concurrent.Executor
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * When the next blocklist fetch happens (BlocklistSync.attempt / start /
 * onNetworkArrived, SyncPolicy.retryOnReconnect).
 *
 * The 1.0.2 emulator run: the service armed its wake-up alarm right after
 * QUEUEING the first fetch, from the failure count of the attempt before it
 * (none). A phone that started offline — or could not reach the server from
 * Russia — got its next try in about six hours instead of five minutes, and
 * the alarm path had the same off-by-one. These pin the wake-up to the result.
 */
class BlocklistScheduleTest {
    @get:Rule val tmp = TemporaryFolder()

    private val direct = Executor { it.run() }

    /** Takes the debounced retry and never runs it: the tests call retryIfReconnected themselves. */
    private val idle = ScheduledThreadPoolExecutor(1)

    @After
    fun stopIdle() {
        idle.shutdownNow()
    }
    private val fiveMin = 5L * 60_000
    private val fifteenMin = 15L * 60_000
    private val hour = 60L * 60_000

    private fun artifact(vararg names: String): ByteArray =
        BlockList.render(names.map { BlockList.hashOf(it) }.distinct().sorted().toLongArray(), 100L)

    private fun ok(): FetchResult {
        val body = artifact("evil.example")
        return FetchResult.Ok(body, "\"" + BlocklistSync.sha256Hex(body) + "\"")
    }

    private class Script(vararg results: FetchResult) : BlocklistFetcher {
        private val queue = ArrayDeque(results.toList())
        var calls = 0
        override fun fetch(url: String, etag: String?): FetchResult {
            calls++
            return if (queue.size > 1) queue.removeFirst() else queue.first()
        }
    }

    /** A sync with a movable monotonic clock that records every armed delay. */
    private inner class Harness(fetcher: BlocklistFetcher, store: BlocklistStore = BlocklistStore(tmp.newFolder())) {
        var elapsed = 1_000L
        val armed = mutableListOf<Long>()
        val sync = BlocklistSync(
            store, fetcher, emptySet(), emptySet(), "https://x/list",
            nowMs = { 1_727_000_000_000L + elapsed }, elapsedMs = { elapsed },
            onSwap = {}, onAttempted = { armed += it },
        )
    }

    private fun isNormalCadence(delay: Long) =
        delay >= SyncPolicy.REFRESH_MS * 9 / 10 && delay <= SyncPolicy.REFRESH_MS * 11 / 10

    @Test
    fun `a failed first fetch arms the next try in five minutes, not six hours`() {
        val h = Harness(Script(FetchResult.Failed("UnknownHostException: api.cleanway.ai")))
        h.sync.start(direct)
        assertEquals(listOf(fiveMin), h.armed)
    }

    @Test
    fun `a good first fetch arms the normal cadence`() {
        val h = Harness(Script(ok()))
        h.sync.start(direct)
        assertEquals(1, h.armed.size)
        assertTrue(isNormalCadence(h.armed.single()))
    }

    @Test
    fun `a fresh stored list needs no fetch at start, and the cadence is still armed`() {
        val body = artifact("evil.example")
        val store = BlocklistStore(tmp.newFolder())
        val fetcher = Script(ok())
        val h = Harness(fetcher, store)
        store.save(body, null, 1_727_000_000_000L + h.elapsed - 60_000L)
        h.sync.loadFromDisk()
        h.sync.start(direct)
        assertEquals(0, fetcher.calls)
        assertTrue(isNormalCadence(h.armed.single()))
    }

    @Test
    fun `each alarm attempt re-arms from its own result`() {
        val h = Harness(Script(FetchResult.Failed("http 429"), FetchResult.Failed("http 429"), FetchResult.Failed("http 429"), ok()))
        repeat(4) { h.sync.attempt() }
        assertEquals(listOf(fiveMin, fifteenMin, hour), h.armed.take(3))
        assertTrue(isNormalCadence(h.armed[3]))
    }

    @Test
    fun `an unexpected exception counts as a failure and still arms the backoff`() {
        val h = Harness(BlocklistFetcher { _, _ -> throw IllegalStateException("boom") })
        assertFalse(h.sync.attempt())
        assertEquals(listOf(fiveMin), h.armed)
        assertEquals(1, h.sync.consecutiveFailures)
    }

    // ── a network coming back ─────────────────────────────────────────

    @Test
    fun `a network coming back after an offline failure fetches at once`() {
        val fetcher = Script(FetchResult.Failed("UnknownHostException"), ok())
        val h = Harness(fetcher)
        h.sync.attempt()                 // offline at start
        h.elapsed += 2 * 60_000          // two minutes later Wi-Fi is back
        h.sync.onNetworkArrived(idle, settleMs = 60_000)
        h.elapsed += SyncPolicy.RECONNECT_SETTLE_MS
        assertTrue(h.sync.retryIfReconnected())
        assertEquals(2, fetcher.calls)
        assertEquals(0, h.sync.consecutiveFailures)
        assertTrue(isNormalCadence(h.armed.last()))
    }

    @Test
    fun `a failure on the network the phone is already on waits for the backoff`() {
        // The server is out of reach from here (throttled, blocked): the
        // connection is fine, so a network callback is no reason to retry.
        val fetcher = Script(FetchResult.Failed("http 429"))
        val h = Harness(fetcher)
        h.sync.onNetworkArrived(idle, settleMs = 60_000)
        h.elapsed += 3_000
        h.sync.attempt()
        h.elapsed += SyncPolicy.RECONNECT_SETTLE_MS
        assertFalse(h.sync.retryIfReconnected())
        assertEquals(1, fetcher.calls)
    }

    @Test
    fun `a flapping network retries at most once per backoff step`() {
        val fetcher = Script(FetchResult.Failed("UnknownHostException"))
        val h = Harness(fetcher)
        h.sync.attempt()                                   // fail #1
        val tries = (1..6).count {
            h.elapsed += 30_000                            // lost and back every 30 s
            h.sync.onNetworkArrived(idle, settleMs = 60_000)
            h.sync.retryIfReconnected()
        }
        assertEquals(1, tries)                             // fail #2 → next reconnect retry only after 15 min
        h.elapsed += fifteenMin
        h.sync.onNetworkArrived(idle, settleMs = 60_000)
        assertTrue(h.sync.retryIfReconnected())
    }

    @Test
    fun `callbacks in a burst make one retry`() {
        val fetcher = Script(FetchResult.Failed("UnknownHostException"), ok())
        val h = Harness(fetcher)
        h.sync.attempt()
        h.elapsed += 60_000
        val executor = ScheduledThreadPoolExecutor(1)
        repeat(5) { h.sync.onNetworkArrived(executor, settleMs = 50) }
        executor.shutdown()                                // delayed tasks still run
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
        assertEquals(2, fetcher.calls)
    }

    @Test
    fun `retry-on-reconnect policy`() {
        val cases = listOf(
            // failures, lastFailureAt, networkSince, lastReconnectRetryAt, now → retry
            listOf(0L, 0L, 10L, null, 20L) to false,       // nothing failed
            listOf(1L, 5L, 10L, null, 20L) to true,        // failed, then the network came
            listOf(1L, 10L, 10L, null, 20L) to false,      // failed on this network
            listOf(1L, 15L, 10L, null, 20L) to false,
            listOf(2L, 5L, 10L, 0L, fifteenMin - 1) to false, // retried too recently
            listOf(2L, 5L, 10L, 0L, fifteenMin) to true,
        )
        for ((args, expected) in cases) {
            val actual = SyncPolicy.retryOnReconnect(
                (args[0] as Long).toInt(), args[1] as Long, args[2] as Long, args[3], args[4] as Long,
            )
            assertEquals("case $args", expected, actual)
        }
    }
}
