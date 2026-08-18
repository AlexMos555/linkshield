package ai.cleanway.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class BlocklistSyncTest {
    @get:Rule val tmp = TemporaryFolder()

    private val veto = setOf("paypal.com")
    private fun artifact(vararg names: String, generated: Long = 100L) =
        "# cleanway-dns-blocklist v1 generated=$generated count=${names.size} status=ok\n" +
            names.joinToString("\n") + "\n"

    private class FakeFetcher(var next: FetchResult) : BlocklistFetcher {
        var calls = 0
        var lastEtag: String? = null
        override fun fetch(url: String, etag: String?): FetchResult { calls++; lastEtag = etag; return next }
    }

    private fun sync(fetcher: BlocklistFetcher, store: BlocklistStore = BlocklistStore(tmp.newFolder()), now: () -> Long = { 1_000L },
                     onSwap: (BlockList) -> Unit = {}) =
        BlocklistSync(store, fetcher, veto, "https://x/list", nowMs = now, elapsedMs = { 5_000L }, onSwap = onSwap)

    @Test
    fun `200 with matching sha is parsed, stored and swapped in`() {
        val text = artifact("evil.example", "list-canary.cleanway.ai")
        val etag = "\"" + BlocklistSync.sha256Hex(text) + "\""
        val store = BlocklistStore(tmp.newFolder())
        var swapped: BlockList? = null
        val s = sync(FakeFetcher(FetchResult.Ok(text, etag)), store, onSwap = { swapped = it })
        assertTrue(s.refreshOnce())
        assertNotNull(swapped)
        assertEquals("evil.example", swapped!!.match("login.evil.example"))
        assertEquals(etag, s.currentEtag)
        assertEquals(text, store.load()!!.text)
        assertEquals(0, s.consecutiveFailures)
    }

    @Test
    fun `weak etags from a gzipping edge still verify`() {
        // Railway rewrites our strong ETag to W/"<sha>" when it gzips the body.
        // The first device fetch failed on exactly this ("sha256 mismatch").
        val text = artifact("evil.example")
        val sha = BlocklistSync.sha256Hex(text)
        assertEquals(sha, BlocklistSync.etagSha("W/\"$sha\""))
        assertEquals(sha, BlocklistSync.etagSha("\"$sha\""))
        assertEquals(sha, BlocklistSync.etagSha(sha.uppercase()))
        assertNull(BlocklistSync.etagSha(null))
        assertNull(BlocklistSync.etagSha("\"not-a-sha\""))
        var swaps = 0
        val s = sync(FakeFetcher(FetchResult.Ok(text, "W/\"$sha\"")), onSwap = { swaps++ })
        assertTrue(s.refreshOnce())
        assertEquals(1, swaps)
    }

    @Test
    fun `sha mismatch is rejected and the previous list survives`() {
        val text = artifact("evil.example")
        var swaps = 0
        val wrong = "\"" + "0".repeat(64) + "\""
        val s = sync(FakeFetcher(FetchResult.Ok(text, wrong)), onSwap = { swaps++ })
        assertFalse(s.refreshOnce())
        assertEquals(0, swaps)
        assertEquals(1, s.consecutiveFailures)
        assertTrue(s.lastError!!.contains("sha256"))
    }

    @Test
    fun `malformed artifact is rejected whole`() {
        val bad = "# cleanway-dns-blocklist v1 generated=1 count=2 status=ok\nok.example\ncom\n"
        var swaps = 0
        val s = sync(FakeFetcher(FetchResult.Ok(bad, null)), onSwap = { swaps++ })
        assertFalse(s.refreshOnce())
        assertEquals(0, swaps)
    }

    @Test
    fun `304 touches the fetch time and sends the stored etag`() {
        val text = artifact("evil.example")
        val etag = "\"" + BlocklistSync.sha256Hex(text) + "\""
        val store = BlocklistStore(tmp.newFolder())
        store.save(text, etag, 10L)
        val f = FakeFetcher(FetchResult.NotModified)
        var t = 50_000L
        val s = sync(f, store, now = { t })
        assertNotNull(s.loadFromDisk())
        assertTrue(s.refreshOnce())
        assertEquals(etag, f.lastEtag)
        assertEquals(50_000L, store.load()!!.fetchedAtMs)
        assertEquals(50_000L, s.lastFetchAtMs)
    }

    @Test
    fun `failures back off 5 then 15 then 60 minutes and reset on success`() {
        val f = FakeFetcher(FetchResult.Failed("http 429"))
        val s = sync(f)
        repeat(4) { assertFalse(s.refreshOnce()) }
        assertEquals(4, s.consecutiveFailures)
        assertEquals(5L * 60_000, SyncPolicy.nextDelayMs(1))
        assertEquals(15L * 60_000, SyncPolicy.nextDelayMs(2))
        assertEquals(60L * 60_000, SyncPolicy.nextDelayMs(3))
        assertEquals(60L * 60_000, SyncPolicy.nextDelayMs(9))
        f.next = FetchResult.NotModified
        assertTrue(s.refreshOnce())
        assertEquals(0, s.consecutiveFailures)
    }

    @Test
    fun `steady-state delay is two hours with bounded jitter`() {
        for (seed in listOf(0L, 1L, 12345L, -7L, Long.MAX_VALUE)) {
            val d = SyncPolicy.nextDelayMs(0, seed)
            assertTrue(d >= SyncPolicy.REFRESH_MS * 9 / 10 && d <= SyncPolicy.REFRESH_MS * 11 / 10)
        }
        assertTrue(SyncPolicy.shouldFetchOnStart(null))
        assertTrue(SyncPolicy.shouldFetchOnStart(SyncPolicy.REFRESH_MS))
        assertFalse(SyncPolicy.shouldFetchOnStart(10_000L))
    }

    @Test
    fun `revoked artifact clears storage and swaps in an empty list`() {
        val text = "# cleanway-dns-blocklist v1 generated=9 count=0 status=revoked\n"
        val store = BlocklistStore(tmp.newFolder())
        store.save(artifact("evil.example"), null, 1L)
        var swapped: BlockList? = null
        val s = sync(FakeFetcher(FetchResult.Ok(text, null)), store, onSwap = { swapped = it })
        assertTrue(s.refreshOnce())
        assertTrue(swapped!!.revoked)
        assertNull(store.load())
    }

    @Test
    fun `corrupt on-disk file is rejected and cleared on load`() {
        val store = BlocklistStore(tmp.newFolder())
        store.save("garbage", null, 1L)
        val s = sync(FakeFetcher(FetchResult.NotModified), store)
        assertNull(s.loadFromDisk())
        assertNull(store.load())
    }
}
