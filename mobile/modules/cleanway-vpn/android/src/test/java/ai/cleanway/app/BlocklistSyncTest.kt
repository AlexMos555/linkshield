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

    /** v2 blob, the way the publisher renders it. */
    private fun artifact(vararg names: String, generated: Long = 100L): ByteArray {
        val hashes = names.map { BlockList.hashOf(it) }.distinct().sorted()
        val out = java.io.ByteArrayOutputStream()
        out.write("CWBL2\n".toByteArray())
        out.write("# cleanway-dns-blocklist v2 generated=$generated count=${hashes.size} status=ok\n".toByteArray())
        for (h in hashes) for (b in BlockList.HASH_BYTES - 1 downTo 0) out.write(((h shr (8 * b)) and 0xFF).toInt())
        return out.toByteArray()
    }

    private fun revokedArtifact(generated: Long = 9L): ByteArray =
        ("CWBL2\n# cleanway-dns-blocklist v2 generated=$generated count=0 status=revoked\n").toByteArray()

    private class FakeFetcher(var next: FetchResult) : BlocklistFetcher {
        var calls = 0
        var lastEtag: String? = null
        var lastUrl: String? = null
        override fun fetch(url: String, etag: String?): FetchResult {
            calls++; lastEtag = etag; lastUrl = url; return next
        }
    }

    private fun sync(fetcher: BlocklistFetcher, store: BlocklistStore = BlocklistStore(tmp.newFolder()), now: () -> Long = { 1_000L },
                     onSwap: (BlockList) -> Unit = {}, metered: () -> Boolean = { false }) =
        BlocklistSync(store, fetcher, veto, emptySet(), "https://x/list", nowMs = now, elapsedMs = { 5_000L },
                      onSwap = onSwap, isMetered = metered)

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
        assertTrue(text.contentEquals(store.load()!!.body))
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
        val bad = "CWBL2\n# cleanway-dns-blocklist v2 generated=1 count=2 status=ok\nnot-hashes".toByteArray()
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
    fun `metered policy - the full artifact waits, a delta never does`() {
        // A full artifact is ~2.5 MB: worth it on Wi-Fi, not worth a prepaid
        // bundle every few hours. A delta is kilobytes, so holding it back
        // would cost protection and save nothing. An absent list always wins.
        assertTrue(SyncPolicy.shouldFetchNow(null, metered = true))
        assertFalse(SyncPolicy.shouldFetchNow(60_000L, metered = true))
        assertTrue(SyncPolicy.shouldFetchNow(SyncPolicy.METERED_MIN_AGE_MS, metered = true))
        assertTrue(SyncPolicy.shouldFetchNow(60_000L, metered = false))
        assertTrue(SyncPolicy.shouldFetchNow(60_000L, metered = true, hasBaseVersion = true))

        // End to end: a phone holding a list refreshes on cellular, because
        // the request carries `from=` and the answer is a delta.
        val text = artifact("evil.example", generated = 100L)
        val etag = "\"" + BlocklistSync.sha256Hex(text) + "\""
        val store = BlocklistStore(tmp.newFolder())
        store.save(text, etag, 10L)
        val f = FakeFetcher(FetchResult.NotModified)
        val s = sync(f, store, now = { 60_000L }, metered = { true })
        assertNotNull(s.loadFromDisk())
        assertTrue(s.refreshOnce())
        assertEquals(1, f.calls)
        assertEquals("https://x/list?from=100", f.lastUrl)
    }

    @Test
    fun `steady-state delay is six hours with bounded jitter`() {
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
        val text = revokedArtifact()
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
        store.save("garbage".toByteArray(), null, 1L)
        val s = sync(FakeFetcher(FetchResult.NotModified), store)
        assertNull(s.loadFromDisk())
        assertNull(store.load())
    }
}

/**
 * Deltas. Measured on the real feed: 13 hours of movement is 0.2% of the list
 * — about 6 KB against a 2.5 MB artifact. That is the difference between a
 * phone staying current on a metered plan and one waiting a day.
 *
 * The safety property is the rebuild: a delta is trusted only once the merged
 * set reproduces the exact bytes the publisher hashed.
 */
class BlocklistDeltaTest {

    private val veto = setOf("paypal.com")

    private fun artifact(names: List<String>, generated: Long): ByteArray =
        BlockList.render(names.map { BlockList.hashOf(it) }.distinct().sorted().toLongArray(), generated)

    private fun sha(b: ByteArray) = BlocklistSync.sha256Hex(b)

    private fun delta(from: Long, to: Long, added: List<String>, removed: List<String>, targetSha: String): ByteArray {
        val a = added.map { BlockList.hashOf(it) }.sorted()
        val r = removed.map { BlockList.hashOf(it) }.sorted()
        val out = java.io.ByteArrayOutputStream()
        out.write("CWBD1\n".toByteArray())
        out.write(("# cleanway-dns-blocklist-delta v2 from=$from to=$to added=${a.size} removed=${r.size} sha256=$targetSha\n").toByteArray())
        for (h in a + r) for (b in BlockList.HASH_BYTES - 1 downTo 0) out.write(((h shr (8 * b)) and 0xFF).toInt())
        return out.toByteArray()
    }

    @Test
    fun `a delta lands exactly on the published artifact`() {
        val before = listOf("a.example", "b.example", "gone.example")
        val after = listOf("a.example", "b.example", "fresh.example")
        val oldBlob = artifact(before, 100L)
        val newBlob = artifact(after, 200L)
        val list = BlockList.parse(oldBlob, veto, nowMs = 0L)!!
        val d = delta(100L, 200L, listOf("fresh.example"), listOf("gone.example"), sha(newBlob))

        assertTrue(BlockList.isDelta(d))
        val rebuilt = BlockList.applyDelta(list, d)
        assertNotNull(rebuilt)
        assertTrue(newBlob.contentEquals(rebuilt!!))
        val merged = BlockList.parse(rebuilt, veto, nowMs = 0L)!!
        assertEquals("fresh.example", merged.match("www.fresh.example"))
        assertNull(merged.match("gone.example"))
    }

    @Test
    fun `a delta that does not reproduce the published bytes is refused`() {
        val list = BlockList.parse(artifact(listOf("a.example"), 100L), veto, nowMs = 0L)!!
        // Right shape, wrong target hash: the merge is not what was published.
        assertNull(BlockList.applyDelta(list, delta(100L, 200L, listOf("x.example"), emptyList(), "0".repeat(64))))
        // Base version mismatch — this delta is for someone else's list.
        val good = artifact(listOf("a.example", "x.example"), 200L)
        assertNull(BlockList.applyDelta(list, delta(999L, 200L, listOf("x.example"), emptyList(), sha(good))))
        // Truncated body.
        val d = delta(100L, 200L, listOf("x.example"), emptyList(), sha(good))
        assertNull(BlockList.applyDelta(list, d.copyOfRange(0, d.size - 1)))
    }

    @Test
    fun `sync applies a delta and keeps serving from the merged list`() {
        val before = listOf("a.example", "gone.example")
        val after = listOf("a.example", "fresh.example")
        val oldBlob = artifact(before, 100L)
        val newBlob = artifact(after, 200L)
        val store = BlocklistStore(tmp.newFolder())
        store.save(oldBlob, "\"${sha(oldBlob)}\"", 10L)

        val d = delta(100L, 200L, listOf("fresh.example"), listOf("gone.example"), sha(newBlob))
        val fetcher = object : BlocklistFetcher {
            var lastUrl: String? = null
            override fun fetch(url: String, etag: String?): FetchResult {
                lastUrl = url
                return FetchResult.Ok(d, "\"${sha(d)}\"")
            }
        }
        var swapped: BlockList? = null
        val s = BlocklistSync(store, fetcher, veto, emptySet(), "https://x/list",
                              nowMs = { 50_000L }, elapsedMs = { 5_000L }, onSwap = { swapped = it })
        assertNotNull(s.loadFromDisk())
        assertTrue(s.refreshOnce())
        // It asked for a delta from the version it held…
        assertEquals("https://x/list?from=100", fetcher.lastUrl)
        // …and now serves the merged list, with the FULL artifact on disk so
        // the next start needs no network at all.
        assertEquals(200L, swapped!!.version)
        assertEquals("fresh.example", swapped!!.match("fresh.example"))
        assertTrue(newBlob.contentEquals(store.load()!!.body))
        assertEquals(d.size, s.lastFetchBytes)
    }

    @get:Rule val tmp = TemporaryFolder()
}
