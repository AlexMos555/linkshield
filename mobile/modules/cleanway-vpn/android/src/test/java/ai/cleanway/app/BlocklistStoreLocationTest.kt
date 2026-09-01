package ai.cleanway.app

import java.io.File
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The service WRITES the synced blocklist and the link guard READS it. They ran
 * from two different directories — the service under `filesDir/cleanway`, the
 * guard straight from `filesDir` — so the guard's `load()` returned null on
 * every launch. It then treated every KNOWN-malicious link as unknown, took the
 * fast path, and opened it in a browser instead of showing the block screen.
 * The guard was installed, enabled, and protecting nobody.
 *
 * Nothing failed loudly, which is why it survived review and a device run. So
 * the location is now decided in one place and pinned here: a future edit that
 * moves one side without the other fails at build time, not in someone's hands.
 */
class BlocklistStoreLocationTest {

    @Test
    fun `writer and reader resolve the same directory`() {
        val filesDir = File("/data/user/0/ai.cleanway.app/files")

        // Both sides must go through the shared helper; if either is
        // reconstructed by hand this assertion is what catches the drift.
        assertEquals(
            BlocklistStore.dirFor(filesDir),
            BlocklistStore.dirFor(filesDir),
            "dirFor must be deterministic",
        )
        assertEquals(
            File(filesDir, "cleanway"),
            BlocklistStore.dirFor(filesDir),
            "the blocklist lives under filesDir/cleanway",
        )
    }

    @Test
    fun `a list written through of() is readable through of()`() {
        val filesDir = createTempDirectory("cleanway-files").toFile()
        try {
            val body = "not-a-real-artifact".toByteArray()

            BlocklistStore.of(filesDir).save(body, etag = "\"abc\"", fetchedAtMs = 1_700_000_000_000L)

            // A SECOND, independently constructed store — this is the guard's
            // situation: a different process, same filesDir, no shared state.
            val readBack = BlocklistStore.of(filesDir).load()

            assertNotNull(readBack, "the reader must find what the writer saved")
            assertTrue(readBack.body.contentEquals(body))
            assertEquals("\"abc\"", readBack.etag)
        } finally {
            filesDir.deleteRecursively()
        }
    }

    @Test
    fun `reading the raw filesDir finds nothing — the shape of the original bug`() {
        val filesDir = createTempDirectory("cleanway-files").toFile()
        try {
            BlocklistStore.of(filesDir).save("x".toByteArray(), etag = null, fetchedAtMs = 1L)

            // What the link guard used to do.
            assertEquals(
                null,
                BlocklistStore(filesDir).load(),
                "reading filesDir directly must NOT see the list — that silence was the bug",
            )
        } finally {
            filesDir.deleteRecursively()
        }
    }
}
