package ai.cleanway.app

import android.content.res.AssetManager
import android.util.Log
import java.io.FileNotFoundException

/**
 * The starter blocklist bundled in the APK (assets/[ASSET], same v2 format).
 *
 * A fresh install used to block nothing until the first 2.6 MB download from
 * our server finished — and for someone in Russia that download crosses the
 * border to a US host, the path most likely to be slow, throttled or cut.
 * With the seed the phone blocks known scam sites from its first minute,
 * whether or not our server is reachable.
 *
 * The seed is never newer in authority than a synced list: it is used only
 * when no list was ever synced ([applies]), and the first list the server
 * sends replaces it. Its age is its publisher's stamp, so a seed from an old
 * release reads as an old list in the app, never as a fresh one.
 *
 * The file is NOT in git: mobile/scripts/fetch-seed-blocklist.sh downloads
 * and verifies it at release-build time. A build without it simply has no
 * seed — [load] returns null and everything else works as before.
 */
object SeedBlocklist {
    const val ASSET = "dns-blocklist-v2.seed.bin"
    private const val TAG = "CleanwayBlocklist"

    /** The seed bytes and the list they parse to. */
    class Seed(val body: ByteArray, val list: BlockList)

    /** Only a phone with no synced list, and no revoke on record, starts from the seed. */
    fun applies(store: BlocklistStore): Boolean = store.fetchedAtMs() == null && !store.isRevoked()

    /**
     * Pure: a usable seed from [body], or null. A seed that is malformed,
     * empty or itself revoked is no seed.
     */
    fun parse(
        body: ByteArray?,
        popularVeto: Set<String>,
        sharedSuffixes: Set<String>,
        nowMs: Long,
        elapsedMs: Long,
    ): Seed? {
        if (body == null) return null
        val list = BlockList.parse(body, popularVeto, nowMs = nowMs, elapsedMs = elapsedMs, sharedSuffixes = sharedSuffixes)
            ?: return null
        if (list.revoked || list.count == 0) return null
        return Seed(body, list)
    }

    /** Read and parse the bundled seed; null when this build has none. */
    fun load(
        assets: AssetManager,
        popularVeto: Set<String>,
        sharedSuffixes: Set<String>,
        nowMs: Long,
        elapsedMs: Long,
    ): Seed? {
        val body = try {
            assets.open(ASSET).use { it.readBytes() }
        } catch (_: FileNotFoundException) {
            Log.i(TAG, "seed_absent — this build carries no starter list")
            return null
        } catch (e: Exception) {
            Log.w(TAG, "seed_unreadable: ${e.javaClass.simpleName}")
            return null
        }
        return parse(body, popularVeto, sharedSuffixes, nowMs, elapsedMs).also {
            if (it == null) Log.w(TAG, "seed_rejected by parser") else Log.i(TAG, "seed_loaded count=${it.list.count} version=${it.list.version}")
        }
    }
}
