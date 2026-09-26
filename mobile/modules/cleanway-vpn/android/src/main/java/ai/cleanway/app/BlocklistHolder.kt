package ai.cleanway.app

import android.content.Context
import android.util.Log

/**
 * The on-device blocklist for anything OUTSIDE the DNS loop — the link guard
 * and the message check.
 *
 * Two sources, in order:
 *  1. the running shield's live list (same process), so a check sees exactly
 *     what DNS is blocking with, including a refresh from a minute ago;
 *  2. otherwise the synced file on disk, parsed with the SAME popular-domain
 *     veto and shared-suffix set the service uses — without them a check
 *     could flag a popular domain the DNS layer allows, a false positive,
 *     the one thing this product guards against hardest.
 *
 * The disk copy is cached by the list's fetch stamp: a re-check reads only
 * the small meta file, not the ~2.6 MB body. Disk loads BLOCK — call from a
 * worker thread (the link guard's one call on the main thread predates this
 * holder and keeps its old behaviour).
 */
object BlocklistHolder {
    private const val TAG = "CleanwayBlocklist"
    private val lock = Any()
    @Volatile private var cached: BlockList? = null
    @Volatile private var cachedStamp: Long = -1L
    @Volatile private var veto: Set<String>? = null
    @Volatile private var shared: Set<String>? = null

    /** The list to check against, or null when none has ever been synced. */
    fun current(context: Context): BlockList? {
        val live = liveList()
        if (live != null) {
            release()
            return live
        }
        return fromDisk(context.applicationContext)
    }

    /**
     * Is there a list to check links with at all — the running shield's, or
     * a synced copy on disk? Reads only the small meta file, never the body.
     */
    fun available(context: Context): Boolean {
        val live = liveList()
        if (live != null) return live.count > 0 && !live.revoked
        return BlocklistStore.of(context.applicationContext.filesDir).fetchedAtMs() != null
    }

    private fun liveList(): BlockList? = CleanwayVpnService.instance
        ?.takeIf { CleanwayVpnService.isRunning }
        ?.currentBlockList()
        ?.takeIf { it.count > 0 || it.revoked }

    /**
     * The shield runs, so its own list is what every check reads. A disk copy
     * parsed while it was off (~3.5 MB, plus the veto sets) would otherwise
     * stay in this process for as long as the VPN keeps it alive.
     */
    private fun release() {
        if (cached == null && veto == null && shared == null) return
        synchronized(lock) {
            cached = null
            cachedStamp = -1L
            veto = null
            shared = null
        }
    }

    /** Sites the person marked "not a scam" — they outrank the list, as in DNS. */
    fun allowed(context: Context): Set<String> = try {
        UserAllow.list(context).toHashSet()
    } catch (e: Exception) {
        Log.w(TAG, "allow_read_error: ${e.message}")
        emptySet()
    }

    private fun fromDisk(context: Context): BlockList? {
        val store = BlocklistStore.of(context.filesDir)
        val stamp = store.fetchedAtMs() ?: return null
        synchronized(lock) {
            val hit = cached
            if (hit != null && cachedStamp == stamp) return hit
            val saved = store.load() ?: return null
            val list = BlockList.parse(
                saved.body,
                popularVeto = assetSet(context, "popular_veto.txt", veto) { veto = it },
                nowMs = System.currentTimeMillis(),
                sharedSuffixes = assetSet(context, "shared_suffixes.txt", shared) { shared = it },
            )
            cached = list
            cachedStamp = saved.fetchedAtMs
            return list
        }
    }

    /** Assets never change inside one install: read each once. */
    private fun assetSet(context: Context, name: String, have: Set<String>?, keep: (Set<String>) -> Unit): Set<String> {
        if (have != null) return have
        return try {
            context.assets.open(name).bufferedReader().useLines { lines ->
                lines.map { it.trim().lowercase() }.filter { it.isNotEmpty() && !it.startsWith("#") }.toHashSet()
            }.also(keep)
        } catch (e: Exception) {
            // Not cached: an empty veto kept for the life of the process would
            // let a bad publish flag popular sites until the next restart.
            Log.w(TAG, "asset_missing $name: ${e.message}")
            emptySet()
        }
    }
}
