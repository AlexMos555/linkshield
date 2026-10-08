package ai.cleanway.app

import android.content.Context
import android.util.Log

/**
 * Android glue for the on-device message check: the shipped vocabulary, the
 * blocklist (via [BlocklistHolder]) and the person's allow list, handed to the
 * pure [MessageAnalyzer].
 *
 * Privacy contract — the reason this runs on the phone at all:
 *  - the message text is analysed in memory and dropped; it is never logged
 *    (not even its length), written to disk, or sent anywhere;
 *  - only link HOSTS come back to the app, which may check them one by one
 *    against the same domain-only endpoint as a typed link.
 *
 * Blocks (disk read, parse): call from a worker thread.
 */
object MessageCheck {
    private const val TAG = "CleanwayMessageCheck"
    private const val RULES_ASSET = "message_rules.json"
    private val lock = Any()
    @Volatile private var rules: MessageRules? = null
    @Volatile private var loadedModel: LoadedModel? = null

    /** The text model once loaded — null inside when its assets are missing or broken (the rules still run). */
    private class LoadedModel(val model: MessageModel?)

    data class Result(
        val analysis: MessageAnalysis,
        /** A synced list was available, so link statuses mean something. */
        val listAvailable: Boolean,
        /** That list was published more than [BlockList.STALE_AFTER_MS] ago. */
        val listStale: Boolean,
    ) {
        fun toWire(): Map<String, Any?> =
            analysis.toWire() + mapOf("listAvailable" to listAvailable, "listStale" to listStale)
    }

    fun analyze(context: Context, text: String): Result {
        val list = BlocklistHolder.current(context)
        val allowed = BlocklistHolder.allowed(context)
        val analyzer = MessageAnalyzer(rules(context), model(context)) { host -> LinkPolicy.classify(host, list, allowed) }
        val usable = list != null && !list.revoked && list.count > 0
        val analysis = analyzer.analyze(text)
        // Only the verdict leaves this function for the after-call notice
        // (CallGuard) — never the text, never the links.
        if (analysis.verdict == MessageVerdict.DANGEROUS) {
            CallGuard.noteEvent(context, CallGuard.EVENT_MESSAGE_DANGEROUS)
        }
        return Result(
            analysis = analysis,
            listAvailable = usable,
            listStale = usable && isStale(list),
        )
    }

    /** The listed suffix that blocks [host] (DNS rules: system and allowed names never match), or null. */
    fun matchBlocklist(context: Context, host: String): String? {
        val normalized = HostNames.normalize(host) ?: return null
        return LinkPolicy.listedSuffix(normalized, BlocklistHolder.current(context), BlocklistHolder.allowed(context))
    }

    /**
     * Staleness by the publisher's own stamp: the disk copy is parsed with
     * "now" as its load time, so BlockList.isStale would call a month-old
     * file fresh.
     */
    private fun isStale(list: BlockList?): Boolean {
        val version = list?.version ?: return true
        if (version <= 0L) return true
        return System.currentTimeMillis() - version * 1000L > BlockList.STALE_AFTER_MS
    }

    /** The text model (message_model.json + .bin, ~0.5 MB), read once. */
    private fun model(context: Context): MessageModel? {
        loadedModel?.let { return it.model }
        synchronized(lock) {
            loadedModel?.let { return it.model }
            val loaded = try {
                val assets = context.applicationContext.assets
                MessageModel.parse(
                    assets.open(MessageModel.ASSET_JSON).bufferedReader().use { it.readText() },
                    assets.open(MessageModel.ASSET_WEIGHTS).use { it.readBytes() },
                )
            } catch (e: Exception) {
                // MessageModelTest guards the shipped assets; degrade to the rules alone.
                Log.w(TAG, "model_unavailable: ${e.javaClass.simpleName}")
                null
            }
            loadedModel = LoadedModel(loaded)
            return loaded
        }
    }

    private fun rules(context: Context): MessageRules {
        rules?.let { return it }
        synchronized(lock) {
            rules?.let { return it }
            val parsed = try {
                val assets = context.applicationContext.assets
                val json = assets.open(RULES_ASSET).bufferedReader().use { it.readText() }
                // Without the root zone, bare links fall back to the asset's
                // own bare_tlds/country_tlds: fewer TLDs, never no check.
                val rootZone = try {
                    RootZone.parse(assets.open(RootZone.ASSET).bufferedReader().use { it.readText() })
                } catch (e: Exception) {
                    Log.w(TAG, "root_zone_unavailable: ${e.javaClass.simpleName}")
                    emptySet()
                }
                MessageRules.parse(json, rootZone)
            } catch (e: Exception) {
                // A broken asset is a shipping bug: MessageAnalyzerTest and CI's
                // mobile/scripts/check-message-rules.mjs guard it.
                // Degrade to "links against the list only" rather than no check.
                Log.w(TAG, "rules_unavailable: ${e.javaClass.simpleName}")
                MessageRules.empty()
            }
            rules = parsed
            return parsed
        }
    }
}
