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
        val analyzer = MessageAnalyzer(rules(context)) { host -> LinkPolicy.classify(host, list, allowed) }
        val usable = list != null && !list.revoked && list.count > 0
        return Result(
            analysis = analyzer.analyze(text),
            listAvailable = usable,
            listStale = usable && isStale(list),
        )
    }

    /**
     * The automatic check of an SMS that just arrived (SmsReceiver, ":sms"
     * process). Same rules and list as a pasted message, plus the sender —
     * the phone knows it, so "Госуслуги" writing from a personal number
     * counts. Links are judged by the on-device list and the rules ONLY:
     * nothing, not even a host, leaves the phone in automatic mode.
     *
     * The allow list is read fresh: the main process writes it, and this one
     * may have loaded an older copy hours ago.
     */
    fun analyzeIncoming(context: Context, text: String, sender: String?): MessageAnalysis {
        val list = BlocklistHolder.current(context)
        val allowed = try {
            UserAllow.listFresh(context).toHashSet()
        } catch (e: Exception) {
            Log.w(TAG, "allow_read_error: ${e.javaClass.simpleName}")
            emptySet()
        }
        return MessageAnalyzer(rules(context)) { host -> LinkPolicy.classify(host, list, allowed) }.analyze(text, sender)
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

    private fun rules(context: Context): MessageRules {
        rules?.let { return it }
        synchronized(lock) {
            rules?.let { return it }
            val parsed = try {
                val json = context.applicationContext.assets.open(RULES_ASSET).bufferedReader().use { it.readText() }
                MessageRules.parse(json)
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
