package ai.cleanway.app

import android.content.Context
import org.json.JSONObject

/**
 * What the native shield does for this phone's entitlement (billing plan A.10).
 *
 *  FULL  — today's shield, untouched: the list every 6 h, blocking on.
 *  BASIC — the lapse policy the founder leans to: blocking continues from the
 *          list, the list is refreshed once a week, the notification says so
 *          (the "yellow shield").
 *  OFF   — the other lapse policy: the tunnel stays up so the person's DNS
 *          keeps working, but nothing is blocked, and the notification says so.
 *
 * Nothing here runs unless the app hands the service a pass ([ProtectionPassStore]);
 * with the billing switch off there is none and the mode is FULL — the
 * service behaves exactly as before this file existed.
 */
enum class ProtectionMode(val wire: String) {
    FULL("full"), BASIC("basic"), OFF("off");

    companion object {
        /** The pass's word for a mode, or null for anything else. */
        fun parse(wire: String?): ProtectionMode? = values().firstOrNull { it.wire == wire }
    }
}

/**
 * The part of the device pass the service keeps — no personal data, and no
 * signature: the app verified it (src/lib/entitlement.ts) before handing it
 * over, and this process trusts its own app, not the network.
 */
data class StoredPass(
    val mode: ProtectionMode,
    /** BASIC or OFF: what the mode becomes after `graceUntilSec` (or `untilSec`). */
    val lapsePolicy: ProtectionMode,
    /** Unix seconds; null = the mode holds until a newer pass. */
    val untilSec: Long?,
    val graceUntilSec: Long?,
    /** When the pass was issued (unix seconds): the device clock is never taken to be earlier. */
    val iatSec: Long,
    /** subscription | trial | legacy | promo | none — for the log only. */
    val source: String,
)

object ProtectionPolicy {
    /** A week between list refreshes in BASIC (and OFF, to be ready the moment it is paid again). */
    const val BASIC_REFRESH_MS = 7L * 24 * 60 * 60 * 1000

    /** In BASIC a list is stale only when it missed its weekly refresh by a day. */
    const val BASIC_STALE_AFTER_MS = 8L * 24 * 60 * 60 * 1000

    /**
     * Pure, the app's offline rule (`entitlement.offline_mode` on the server,
     * `offlineMode` in src/lib/entitlement.ts), ported 1:1 so a phone that
     * never opens the app downgrades at the same moment the server would:
     *  - the device clock is clamped to ≥ iat (a clock turned back extends nothing);
     *  - before `until` the issued mode; inside the grace window still the
     *    issued mode; after both, the lapse policy;
     *  - `until = null`: the mode holds until a newer pass;
     *  - no pass at all: FULL.
     */
    fun effectiveMode(pass: StoredPass?, nowSec: Long): ProtectionMode {
        if (pass == null) return ProtectionMode.FULL
        val now = maxOf(nowSec, pass.iatSec)
        val until = pass.untilSec ?: return pass.mode
        if (now < until) return pass.mode
        val grace = pass.graceUntilSec
        if (grace != null && now < grace) return pass.mode
        return pass.lapsePolicy
    }

    /** Pure: when [effectiveMode] next changes (unix seconds), null when it never does. */
    fun nextChangeSec(pass: StoredPass?, nowSec: Long): Long? {
        if (pass == null) return null
        val now = maxOf(nowSec, pass.iatSec)
        val until = pass.untilSec ?: return null
        val grace = pass.graceUntilSec
        if (now < until) return if (grace != null && grace > until) grace else until
        if (grace != null && now < grace) return grace
        return null
    }

    /** Pure: does the shield answer listed names with NXDOMAIN in [mode]? */
    fun blocks(mode: ProtectionMode): Boolean = mode != ProtectionMode.OFF

    /** Pure: how often the list is refreshed in [mode]. */
    fun refreshMs(mode: ProtectionMode): Long =
        if (mode == ProtectionMode.FULL) SyncPolicy.REFRESH_MS else BASIC_REFRESH_MS

    /** Pure: when a loaded list counts as stale in [mode] (BlockList.isStale). */
    fun staleAfterMs(mode: ProtectionMode): Long =
        if (mode == ProtectionMode.FULL) BlockList.STALE_AFTER_MS else BASIC_STALE_AFTER_MS

    /**
     * Pure: the pass the app hands over, as JSON with the server's field names
     * (`{mode, lapse_policy, until, grace_until, iat, src}`); null for
     * anything that is not one — then the service stays FULL rather than
     * guessing a downgrade from a broken message.
     */
    fun parse(json: String?): StoredPass? {
        if (json.isNullOrBlank()) return null
        return try {
            val o = JSONObject(json)
            val mode = ProtectionMode.parse(optString(o, "mode")) ?: return null
            val policy = ProtectionMode.parse(optString(o, "lapse_policy"))
                ?.takeIf { it != ProtectionMode.FULL } ?: return null
            if (!o.has("iat") || o.isNull("iat")) return null
            StoredPass(
                mode = mode,
                lapsePolicy = policy,
                untilSec = optLong(o, "until"),
                graceUntilSec = optLong(o, "grace_until"),
                iatSec = o.getLong("iat"),
                source = optString(o, "src") ?: "none",
            )
        } catch (_: Exception) {
            null
        }
    }

    /** Pure: [parse]'s inverse, for the preferences file. */
    fun format(pass: StoredPass): String = JSONObject().apply {
        put("mode", pass.mode.wire)
        put("lapse_policy", pass.lapsePolicy.wire)
        put("until", pass.untilSec ?: JSONObject.NULL)
        put("grace_until", pass.graceUntilSec ?: JSONObject.NULL)
        put("iat", pass.iatSec)
        put("src", pass.source)
    }.toString()

    private fun optLong(o: JSONObject, key: String): Long? =
        if (!o.has(key) || o.isNull(key)) null else o.getLong(key)

    private fun optString(o: JSONObject, key: String): String? =
        if (!o.has(key) || o.isNull(key)) null else o.getString(key)
}

/**
 * The last pass the app handed over, in the shield's own preferences file
 * (next to the "user turned it on" flag), so the ":boot" process and a
 * restarted service start in the right mode without any JS alive.
 */
internal object ProtectionPassStore {
    private const val PREFS = "cleanway_shield"
    private const val KEY_PASS = "protection_pass"

    fun read(context: Context): StoredPass? = ProtectionPolicy.parse(
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_PASS, null),
    )

    /** [pass] null clears it: the mode is FULL again (the billing switch went off, or a legacy phone). */
    fun write(context: Context, pass: StoredPass?) {
        context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .apply { if (pass == null) remove(KEY_PASS) else putString(KEY_PASS, ProtectionPolicy.format(pass)) }
            // commit(): the app may be swiped away right after; a lost write
            // would leave a paid phone in BASIC until the next launch.
            .commit()
    }
}
