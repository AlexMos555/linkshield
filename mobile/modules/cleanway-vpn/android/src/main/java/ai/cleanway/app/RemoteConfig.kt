package ai.cleanway.app

import android.content.Context
import android.util.Log
import org.json.JSONObject

/**
 * Switches the server can flip for the on-phone checks without a new APK —
 * today the SMS text model ([MessageModel]): turn it off, or make it quieter.
 *
 * Where they come from: `remote_config` in GET /api/v1/mobile/version
 * (api/routers/mobile.py, env-driven), fetched by the app's update check
 * (mobile/src/hooks/useUpdateCheck.ts) on app start and about daily, and
 * handed to [RemoteConfigStore.save] through the module's `setRemoteConfig`.
 * The message check runs here in Kotlin, so the switches live where it can
 * read them: SharedPreferences.
 *
 * Fail-safe order: the last answer the phone got → [DEFAULT] (model on, the
 * shipped thresholds). A failed fetch, a response without the block, or a
 * malformed one never changes what is stored — an outage cannot flip a switch.
 *
 * The threshold overrides only ever RAISE the shipped thresholds
 * ([cautionThreshold], [dangerThreshold]): the server can make the model
 * quieter, never louder, so a wrong value cannot turn every SMS into a warning.
 */
data class RemoteConfig(
    val smsTextModelEnabled: Boolean = true,
    /** In (0, 1) or null; see [cautionThreshold]. */
    val smsTextModelCautionThresholdOverride: Double? = null,
    /** In (0, 1) or null; see [dangerThreshold]. */
    val smsTextModelDangerThresholdOverride: Double? = null,
) {
    /** The caution threshold to use: the model's own, raised by the override, never lowered. */
    fun cautionThreshold(shipped: Double): Double = raiseOnly(shipped, smsTextModelCautionThresholdOverride)

    /** The danger threshold to use: the model's own, raised by the override, never lowered. */
    fun dangerThreshold(shipped: Double): Double = raiseOnly(shipped, smsTextModelDangerThresholdOverride)

    /** The stored form — the same snake_case keys the server sends. */
    fun toJson(): String = JSONObject()
        .put(K_ENABLED, smsTextModelEnabled)
        .put(K_CAUTION, smsTextModelCautionThresholdOverride ?: JSONObject.NULL)
        .put(K_DANGER, smsTextModelDangerThresholdOverride ?: JSONObject.NULL)
        .toString()

    companion object {
        val DEFAULT = RemoteConfig()

        const val K_ENABLED = "sms_text_model_enabled"
        const val K_CAUTION = "sms_text_model_caution_threshold_override"
        const val K_DANGER = "sms_text_model_danger_threshold_override"

        /**
         * The switches in [raw], or null when it is not a config at all (not
         * JSON, not an object, no boolean [K_ENABLED]) — the caller then keeps
         * what it had. A threshold that is not a number in (0, 1) is dropped
         * on its own: the rest of the answer still counts.
         */
        fun parse(raw: String?): RemoteConfig? {
            if (raw.isNullOrBlank()) return null
            return try {
                val o = JSONObject(raw)
                val enabled = o.opt(K_ENABLED) as? Boolean ?: return null
                RemoteConfig(enabled, threshold(o.opt(K_CAUTION)), threshold(o.opt(K_DANGER)))
            } catch (_: Exception) {
                null
            }
        }

        internal fun threshold(v: Any?): Double? {
            val d = (v as? Number)?.toDouble() ?: return null
            return d.takeIf { it.isFinite() && it > 0.0 && it < 1.0 }
        }

        private fun raiseOnly(shipped: Double, override: Double?): Double =
            if (override != null && override > shipped) override else shipped
    }
}

/**
 * The last [RemoteConfig] the app got, in SharedPreferences (no personal data:
 * the server's switches only). Read on every message check — cheap, Android
 * caches the file in memory — so a new answer applies to the next message.
 */
object RemoteConfigStore {
    private const val PREFS = "cleanway_remote_config"
    private const val KEY = "config"
    private const val TAG = "CleanwayRemoteConfig"

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** The stored switches, or [RemoteConfig.DEFAULT] when none were ever stored (or the copy is unreadable). */
    fun current(context: Context): RemoteConfig = try {
        RemoteConfig.parse(prefs(context).getString(KEY, null)) ?: RemoteConfig.DEFAULT
    } catch (e: Exception) {
        Log.w(TAG, "read_failed: ${e.javaClass.simpleName}")
        RemoteConfig.DEFAULT
    }

    /** Store [raw] as the new switches. False, with the old ones kept, when it is not a config or could not be written. */
    fun save(context: Context, raw: String): Boolean {
        val parsed = RemoteConfig.parse(raw) ?: return false
        return try {
            prefs(context).edit().putString(KEY, parsed.toJson()).apply()
            true
        } catch (e: Exception) {
            Log.w(TAG, "write_failed: ${e.javaClass.simpleName}")
            false
        }
    }
}
