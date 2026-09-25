package ai.cleanway.app

import android.content.Context
import android.content.res.Configuration
import java.util.Locale

/**
 * Builds strings for notifications in the language the user PICKED in the app,
 * not the phone's system language.
 *
 * The block/foreground notifications come from the native service and read
 * res/values-xx via Android's resource resolution, which keys off the DEVICE
 * locale. So a user whose phone is English but who chose Russian in Settings
 * got English notifications — wrong for an RU-first product (a grandma on an
 * English hand-me-down phone). The app writes its chosen locale here; the
 * notifier wraps its Context with that locale before getString().
 */
object LocalizedContext {
    private const val PREFS = "cleanway_ui"
    private const val KEY = "locale"

    /** Persist the app's chosen UI locale (BCP-47 code, e.g. "ru"). */
    fun set(context: Context, code: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY, code).apply()
    }

    /**
     * A Context whose resources resolve in the chosen locale, or the original
     * when nothing was chosen (fall back to the device locale, unchanged).
     *
     * [fresh]: re-read the choice from disk if the app changed it since this
     * process last looked. The SMS receiver runs in its own process, which can
     * stay alive for hours; without it a warning could arrive in the language
     * the person switched away from.
     */
    fun of(base: Context, fresh: Boolean = false): Context {
        @Suppress("DEPRECATION") // MODE_MULTI_PROCESS: still honoured for exactly this, a reader in another process.
        val mode = if (fresh) Context.MODE_MULTI_PROCESS else Context.MODE_PRIVATE
        val code = base.getSharedPreferences(PREFS, mode).getString(KEY, null)
            ?.takeIf { it.isNotBlank() } ?: return base
        // Android keeps Indonesian under the legacy code "in"; every other
        // code we ship matches its values-xx directory directly.
        val androidCode = if (code == "id") "in" else code
        return try {
            val cfg = Configuration(base.resources.configuration)
            cfg.setLocale(Locale(androidCode))
            base.createConfigurationContext(cfg)
        } catch (e: Exception) {
            base
        }
    }
}
