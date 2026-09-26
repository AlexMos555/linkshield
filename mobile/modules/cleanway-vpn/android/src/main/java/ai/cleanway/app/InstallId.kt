package ai.cleanway.app

import android.content.Context
import java.util.UUID

/**
 * A random number for this install, sent as [HEADER] with every site check.
 *
 * Why: the check endpoint is rate-limited per IP, and Tele2 puts thousands of
 * phones behind one carrier-NAT address — one busy street would spend the
 * whole city's quota. A per-install number lets the server count per phone.
 *
 * What it is not: it is not derived from the phone (no Android ID, no IMEI,
 * no account), it is not sent anywhere but our own check endpoint — not with
 * the blocklist download, which stays anonymous — and it is forgotten with
 * the app. The JS side reads the same value (CleanwayVpnModule.installId), so
 * the app's own checks and the link guard's count as one install.
 */
object InstallId {
    const val HEADER = "X-Cleanway-Install"
    private const val PREFS = "cleanway_install"
    private const val KEY = "install_id"
    private val UUID_SHAPE = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

    @Volatile private var cached: String? = null

    fun get(context: Context): String {
        cached?.let { return it }
        synchronized(this) {
            cached?.let { return it }
            val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val id = prefs.getString(KEY, null)?.takeIf(::isValid)
                ?: UUID.randomUUID().toString().also { prefs.edit().putString(KEY, it).commit() }
            cached = id
            return id
        }
    }

    /** Pure: a random (version 4) UUID in its canonical lower-case form. */
    fun isValid(value: String): Boolean = UUID_SHAPE.matches(value)
}
