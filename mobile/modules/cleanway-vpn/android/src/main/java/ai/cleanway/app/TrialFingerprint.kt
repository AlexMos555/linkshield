package ai.cleanway.app

import android.content.Context
import android.provider.Settings
import java.security.MessageDigest

/**
 * What the free trial is keyed on (billing plan §2.2): one trial per phone,
 * and a reinstall gets the same one back rather than a second one.
 *
 * ANDROID_ID is stable per app signing key and per user until a factory
 * reset, which is exactly the lifetime a trial should have. It never leaves
 * the phone as itself: this is a SHA-256 under a fixed label, and the server
 * stores only an HMAC of that — nobody can walk back from either to the id.
 */
object TrialFingerprint {
    private const val LABEL = "cleanway-trial:"

    /** The fingerprint, or null on a phone that has no ANDROID_ID (then the app keys the trial on its install id). */
    fun of(context: Context): String? {
        val id = try {
            Settings.Secure.getString(context.applicationContext.contentResolver, Settings.Secure.ANDROID_ID)
        } catch (_: Exception) {
            null
        }
        return id?.takeIf { it.isNotBlank() }?.let { digest(LABEL + it) }
    }

    /** Pure: lower-case hex SHA-256 of [input]. */
    fun digest(input: String): String =
        MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
}
