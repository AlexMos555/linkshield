package ai.cleanway.app

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.ContactsContract
import android.provider.Settings
import android.util.Log

/**
 * The native half of the app's "Проверка защиты" screen: what the phone can
 * tell about itself, and the system screens its fixes open.
 *
 * Nothing here asks for a permission. The battery state is the app's own;
 * the settings screens are public intents; a contact comes back through the
 * system picker, which grants read access to the ONE row the person chose —
 * no READ_CONTACTS. A call only opens the dialer with the number filled in
 * (ACTION_DIAL) — no CALL_PHONE, and nothing is dialled until the person
 * presses the green button themselves.
 */
object ProtectionCheckup {
    private const val TAG = "CleanwayCheckup"

    /** Shortest number worth dialling (112, 115) and the E.164 maximum. */
    private const val MIN_DIGITS = 3
    private const val MAX_DIGITS = 15

    /**
     * What people and address books put between digits: spaces, dashes,
     * brackets, dots. Java's \s is ASCII-only, so \p{Z} and U+FEFF add the
     * Unicode spaces (U+00A0, U+2009, U+202F…) — the same set JS's \s
     * matches in src/utils/phone-number.ts.
     */
    private val SEPARATORS = Regex("[\\s\\p{Z}\\uFEFF\\u2010-\\u2015\\-().]")

    /**
     * Pure: the number as the dialer should receive it — digits with an
     * optional leading "+" — or null when it is not a plain phone number.
     *
     * Anything else is refused rather than cleaned up: "*" and "#" would make
     * it a USSD code, letters and ";" / "," an extension or a pause sequence.
     * Mirrored in src/utils/phone-number.ts; the two must agree, and only the
     * JS table runs in CI — run this module's unit tests after a change.
     */
    fun dialable(raw: String?): String? {
        val compact = raw?.trim()?.replace(SEPARATORS, "") ?: return null
        val plus = compact.startsWith("+")
        val digits = if (plus) compact.substring(1) else compact
        if (digits.length !in MIN_DIGITS..MAX_DIGITS) return null
        if (!digits.all { it in '0'..'9' }) return null
        return if (plus) "+$digits" else digits
    }

    /**
     * Has Android put Cleanway under "Restricted" battery use? Then the
     * shield's alarms and restarts are held back and protection can stop
     * without a word. Null below Android 9, where the state does not exist
     * in this form, and on error — never guessed either way.
     */
    fun backgroundRestricted(context: Context): Boolean? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return null
        val am = context.getSystemService(ActivityManager::class.java) ?: return null
        return runCatching { am.isBackgroundRestricted }.getOrNull()
    }

    /** This app's page in system settings — the "Battery" entry lives there. */
    fun appDetailsIntent(context: Context): Intent =
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null))

    /**
     * The list of apps allowed to install other apps ("Install unknown
     * apps", Android 8+), where the family switches it off for messengers and
     * browsers. Before Android 8 it was one switch under Security.
     */
    fun unknownSourcesIntent(): Intent =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES)
        } else {
            Intent(Settings.ACTION_SECURITY_SETTINGS)
        }

    /** The system contact picker, limited to rows that carry a phone number. */
    fun contactPickIntent(): Intent =
        Intent(Intent.ACTION_PICK).setType(ContactsContract.CommonDataKinds.Phone.CONTENT_TYPE)

    /**
     * What the picker hands back when no number came out of it: the row could
     * not be read, or no picker could be opened. Distinct from null (the
     * person backed out), so the screen can say so instead of doing nothing.
     */
    val PICK_FAILED: Map<String, String?> = mapOf("error" to "pick_failed")

    /**
     * The name and number of the contact row the picker returned, or
     * [PICK_FAILED] — an OEM picker without a read grant, a row that is gone.
     * Read once, through the picker's temporary grant; never logged.
     */
    fun readPickedPhone(context: Context, uri: Uri): Map<String, String?> = try {
        val projection = arrayOf(
            ContactsContract.CommonDataKinds.Phone.NUMBER,
            ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME,
        )
        context.contentResolver.query(uri, projection, null, null, null)?.use { row ->
            if (row.moveToFirst()) mapOf("number" to row.getString(0), "name" to row.getString(1)) else null
        } ?: PICK_FAILED
    } catch (e: Exception) {
        Log.w(TAG, "contact_read_failed: ${e.javaClass.simpleName}")
        PICK_FAILED
    }

    /** The dialer with [number] filled in, or null when it is not a dialable number. */
    fun dialIntent(number: String): Intent? =
        dialable(number)?.let { Intent(Intent.ACTION_DIAL, Uri.parse("tel:$it")) }

    /** Start a system screen from outside an activity; false when the phone has none. */
    fun open(context: Context, intent: Intent): Boolean = try {
        context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        true
    } catch (e: Exception) {
        Log.w(TAG, "open_failed: ${e.javaClass.simpleName}")
        false
    }
}
