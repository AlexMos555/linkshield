package ai.cleanway.app

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import java.io.File

/**
 * The one number a person can call when a caller has frightened them — a
 * daughter, a son, a neighbour ("Саша" in the plan).
 *
 * Kept only on this phone, never sent anywhere and never shown in a
 * notification's text. It is dialled with [Intent.ACTION_DIAL], which opens
 * the phone app with the number filled in and needs no permission — the
 * person still presses the call button herself.
 *
 * Where it lives: a file in the app's noBackupFilesDir (like [InstallId] and
 * [StopReasonStore]), which Android's backup and device-to-device transfer
 * never copy — the same posture as the "close one" contact the checkup
 * screen (#55) keeps in expo-secure-store. That screen is the hook that
 * writes here: its `saveCloseOne` / `clearCloseOne` mirror the number with
 * the module's `setCloseContactPhone`, so the service can offer "Позвонить
 * близкому" on the after-call notice, where JS is not running. Until that
 * ships nothing is saved, and every "call a close one" button and
 * notification action simply stays hidden.
 */
object CloseContact {
    private const val FILE = "cleanway_close_contact"
    private const val MIN_DIGITS = 3
    private const val MAX_LENGTH = 20
    private const val TAG = "CleanwayCall"
    /** What people type or paste around the digits: spaces (a pasted number often carries non-breaking ones), dashes, brackets. */
    private val SEPARATORS = setOf(' ', '\u00A0', '-', '(', ')')

    private fun file(context: Context) = File(context.applicationContext.noBackupFilesDir, FILE)

    /** The saved number, or null. */
    fun phone(context: Context): String? = try {
        file(context).takeIf { it.isFile }?.readText()?.let { normalize(it) }
    } catch (_: Exception) {
        null
    }

    /** Save (or clear with null/blank). Returns false when the number is not dialable or could not be stored. */
    fun set(context: Context, phone: String?): Boolean {
        val f = file(context)
        return try {
            if (phone.isNullOrBlank()) {
                f.delete()
                true
            } else {
                val clean = normalize(phone) ?: return false
                f.writeText(clean)
                true
            }
        } catch (e: Exception) {
            Log.w(TAG, "close_contact_write_failed: ${e.javaClass.simpleName}")
            false
        }
    }

    /**
     * Pure: a number as the phone app takes it — digits, one leading "+",
     * with the spaces, dashes and brackets people type removed. Null when
     * there is not a number in it.
     */
    fun normalize(raw: String): String? {
        val trimmed = raw.trim()
        val plus = trimmed.startsWith("+")
        val digits = trimmed.filter { it.isDigit() }
        if (digits.length < MIN_DIGITS || digits.length > MAX_LENGTH) return null
        val body = trimmed.drop(if (plus) 1 else 0)
        if (body.any { !(it.isDigit() || it in SEPARATORS) }) return null
        return (if (plus) "+" else "") + digits
    }

    /** An intent that opens the phone app on the saved number, or null when none is saved. */
    fun dialIntent(context: Context): Intent? {
        val number = phone(context) ?: return null
        return Intent(Intent.ACTION_DIAL, Uri.fromParts("tel", number, null))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
}
