package ai.cleanway.app

import android.content.Context
import java.io.File
import java.util.UUID

/**
 * A random number for this install, sent as [HEADER] with every site check.
 *
 * Why: the check endpoint is rate-limited per IP, and Tele2 puts thousands of
 * phones behind one carrier-NAT address — one busy street would spend the
 * whole city's quota. A per-install number lets the server count per phone.
 *
 * What it is not: it is not derived from the phone (no Android ID, no IMEI,
 * no account), and it is not sent anywhere but our own check endpoint — not
 * with the blocklist download, which stays anonymous.
 *
 * How long it lives: a new one every day ([ROTATE_AFTER_MS]). The rate limit
 * counts per hour, so a day is plenty for it, and the server can never tie
 * more than a day of one phone's checks together. It is kept in
 * noBackupFilesDir, which Android's Auto Backup and device-to-device transfer
 * never copy — the first version sat in SharedPreferences, which the backup
 * rules include, so it came back after a reinstall and moved to a new phone.
 *
 * The JS side reads the same value (CleanwayVpnModule.installId), so the
 * app's own checks and the link guard's count as one install.
 */
object InstallId {
    const val HEADER = "X-Cleanway-Install"
    const val ROTATE_AFTER_MS = 24 * 60 * 60_000L
    private const val FILE = "cleanway_install_id"
    private val UUID_SHAPE = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

    /** A number and when it was made (epoch ms). */
    data class Stamped(val id: String, val madeAtMs: Long)

    @Volatile private var cached: Stamped? = null

    fun get(context: Context): String = synchronized(this) {
        val stored = cached ?: read(context)
        val next = current(stored, System.currentTimeMillis()) { UUID.randomUUID().toString() }
        if (next != stored) write(context, next)
        cached = next
        next.id
    }

    /** Pure: [stored] while it is a valid number made less than a day ago, else a new one made now. */
    fun current(stored: Stamped?, nowMs: Long, make: () -> String): Stamped {
        val age = stored?.let { nowMs - it.madeAtMs } ?: -1L
        return if (stored != null && isValid(stored.id) && age in 0 until ROTATE_AFTER_MS) stored else Stamped(make(), nowMs)
    }

    /** Pure: a random (version 4) UUID in its canonical lower-case form. */
    fun isValid(value: String): Boolean = UUID_SHAPE.matches(value)

    /** Pure: the stored form — the id, a newline, the time it was made. */
    fun format(stamped: Stamped): String = "${stamped.id}\n${stamped.madeAtMs}"

    /** Pure: [format] read back; null for anything else. */
    fun parse(text: String?): Stamped? {
        val lines = text?.trim()?.lines() ?: return null
        if (lines.size != 2) return null
        val madeAt = lines[1].toLongOrNull() ?: return null
        return Stamped(lines[0], madeAt)
    }

    private fun file(context: Context) = File(context.applicationContext.noBackupFilesDir, FILE)

    private fun read(context: Context): Stamped? = try {
        file(context).takeIf { it.isFile }?.let { parse(it.readText()) }
    } catch (_: Exception) {
        null
    }

    /** Best effort: if the file cannot be written, this process still uses the number it made. */
    private fun write(context: Context, stamped: Stamped) {
        try {
            val target = file(context)
            val tmp = File(target.parentFile, "$FILE.tmp")
            tmp.writeText(format(stamped))
            if (!tmp.renameTo(target)) target.writeText(format(stamped))
        } catch (_: Exception) {
        }
    }
}
