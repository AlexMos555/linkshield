package ai.cleanway.app

import android.content.Intent
import android.provider.Telephony

/** One PDU of an incoming SMS, as the telephony stack hands it over. */
data class SmsPart(
    /** The sender as the phone shows it: a number, a short code or an alpha id ("Gosuslugi"). */
    val sender: String?,
    val body: String?,
    /** The service centre's timestamp: the same for a message the phone re-delivers after a reboot. */
    val sentAtMs: Long,
)

/** One message as the person reads it: every part from one sender, joined in order. */
data class IncomingSms(val sender: String?, val text: String, val sentAtMs: Long)

/**
 * SMS_RECEIVED → the messages the person actually received.
 *
 * A long SMS travels as several parts. Android reassembles them before the
 * broadcast, so all the parts of one message arrive in ONE intent, in order —
 * but checked part by part, "Госуслуги: ваш аккаунт взломан" and "позвоните
 * +7 9…" would each look harmless, and one message would raise two alerts.
 * So the parts are grouped by sender and joined, and each group is checked
 * once. Pure apart from [fromIntent]; JVM-tested in IncomingSmsTest.
 */
object IncomingSmsParts {
    /** Longest sender kept: an alpha id is at most 11 characters, a full number about 16. */
    const val MAX_SENDER_CHARS = 32

    /** Decode the PDUs. Never logged: the parts carry the text and the sender. */
    fun fromIntent(intent: Intent): List<SmsPart> =
        Telephony.Sms.Intents.getMessagesFromIntent(intent).orEmpty().filterNotNull().map {
            SmsPart(it.displayOriginatingAddress, it.displayMessageBody, it.timestampMillis)
        }

    /** Pure: one message per sender, parts joined in arrival order, senders in order of first part. */
    fun group(parts: List<SmsPart>): List<IncomingSms> =
        parts.groupBy { it.sender?.trim().orEmpty() }.map { (sender, group) ->
            IncomingSms(
                sender = cleanSender(sender),
                text = group.joinToString("") { it.body.orEmpty() },
                sentAtMs = group.minOf { it.sentAtMs },
            )
        }

    /**
     * Pure: the sender as it may be stored and shown. Control and format
     * characters go — a right-to-left override in an alpha id would otherwise
     * turn "knabrebs" into "sberbank" in the notification — runs of spaces
     * become one, and the result is capped. Null when nothing is left.
     */
    fun cleanSender(raw: String?): String? {
        if (raw == null) return null
        val kept = StringBuilder()
        raw.codePoints().forEach { cp ->
            val type = Character.getType(cp)
            when {
                // A line break between words is a space, not nothing.
                Character.isWhitespace(cp) || Character.isSpaceChar(cp) ->
                    if (kept.isNotEmpty() && kept.last() != ' ') kept.append(' ')
                type == Character.CONTROL.toInt() || type == Character.FORMAT.toInt() -> Unit
                type == Character.UNASSIGNED.toInt() || type == Character.SURROGATE.toInt() -> Unit
                else -> kept.appendCodePoint(cp)
            }
        }
        val text = kept.toString().trim()
        if (text.isEmpty()) return null
        if (text.codePointCount(0, text.length) <= MAX_SENDER_CHARS) return text
        return text.substring(0, text.offsetByCodePoints(0, MAX_SENDER_CHARS)).trimEnd() + "…"
    }
}
