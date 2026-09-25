package ai.cleanway.app

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.core.os.ConfigurationCompat
import androidx.core.text.BidiFormatter
import expo.modules.cleanwayvpn.R
import java.net.URLEncoder
import java.util.Locale

/** The one reason a notification names — plain words for the most useful thing to know. */
enum class SmsAlertReason {
    LINK_LISTED, CODE, SAFE_ACCOUNT, RELATIVE, SMS_COMMAND, INSTALL, CALL, FAKE_SITE, PAYMENT,
    LINK, CONFIRM_DATA, BAIT, SENDER, THREAT, ORGANISATION, DISGUISED, GENERIC,
}

/**
 * Pure: which strings one warning is made of. [sender] null reads "an
 * unknown sender"; SmsNotifier resolves the rest from resources.
 */
data class SmsAlertCopy(val dangerous: Boolean, val sender: String?, val reason: SmsAlertReason)

/**
 * Pure: what the SMS warning says. JVM-tested in SmsNotifierTest.
 *
 * The analyzer orders reasons by how the verdict was reached, so
 * "claims_organisation" usually comes first — true, and useless in a
 * notification ("From 900: it names an organisation"). The notification
 * names the reason that tells the person what the trap IS, in this order:
 * a listed site, then what they would be asked to do (hand over a code, move
 * money, install something, call back), then how the link or the sender
 * lies, then the pressure and the name-dropping.
 */
object SmsAlertText {
    private val PRIORITY: List<Pair<SmsAlertReason, Set<String>>> = listOf(
        SmsAlertReason.LINK_LISTED to setOf(MessageAnalyzer.R_LINK_BLOCKLISTED),
        SmsAlertReason.CODE to setOf(MessageAnalyzer.R_CODE),
        SmsAlertReason.SAFE_ACCOUNT to setOf(MessageAnalyzer.R_SAFE_ACCOUNT),
        SmsAlertReason.RELATIVE to setOf(MessageAnalyzer.R_RELATIVE),
        SmsAlertReason.SMS_COMMAND to setOf(MessageAnalyzer.R_SMS_COMMAND),
        SmsAlertReason.INSTALL to setOf(MessageAnalyzer.R_INSTALL, MessageAnalyzer.R_LINK_APK, MessageAnalyzer.R_MALWARE_LURE),
        SmsAlertReason.CALL to setOf(MessageAnalyzer.R_CALL_UNKNOWN),
        SmsAlertReason.FAKE_SITE to setOf(MessageAnalyzer.R_LINK_LOOKALIKE, MessageAnalyzer.R_LINK_IMITATES_BRAND),
        SmsAlertReason.PAYMENT to setOf(MessageAnalyzer.R_PAYMENT),
        SmsAlertReason.LINK to setOf(
            MessageAnalyzer.R_LINK_NOT_OFFICIAL, MessageAnalyzer.R_LINK_SHORTENER,
            MessageAnalyzer.R_LINK_MESSENGER, MessageAnalyzer.R_LINK_IP,
        ),
        SmsAlertReason.CONFIRM_DATA to setOf(MessageAnalyzer.R_CONFIRM_DATA),
        SmsAlertReason.BAIT to setOf(MessageAnalyzer.R_BAIT),
        SmsAlertReason.SENDER to setOf(MessageAnalyzer.R_SENDER_MISMATCH, MessageAnalyzer.R_SENDER_PERSONAL),
        SmsAlertReason.THREAT to setOf(MessageAnalyzer.R_THREAT),
        SmsAlertReason.ORGANISATION to setOf(MessageAnalyzer.R_ORGANISATION),
        SmsAlertReason.DISGUISED to setOf(MessageAnalyzer.R_DISGUISED),
    )

    /** Every analyzer code maps to a phrase; an unknown one (a newer rules file) falls back to GENERIC. */
    fun topReason(reasons: List<String>): SmsAlertReason =
        PRIORITY.firstOrNull { (_, codes) -> reasons.any { it in codes } }?.first ?: SmsAlertReason.GENERIC

    /** Codes the priority list covers — the test pins that it covers every one the analyzer emits. */
    val COVERED: Set<String> get() = PRIORITY.flatMap { it.second }.toSet()

    /**
     * The warning for [event]: title by verdict, the sender as recorded, one
     * reason. Nothing else goes in — the event holds no text to leak.
     */
    fun copyFor(event: SmsEvent): SmsAlertCopy = SmsAlertCopy(
        dangerous = event.verdict == MessageVerdict.DANGEROUS.wire,
        sender = event.sender,
        reason = topReason(event.reasons),
    )

    /**
     * Pure: where tapping the warning lands — History on the SMS filter with
     * this event open. The route opens an id only if the event log holds it,
     * so a crafted link from another app cannot put a made-up warning on
     * screen; the id is hex, and encoded anyway.
     */
    fun historyDeepLink(id: String): String =
        "cleanway:///history?filter=sms&sms=" + URLEncoder.encode(id, "UTF-8")
}

/**
 * Tells the person, at the moment it arrives, that an SMS looks like a scam.
 *
 * The phone's own SMS app shows the message; we cannot hold it back or mark
 * it (only the default SMS app can). So the warning has to say, in the
 * notification itself, the two things that stop the loss — do not call the
 * number, do not open the link — without making the person open anything.
 *
 * What it carries: the sender as the phone shows it and one reason. Never a
 * word of the message text. On the lock screen only the title shows (the
 * public version), so a phone left on a table does not show who wrote.
 *
 * Channel [CHANNEL_ID], high importance: a warning that sits silently in the
 * shade until after the person has called back is no warning. Strings come
 * from res/values-xx/strings.xml, generated from packages/i18n-strings.
 */
object SmsNotifier {
    const val CHANNEL_ID = "cleanway_sms_alerts"
    /** Own tag: an SMS id can never replace a block alert that hashed to the same number. */
    private const val NOTIFICATION_TAG = "cleanway_sms"
    private const val TAG = "CleanwaySms"

    fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val loc = LocalizedContext.of(context, fresh = true)
        // Re-creating only renames (e.g. after a language change); the
        // importance the person chose is kept.
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                loc.getString(R.string.sms_channel),
                NotificationManager.IMPORTANCE_HIGH,
            ).apply { description = loc.getString(R.string.sms_channel_desc) }
        )
    }

    /**
     * Can a warning reach the person right now? The app switch, and on 13+
     * the runtime permission; and our channel, if the person turned it off.
     */
    fun canNotify(context: Context): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            return false
        }
        val nm = NotificationManagerCompat.from(context)
        if (!nm.areNotificationsEnabled()) return false
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return true
        val channel = nm.getNotificationChannel(CHANNEL_ID) ?: return true
        return channel.importance != NotificationManager.IMPORTANCE_NONE
    }

    /** Post the warning for [event]. Never throws; a failure only loses the pop-up, the event is recorded. */
    fun notify(context: Context, event: SmsEvent) {
        try {
            if (!canNotify(context)) return
            ensureChannel(context)
            val loc = LocalizedContext.of(context, fresh = true)
            val copy = SmsAlertText.copyFor(event)
            val title = loc.getString(if (copy.dangerous) R.string.sms_alert_title_dangerous else R.string.sms_alert_title_caution)
            // A Latin number or alpha id inside an Arabic sentence must not
            // reorder it: wrap it for the notification's own language.
            val locale = ConfigurationCompat.getLocales(loc.resources.configuration)[0] ?: Locale.getDefault()
            val sender = copy.sender?.let { BidiFormatter.getInstance(locale).unicodeWrap(it) }
                ?: loc.getString(R.string.sms_alert_unknown_sender)
            val text = loc.getString(R.string.sms_alert_text, sender, loc.getString(reasonText(copy.reason)))
            val open = Intent(Intent.ACTION_VIEW, Uri.parse(SmsAlertText.historyDeepLink(event.id))).apply {
                component = ComponentName(context.packageName, "ai.cleanway.app.MainActivity")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            }
            val pending = PendingIntent.getActivity(
                context, event.id.hashCode(), open,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            // The lock screen gets the title only: who wrote stays private.
            val public = NotificationCompat.Builder(context, CHANNEL_ID)
                .setContentTitle(title)
                .setSmallIcon(BlockNotifier.SMALL_ICON)
                .setColor(BlockNotifier.ACCENT_COLOR)
                .build()
            val notif = NotificationCompat.Builder(context, CHANNEL_ID)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                .setSmallIcon(BlockNotifier.SMALL_ICON)
                .setColor(BlockNotifier.ACCENT_COLOR)
                .setContentIntent(pending)
                .setAutoCancel(true)
                .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
                .setPublicVersion(public)
                // Pre-O phones have no channels; HIGH is what makes them pop up.
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .build()
            (context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .notify(NOTIFICATION_TAG, event.id.hashCode(), notif)
        } catch (e: Exception) {
            // The class name only: a message could carry anything.
            Log.w(TAG, "sms_alert_failed: ${e.javaClass.simpleName}")
        }
    }

    /** The phrase for each reason. Internal: SmsNotifierTest pins it to the string of the same name. */
    internal fun reasonText(reason: SmsAlertReason): Int = when (reason) {
        SmsAlertReason.LINK_LISTED -> R.string.sms_reason_link_listed
        SmsAlertReason.CODE -> R.string.sms_reason_code
        SmsAlertReason.SAFE_ACCOUNT -> R.string.sms_reason_safe_account
        SmsAlertReason.RELATIVE -> R.string.sms_reason_relative
        SmsAlertReason.SMS_COMMAND -> R.string.sms_reason_sms_command
        SmsAlertReason.INSTALL -> R.string.sms_reason_install
        SmsAlertReason.CALL -> R.string.sms_reason_call
        SmsAlertReason.FAKE_SITE -> R.string.sms_reason_fake_site
        SmsAlertReason.PAYMENT -> R.string.sms_reason_payment
        SmsAlertReason.LINK -> R.string.sms_reason_link
        SmsAlertReason.CONFIRM_DATA -> R.string.sms_reason_confirm_data
        SmsAlertReason.BAIT -> R.string.sms_reason_bait
        SmsAlertReason.SENDER -> R.string.sms_reason_sender
        SmsAlertReason.THREAT -> R.string.sms_reason_threat
        SmsAlertReason.ORGANISATION -> R.string.sms_reason_organisation
        SmsAlertReason.DISGUISED -> R.string.sms_reason_disguised
        SmsAlertReason.GENERIC -> R.string.sms_reason_generic
    }
}
