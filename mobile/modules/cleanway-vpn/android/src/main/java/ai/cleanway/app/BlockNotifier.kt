package ai.cleanway.app

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import expo.modules.cleanwayvpn.R
import java.net.URLEncoder

/**
 * Tells the person what the shield just did — in their language, from the
 * service, so it works while the app is closed.
 *
 * Why this exists: a DNS block is invisible. The browser shows "site can't be
 * reached", which to the target user reads as "my internet is broken", not
 * "I was just protected". The notification is the only place the shield's
 * work becomes visible in the moment.
 *
 * Two honest variants (see BlockLog):
 *  - blocked: "Cleanway blocked a dangerous site — it is on the list of scam
 *    sites and won't open." The query got NXDOMAIN before anything opened.
 *  - warned:  "This site looks like a scam — if it is open, close it and
 *    don't type anything." The link guard let the link open and the check of
 *    its site came back afterwards; a late warning is still protection, and
 *    it must not be dressed up as a block.
 *
 * Tapping either opens History on that site's entry ([historyDeepLink]):
 * what happened, when, which shield, and the "not a scam" rescue — behind a
 * confirmation that first says a caller asking for it is a scammer. The
 * notification itself has no allow button any more (1.0.3): one tap on a
 * pop-up is exactly what a scammer on the phone talks a person into.
 *
 * Strings come from res/values-xx/strings.xml, GENERATED from
 * packages/i18n-strings by scripts/build-i18n.py (10 locales).
 *
 * Blocks go to [ALERT_CHANNEL_ID] (high importance), so the phone shows
 * them as a pop-up at the moment the site fails to open — within the
 * [AlertBudget]: at most 3 pop-ups an hour and 10 a day, one per site in six
 * hours, and past the cap one collapsed "N more suspicious" notice
 * ([notifySummary]) on the silent [CAUTION_CHANNEL_ID]. Warnings ("this site
 * looks like a scam") are always silent: they wait in the shade, no pop-up,
 * no sound. The quieter "allow it in the app" notice ([notifyAllowMoved])
 * stays on [CHANNEL_ID].
 *
 * Nothing posted here carries a link or a phone number; the site's name is
 * plain text (the person — and the founder — want to see what was stopped).
 */
object BlockNotifier {
    /** Quiet channel: the "allow it in the app" notice. Created as the block
     *  channel in 1.0.x, and a channel's importance can't be raised after
     *  creation — hence the separate [ALERT_CHANNEL_ID]. */
    const val CHANNEL_ID = "cleanway_blocks"
    const val ALERT_CHANNEL_ID = "cleanway_block_alerts"
    /** Silent: warnings, repeats of a site already popped up, the summary. No sound, no pop-up. */
    const val CAUTION_CHANNEL_ID = "cleanway_caution"
    /** The one collapsed "N more suspicious" notice over the cap. */
    private const val SUMMARY_ID = 4713
    /** Kept for callers: the burst window now lives in [AlertBudget]. */
    const val PER_DOMAIN_WINDOW_MS = AlertBudget.BURST_WINDOW_MS

    /**
     * Status-bar icon for EVERY Cleanway notification. Android draws a small
     * icon from its alpha channel only, so the full-colour launcher icon came
     * out as a white blob; this is a white shield on transparent.
     */
    val SMALL_ICON: Int get() = R.drawable.cleanway_ic_notification

    /** Brand green: tints the small icon in the notification shade. */
    const val ACCENT_COLOR: Int = 0xFF22C55E.toInt()

    /**
     * Pure: where tapping a block or warn notification lands — History,
     * filtered to that kind, with this site's entry open. The route reads
     * `domain` only if the site really is in the block log, so a crafted link
     * from another app cannot put an arbitrary site in front of the person.
     */
    fun historyDeepLink(domain: String, kind: String): String {
        val filter = if (kind == BlockLog.KIND_WARNED) "warned" else "blocked"
        return "cleanway:///history?filter=$filter&domain=" + URLEncoder.encode(domain, "UTF-8")
    }

    /** The process-wide pop-up budget (AlertBudget); the after-call notice shares it. */
    val budget = AlertBudget()

    /**
     * Pure: how loud an event may be. A block is "Dangerous" (the site was
     * on the list) and pops up. A late warning about a site that already
     * opened pops up only when the server's verdict on it was "dangerous";
     * a "caution" verdict — even one the model is sure about — is
     * "Careful", and "Careful" is always silent (plan №7). No level known:
     * careful.
     */
    fun severityOf(kind: String, level: String? = null): AlertBudget.Severity = when {
        kind != BlockLog.KIND_WARNED -> AlertBudget.Severity.DANGER
        level == "dangerous" -> AlertBudget.Severity.DANGER
        else -> AlertBudget.Severity.CAUTION
    }

    /**
     * Pure: will a block alert actually show? The app-wide switch can be on
     * while the person turned off just [ALERT_CHANNEL_ID] (in Android's
     * settings, or by long-pressing an alert) — then every block happens in
     * silence. [channelImportance] is null while the channel does not exist
     * yet (or before Android 8): the first alert creates it switched on.
     */
    fun alertsAudible(appEnabled: Boolean, channelImportance: Int?): Boolean =
        appEnabled && channelImportance != NotificationManager.IMPORTANCE_NONE

    /** The block-alerts channel's importance as the person left it; null when there is none. */
    fun alertChannelImportance(context: Context): Int? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return null
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        return nm.getNotificationChannel(ALERT_CHANNEL_ID)?.importance
    }

    fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val loc = LocalizedContext.of(context)
        // Re-creating an existing channel only updates its name and
        // description (never the importance the person chose), which renames
        // the 1.0.x block channel to what it carries now.
        nm.createNotificationChannel(
            NotificationChannel(
                ALERT_CHANNEL_ID,
                loc.getString(R.string.block_channel),
                NotificationManager.IMPORTANCE_HIGH,
            ).apply { description = loc.getString(R.string.block_channel_desc) }
        )
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                loc.getString(R.string.allow_channel),
                NotificationManager.IMPORTANCE_DEFAULT,
            ).apply { description = loc.getString(R.string.allow_channel_desc) }
        )
        // LOW: shown in the shade, never a pop-up, never a sound.
        nm.createNotificationChannel(
            NotificationChannel(
                CAUTION_CHANNEL_ID,
                loc.getString(R.string.caution_channel),
                NotificationManager.IMPORTANCE_LOW,
            ).apply { description = loc.getString(R.string.caution_channel_desc) }
        )
    }

    /**
     * The "allow" button of a block notification posted by 1.0.2 was tapped
     * (see AllowReceiver). Nothing is allowed: say where allowing lives now,
     * lead with the scam warning, and open that site's History entry on tap.
     */
    fun notifyAllowMoved(context: Context, domain: String) {
        try {
            ensureChannel(context)
            val loc = LocalizedContext.of(context)
            val text = loc.getString(R.string.allow_moved_text, domain)
            val notif = NotificationCompat.Builder(context, CHANNEL_ID)
                .setContentTitle(loc.getString(R.string.allow_moved_title))
                .setContentText(text)
                .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                .setSmallIcon(SMALL_ICON)
                .setColor(ACCENT_COLOR)
                .setContentIntent(historyEntry(context, domain, BlockLog.KIND_BLOCKED))
                .setAutoCancel(true)
                .setPriority(NotificationCompat.PRIORITY_DEFAULT)
                .build()
            (context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .notify(("allow-moved:" + domain).hashCode(), notif)
        } catch (_: Exception) {
        }
    }

    /**
     * Opens that exact entry in History (why, when, which shield) — not a
     * fresh server check of the site, which used to add a second "dangerous"
     * row and inflate the Blocked counter on every tap.
     */
    private fun historyEntry(context: Context, domain: String, kind: String): PendingIntent {
        val detail = Intent(Intent.ACTION_VIEW, android.net.Uri.parse(historyDeepLink(domain, kind))).apply {
            component = android.content.ComponentName(context.packageName, "ai.cleanway.app.MainActivity")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }
        return PendingIntent.getActivity(
            context, domain.hashCode() and 0xffff, detail,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }

    /**
     * Post the notification as the budget allows. Safe to call from any
     * thread. [severity] defaults from the kind alone; the link guard passes
     * the one it derived from the server's verdict ([severityOf] with a level).
     */
    fun notify(
        context: Context,
        domain: String,
        kind: String,
        now: Long = System.currentTimeMillis(),
        severity: AlertBudget.Severity = severityOf(kind),
    ) {
        when (val verdict = budget.decide(severity, domain, now)) {
            AlertBudget.Verdict.DROP -> return
            AlertBudget.Verdict.HEADS_UP -> post(context, domain, kind, headsUp = true)
            AlertBudget.Verdict.SILENT -> post(context, domain, kind, headsUp = false)
            is AlertBudget.Verdict.SUMMARY -> notifySummary(context, verdict.count)
        }
    }

    private fun post(context: Context, domain: String, kind: String, headsUp: Boolean) {
        try {
            ensureChannel(context)
            val loc = LocalizedContext.of(context)
            val (title, text) = when (kind) {
                BlockLog.KIND_WARNED -> loc.getString(R.string.warn_title) to
                    loc.getString(R.string.warn_text, domain)
                else -> loc.getString(R.string.blocked_title) to
                    loc.getString(R.string.blocked_text, domain)
            }
            // No "not a scam — allow" button here. It was one tap on a pop-up
            // that appears while the person is trying to open the site — the
            // moment a scammer on the phone says "press allow". Allowing
            // lives in History (the tap below), behind a warning.
            val notif = NotificationCompat.Builder(context, if (headsUp) ALERT_CHANNEL_ID else CAUTION_CHANNEL_ID)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                .setSmallIcon(SMALL_ICON)
                .setColor(ACCENT_COLOR)
                .setContentIntent(historyEntry(context, domain, kind))
                .setAutoCancel(true)
                // Pre-O phones have no channels; the priority is what decides there.
                .setPriority(if (headsUp) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_LOW)
                .build()
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            // Distinct id per domain so a repeat replaces rather than stacks;
            // POST_NOTIFICATIONS may be denied on 13+ — notify() then no-ops,
            // and the block log still records it.
            nm.notify(domain.hashCode(), notif)
        } catch (_: Exception) {
            // Never let a notification failure touch the DNS path.
        }
    }

    /**
     * Over the cap: one collapsed, silent notice, updated in place with the
     * count. It names no site — the sites are in History, where the tap lands.
     */
    private fun notifySummary(context: Context, count: Int) {
        try {
            ensureChannel(context)
            val loc = LocalizedContext.of(context)
            val n = count.toString()
            val history = Intent(Intent.ACTION_VIEW, android.net.Uri.parse("cleanway:///history?filter=blocked")).apply {
                component = android.content.ComponentName(context.packageName, "ai.cleanway.app.MainActivity")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            }
            val notif = NotificationCompat.Builder(context, CAUTION_CHANNEL_ID)
                .setContentTitle(loc.getString(R.string.summary_title, n))
                .setContentText(loc.getString(R.string.summary_text))
                .setSmallIcon(SMALL_ICON)
                .setColor(ACCENT_COLOR)
                .setContentIntent(PendingIntent.getActivity(
                    context, SUMMARY_ID, history, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                ))
                .setAutoCancel(true)
                .setOnlyAlertOnce(true)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .build()
            (context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).notify(SUMMARY_ID, notif)
        } catch (_: Exception) {
        }
    }
}
