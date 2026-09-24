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
 * what happened, when, which shield, and the "not a scam" rescue.
 *
 * Strings come from res/values-xx/strings.xml, GENERATED from
 * packages/i18n-strings by scripts/build-i18n.py (10 locales).
 *
 * Throttling (pure, JVM-tested): one notification per domain per
 * [PER_DOMAIN_WINDOW_MS], and at most [MAX_PER_MINUTE] overall — a page that
 * loads twenty trackers off one blocked host must not become twenty
 * notifications.
 */
object BlockNotifier {
    const val CHANNEL_ID = "cleanway_blocks"
    const val PER_DOMAIN_WINDOW_MS = 6L * 60 * 60 * 1000
    const val MAX_PER_MINUTE = 3
    private const val MINUTE_MS = 60_000L

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

    /**
     * Pure, JVM-tested throttle. One instance per process; state is tiny.
     */
    class Throttle {
        private val lastByDomain = mutableMapOf<String, Long>()
        private val recent = ArrayDeque<Long>()

        @Synchronized
        fun shouldNotify(domain: String, now: Long): Boolean {
            val last = lastByDomain[domain]
            if (last != null && now - last < PER_DOMAIN_WINDOW_MS) return false
            while (recent.isNotEmpty() && now - recent.first() >= MINUTE_MS) recent.removeFirst()
            if (recent.size >= MAX_PER_MINUTE) return false
            lastByDomain[domain] = now
            recent.addLast(now)
            // Keep the per-domain map from growing forever on a long session.
            if (lastByDomain.size > 512) {
                lastByDomain.entries.filter { now - it.value >= PER_DOMAIN_WINDOW_MS }
                    .forEach { lastByDomain.remove(it.key) }
            }
            return true
        }
    }

    private val throttle = Throttle()

    fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CHANNEL_ID) != null) return
        val loc = LocalizedContext.of(context)
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                loc.getString(R.string.block_channel),
                NotificationManager.IMPORTANCE_DEFAULT,
            ).apply { description = loc.getString(R.string.block_channel_desc) }
        )
    }

    /**
     * Confirm an allow, and say where to undo it. Never silent: an allowed
     * site must not be something the person discovers only by noticing the
     * shield stopped blocking it.
     */
    fun notifyAllowed(context: Context, domain: String) {
        try {
            ensureChannel(context)
            val loc = LocalizedContext.of(context)
            val launch = context.packageManager.getLaunchIntentForPackage(context.packageName)
            val pending = launch?.let {
                PendingIntent.getActivity(context, 2, it, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            }
            val text = loc.getString(R.string.allowed_text, domain)
            val notif = NotificationCompat.Builder(context, CHANNEL_ID)
                .setContentTitle(loc.getString(R.string.allowed_title))
                .setContentText(text)
                .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                .setSmallIcon(SMALL_ICON)
                .setColor(ACCENT_COLOR)
                .setContentIntent(pending)
                .setAutoCancel(true)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .build()
            (context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .notify(("allowed:" + domain).hashCode(), notif)
        } catch (_: Exception) {
        }
    }

    /** Post the notification if throttling allows. Safe to call from any thread. */
    fun notify(context: Context, domain: String, kind: String, now: Long = System.currentTimeMillis()) {
        if (!throttle.shouldNotify(domain, now)) return
        try {
            ensureChannel(context)
            val loc = LocalizedContext.of(context)
            val (title, text) = when (kind) {
                BlockLog.KIND_WARNED -> loc.getString(R.string.warn_title) to
                    loc.getString(R.string.warn_text, domain)
                else -> loc.getString(R.string.blocked_title) to
                    loc.getString(R.string.blocked_text, domain)
            }
            // Tapping "Cleanway blocked X" opens that exact entry in History
            // (why, when, which shield) — not a fresh server check of the
            // site, which used to add a second "dangerous" row and inflate
            // the Blocked counter on every tap.
            val detail = Intent(Intent.ACTION_VIEW, android.net.Uri.parse(historyDeepLink(domain, kind))).apply {
                component = android.content.ComponentName(context.packageName, "ai.cleanway.app.MainActivity")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            }
            val pending = PendingIntent.getActivity(
                context, domain.hashCode() and 0xffff, detail,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            // The escape hatch, where the person actually is when their site
            // breaks: one tap and it works again, with the shield still on.
            // Without it the only remedy for a false positive is turning
            // protection off — the outcome we least want.
            val allowIntent = PendingIntent.getBroadcast(
                context,
                domain.hashCode(),
                Intent(context, AllowReceiver::class.java)
                    .setPackage(context.packageName)
                    .setAction(AllowReceiver.ACTION_ALLOW)
                    .putExtra(AllowReceiver.EXTRA_DOMAIN, domain),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            val notif = NotificationCompat.Builder(context, CHANNEL_ID)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                .setSmallIcon(SMALL_ICON)
                .setColor(ACCENT_COLOR)
                .setContentIntent(pending)
                // The chosen-locale context, like the title and text: the
                // plain context rendered this one button in the phone's
                // system language under a Russian notification.
                .addAction(0, loc.getString(R.string.allow_action), allowIntent)
                .setAutoCancel(true)
                .setPriority(NotificationCompat.PRIORITY_DEFAULT)
                .build()
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            // Distinct id per domain so a repeat (after the window) replaces
            // rather than stacks; POST_NOTIFICATIONS may be denied on 13+ —
            // notify() then no-ops, and the block log still records it.
            nm.notify(domain.hashCode(), notif)
        } catch (_: Exception) {
            // Never let a notification failure touch the DNS path.
        }
    }
}
