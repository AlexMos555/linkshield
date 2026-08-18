package ai.cleanway.app

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import expo.modules.cleanwayvpn.R

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
 *  - blocked: "Cleanway stopped a dangerous site" — the query got NXDOMAIN
 *    before anything opened.
 *  - warned:  "This site looks like a scam — if it is open, close it and
 *    don't type anything." The verdict came back after the first lookup had
 *    already been forwarded; a late warning is still protection, and it must
 *    not be dressed up as a block.
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
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                context.getString(R.string.block_channel),
                NotificationManager.IMPORTANCE_DEFAULT,
            ).apply { description = context.getString(R.string.block_channel_desc) }
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
            val launch = context.packageManager.getLaunchIntentForPackage(context.packageName)
            val pending = launch?.let {
                PendingIntent.getActivity(context, 2, it, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            }
            val text = context.getString(R.string.allowed_text, domain)
            val notif = NotificationCompat.Builder(context, CHANNEL_ID)
                .setContentTitle(context.getString(R.string.allowed_title))
                .setContentText(text)
                .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                .setSmallIcon(context.applicationInfo.icon)
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
            val (title, text) = when (kind) {
                BlockLog.KIND_WARNED -> context.getString(R.string.warn_title) to
                    context.getString(R.string.warn_text, domain)
                else -> context.getString(R.string.blocked_title) to
                    context.getString(R.string.blocked_text, domain)
            }
            val launch = context.packageManager.getLaunchIntentForPackage(context.packageName)
            val pending = launch?.let {
                PendingIntent.getActivity(
                    context, 1, it,
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                )
            }
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
                .setSmallIcon(context.applicationInfo.icon)
                .setContentIntent(pending)
                .addAction(0, context.getString(R.string.allow_action), allowIntent)
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
