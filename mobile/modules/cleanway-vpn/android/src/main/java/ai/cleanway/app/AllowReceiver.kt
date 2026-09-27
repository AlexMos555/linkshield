package ai.cleanway.app

import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * The retired "Not a scam — allow it" button of a block notification.
 *
 * Up to 1.0.2 every block pop-up carried it: one tap, and the site opened
 * with the shield still on. That is also exactly what a scammer on the phone
 * says — "press allow" — while the person is looking at the pop-up. From
 * 1.0.3 the notification has no such button (BlockNotifier.notify); a site is
 * allowed only in History, behind a confirmation that first says a caller
 * asking for it is a scammer.
 *
 * Kept for one reason: a notification posted by 1.0.2 can still be in the
 * shade after the update, and its button still fires here. It allows NOTHING
 * now. It removes that notification and posts one that says where allowing
 * lives, leads with the scam warning, and opens the site's History entry.
 */
class AllowReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_ALLOW) return
        val domain = UserAllow.normalize(intent.getStringExtra(EXTRA_DOMAIN)) ?: return
        Log.i(TAG, "legacy_allow_action — nothing allowed")
        try {
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.cancel(domain.hashCode())
        } catch (_: Exception) {
        }
        BlockNotifier.notifyAllowMoved(context, domain)
    }

    companion object {
        const val ACTION_ALLOW = "ai.cleanway.ALLOW_DOMAIN"
        const val EXTRA_DOMAIN = "domain"
        private const val TAG = "CleanwayAllow"
    }
}
