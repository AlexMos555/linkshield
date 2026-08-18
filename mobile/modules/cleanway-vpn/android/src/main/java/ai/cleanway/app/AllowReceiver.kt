package ai.cleanway.app

import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Handles the "Not a scam — allow it" action on a block notification.
 *
 * The notification is where the person actually is at the moment their site
 * broke, so the escape hatch lives there: one tap, the site works, the shield
 * stays on for everything else. The action is never silent — the allow is
 * recorded in history and confirmed with a follow-up notification that says
 * where to undo it.
 */
class AllowReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_ALLOW) return
        val domain = intent.getStringExtra(EXTRA_DOMAIN) ?: return
        val normalized = UserAllow.normalize(domain) ?: return
        UserAllow.add(context, normalized)
        BlockLog.record(context, normalized, System.currentTimeMillis(), BlockLog.KIND_ALLOWED)
        // The DNS thread reads a snapshot; refresh it now so the very next
        // lookup of the rescued site already works.
        CleanwayVpnService.instance?.reloadAllowed()
        Log.i(TAG, "user_allowed=$normalized")
        try {
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.cancel(normalized.hashCode())
        } catch (_: Exception) {
        }
        BlockNotifier.notifyAllowed(context, normalized)
    }

    companion object {
        const val ACTION_ALLOW = "ai.cleanway.ALLOW_DOMAIN"
        const val EXTRA_DOMAIN = "domain"
        private const val TAG = "CleanwayAllow"
    }
}
