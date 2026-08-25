package ai.cleanway.app

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log

/**
 * Checks a link the user tapped ANYWHERE (any app) before it opens.
 *
 * The DNS shield blocks KNOWN-bad domains silently, device-wide — but the
 * browser then shows its own "site can't be reached", with no Cleanway
 * branding and no "why". This activity is the layer above: it registers as an
 * http/https handler, so a tapped link can be routed through Cleanway. It then
 * decides in microseconds from the on-device blocklist:
 *
 *   - KNOWN BAD  → hand off to the app's branded warning screen (shared.tsx),
 *     which says Cleanway stopped it and shows the reasons. Nothing is opened.
 *   - EVERYTHING ELSE → the app checks the FULL url (not just the domain the
 *     DNS layer sees) and shows a verdict with an explicit "Open anyway".
 *
 * No UI of its own (transparent, NoDisplay): it either forwards to the RN
 * screen or, in the safe fast-path, straight to a real browser — so a safe
 * link never makes the user wait on a Cleanway screen.
 *
 * Never loops back into itself: forwarding to a browser uses an explicit
 * package that is NOT us (see forwardToBrowser).
 */
class LinkGuardActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val url = intent?.dataString
        if (url.isNullOrBlank() || !(url.startsWith("http://") || url.startsWith("https://"))) {
            finish()
            return
        }
        try {
            routeToApp(url)
        } catch (e: Exception) {
            Log.w(TAG, "link_guard_error: ${e.message}")
            // On any failure, do not trap the user's tap — open it in a real
            // browser rather than swallowing the link.
            forwardToBrowser(url)
        }
        finish()
    }

    /** Hand the URL to the RN app's link-check screen (branded verdict). */
    private fun routeToApp(url: String) {
        val deepLink = "cleanway:///shared?url=${Uri.encode(url)}&via=guard"
        // Reference MainActivity by name (it lives in the app's Gradle module,
        // not this one, so a direct class ref would not compile here).
        startActivity(
            Intent(Intent.ACTION_VIEW, Uri.parse(deepLink)).apply {
                component = ComponentName(packageName, "ai.cleanway.app.MainActivity")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            }
        )
    }

    /**
     * Open a URL in a real browser that is NOT Cleanway, so a forward can never
     * bounce back into this activity. Picks an explicit browser package from
     * the ones that handle http, excluding our own.
     */
    private fun forwardToBrowser(url: String) {
        val view = Intent(Intent.ACTION_VIEW, Uri.parse(url)).addCategory(Intent.CATEGORY_BROWSABLE)
        val pm = packageManager
        val self = packageName
        val browser = pm.queryIntentActivities(
            Intent(Intent.ACTION_VIEW, Uri.parse("http://example.com")).addCategory(Intent.CATEGORY_BROWSABLE),
            0,
        ).map { it.activityInfo.packageName }.firstOrNull { it != self }
        try {
            if (browser != null) view.setPackage(browser)
            startActivity(view.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        } catch (e: ActivityNotFoundException) {
            Log.w(TAG, "no_browser_to_forward: ${e.message}")
        }
    }

    private companion object {
        const val TAG = "CleanwayLinkGuard"
    }
}
