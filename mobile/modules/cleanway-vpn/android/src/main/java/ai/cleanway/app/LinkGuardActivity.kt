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
 * http/https handler, so a tapped link is routed through Cleanway. It then
 * decides in microseconds from the on-device blocklist:
 *
 *   - KNOWN BAD  → the branded warning screen (shared.tsx), which says Cleanway
 *     stopped it and shows the reasons. Nothing is opened.
 *   - EVERYTHING ELSE → FAST PATH: the link opens in the real browser with no
 *     visible Cleanway screen (so a safe link never makes the user wait), and
 *     the always-alive service checks its FULL url in the background. If the
 *     analyzer calls it phishing, the service warns and blocks it from then on.
 *
 * No UI of its own (transparent, finishes immediately). Never loops back into
 * itself: forwarding uses an explicit browser package that is NOT us.
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
            val host = hostOf(url)
            val list = cachedBlockList()
            if (host != null && list != null && list.match(host) != null) {
                // Known bad — show the branded block, do not open it.
                routeToApp(url)
            } else {
                // Fast path: open now, check in the background.
                forwardToBrowser(url)
                if (host != null) requestServiceCheck(host)
            }
        } catch (e: Exception) {
            Log.w(TAG, "link_guard_error: ${e.message}")
            forwardToBrowser(url)
        }
        finish()
    }

    private fun hostOf(url: String): String? =
        try { Uri.parse(url).host?.lowercase()?.trimEnd('.')?.ifBlank { null } } catch (_: Exception) { null }

    /** Hand the URL to the RN app's branded link-check screen. */
    private fun routeToApp(url: String) {
        val deepLink = "cleanway:///shared?url=${Uri.encode(url)}&via=guard"
        startActivity(
            Intent(Intent.ACTION_VIEW, Uri.parse(deepLink)).apply {
                component = ComponentName(packageName, "ai.cleanway.app.MainActivity")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            }
        )
    }

    /** Ask the always-alive VPN service to check this host's full URL. */
    private fun requestServiceCheck(host: String) {
        if (!CleanwayVpnService.isRunning) return
        try {
            startService(
                Intent(this, CleanwayVpnService::class.java).apply {
                    action = CleanwayVpnService.ACTION_CHECK_URL
                    putExtra(CleanwayVpnService.EXTRA_CHECK_HOST, host)
                }
            )
        } catch (e: Exception) {
            Log.v(TAG, "service_check_request_failed: ${e.message}")
        }
    }

    /**
     * Open a URL in a real browser that is NOT Cleanway, so a forward can never
     * bounce back into this activity.
     *
     * We always forward with an EXPLICIT browser package. Firing an implicit
     * VIEW would be catastrophic when Cleanway is the ONLY http/https handler on
     * the device (e.g. the user made us default and has no other browser): the
     * implicit intent resolves straight back to this activity → an infinite
     * loop. So if there is no other browser, we hand the link to our own branded
     * screen instead — the deep link is `cleanway://`, which this activity does
     * not handle, so it cannot loop, and the link is never silently dropped.
     */
    private fun forwardToBrowser(url: String) {
        val self = packageName
        // Android 11+ package visibility: the probe scheme must match a declared
        // <queries> filter or queryIntentActivities returns NOTHING but ourselves.
        // Expo's template declares https only, so an http:// probe made every
        // browser invisible — the guard then believed no browser existed and sent
        // every SAFE link to the in-app fallback screen instead of Chrome. The
        // module manifest now also declares http, but probe https regardless.
        val browser = packageManager.queryIntentActivities(
            Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com")).addCategory(Intent.CATEGORY_BROWSABLE),
            0,
        ).map { it.activityInfo.packageName }.firstOrNull { it != self }

        if (browser == null) {
            Log.w(TAG, "no_other_browser: routing to app screen instead of looping")
            routeToApp(url)
            return
        }

        val view = Intent(Intent.ACTION_VIEW, Uri.parse(url))
            .addCategory(Intent.CATEGORY_BROWSABLE)
            .setPackage(browser)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            startActivity(view)
        } catch (e: ActivityNotFoundException) {
            // The chosen browser disappeared between query and launch — last
            // resort our own screen rather than a dropped link.
            Log.w(TAG, "browser_launch_failed: ${e.message}")
            routeToApp(url)
        }
    }

    /**
     * Load the synced blocklist from disk with the SAME popular-domain veto and
     * shared-suffix set the service uses — otherwise the guard could show a
     * block for a popular domain the DNS layer allows (a false positive, the
     * one thing we protect against hardest). Cached across invocations.
     */
    private fun cachedBlockList(): BlockList? {
        // Must be the SAME directory the service writes to; reading filesDir
        // directly meant load() always returned null here and every known-bad
        // link sailed through to the browser.
        val store = BlocklistStore.of(filesDir)
        val saved = store.load() ?: return null
        synchronized(lock) {
            val cache = cached
            if (cache != null && cachedVersion == saved.fetchedAtMs) return cache
            val list = BlockList.parse(
                saved.body,
                popularVeto = loadAsset("popular_veto.txt"),
                nowMs = System.currentTimeMillis(),
                sharedSuffixes = loadAsset("shared_suffixes.txt"),
            )
            cached = list
            cachedVersion = saved.fetchedAtMs
            return list
        }
    }

    private fun loadAsset(name: String): Set<String> = try {
        assets.open(name).bufferedReader().useLines { lines ->
            lines.map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }.toHashSet()
        }
    } catch (e: Exception) {
        emptySet()
    }

    private companion object {
        const val TAG = "CleanwayLinkGuard"
        private val lock = Any()
        @Volatile private var cached: BlockList? = null
        @Volatile private var cachedVersion: Long = -1L
    }
}
