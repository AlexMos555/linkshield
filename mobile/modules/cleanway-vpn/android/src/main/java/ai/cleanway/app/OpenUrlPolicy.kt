package ai.cleanway.app

/**
 * What openInBrowser (CleanwayVpnModule) may hand to a browser.
 *
 * The link-guard screen's "Open anyway" passes a URL that JS rebuilt from the
 * checked host (src/utils/open-url.ts). This is the native backstop: only a
 * plain http(s) URL with a host and no userinfo leaves the app, and only when
 * the string itself is a single token — never an intent:/javascript:/file:
 * URL, and never a string whose host android.net.Uri and the browser could
 * read differently (whitespace, controls, a backslash).
 *
 * Pure: the caller passes what Uri.parse(raw) reported, so the JVM unit test
 * (OpenUrlPolicyTest) runs without Android.
 */
object OpenUrlPolicy {

    private val UNSAFE = Regex("[\\s\\u0000-\\u001f\\u007f-\\u009f\\\\]")

    fun isOpenable(raw: String, scheme: String?, host: String?, userInfo: String?): Boolean {
        if (raw.isEmpty() || UNSAFE.containsMatchIn(raw)) return false
        val s = scheme?.lowercase() ?: return false
        if (s != "http" && s != "https") return false
        // Uri's idea of the scheme must be the string's own "<scheme>://" prefix.
        if (!raw.regionMatches(0, "$s://", 0, s.length + 3, ignoreCase = true)) return false
        if (host.isNullOrBlank()) return false
        if (userInfo != null) return false
        return true
    }
}
