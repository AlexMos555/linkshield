package ai.cleanway.app

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * openInBrowser (CleanwayVpnModule) launches only what this policy allows.
 * The JS side already rebuilds the URL from the checked host
 * (src/utils/open-url.ts); this is the native backstop, so a future caller —
 * or a JS bug — cannot hand Android an intent:/javascript:/file: URL or a
 * string whose host Uri.parse and the browser would read differently.
 *
 * The scheme/host/userInfo arguments are what android.net.Uri.parse(raw)
 * reports; the JVM test passes them by hand because Uri is an Android stub.
 */
class OpenUrlPolicyTest {

    @Test
    fun `plain http and https URLs with a host are allowed`() {
        assertTrue(OpenUrlPolicy.isOpenable("https://google.com/", "https", "google.com", null))
        assertTrue(OpenUrlPolicy.isOpenable("http://google.com/a?b=1#c", "http", "google.com", null))
        assertTrue(OpenUrlPolicy.isOpenable("HTTPS://google.com/", "HTTPS", "google.com", null))
    }

    @Test
    fun `non-web schemes are refused`() {
        assertFalse(OpenUrlPolicy.isOpenable(
            "intent://evil.tld/#Intent;scheme=https;package=com.evil;end", "intent", "evil.tld", null))
        assertFalse(OpenUrlPolicy.isOpenable("javascript:alert(1)//https://google.com", "javascript", null, null))
        assertFalse(OpenUrlPolicy.isOpenable("file:///data/data/ai.cleanway.app/x", "file", null, null))
        assertFalse(OpenUrlPolicy.isOpenable("content://evil/x", "content", "evil", null))
        assertFalse(OpenUrlPolicy.isOpenable("google.com", null, null, null))
    }

    @Test
    fun `a missing host or any userinfo is refused`() {
        assertFalse(OpenUrlPolicy.isOpenable("https:///x", "https", null, null))
        assertFalse(OpenUrlPolicy.isOpenable("https:///x", "https", "", null))
        assertFalse(OpenUrlPolicy.isOpenable("https://google.com@evil.tld/", "https", "evil.tld", "google.com"))
    }

    @Test
    fun `whitespace, controls and backslashes are refused`() {
        assertFalse(OpenUrlPolicy.isOpenable(
            "https://google.com https://evil.tld/x", "https", "google.com", null))
        assertFalse(OpenUrlPolicy.isOpenable(
            "intent://evil.tld/#Intent;scheme=https;package=com.evil;end https://google.com", "intent", "evil.tld", null))
        assertFalse(OpenUrlPolicy.isOpenable("https://google.com/\nx", "https", "google.com", null))
        assertFalse(OpenUrlPolicy.isOpenable("https://google.com/\u0000x", "https", "google.com", null))
        assertFalse(OpenUrlPolicy.isOpenable("https://google.com\\@evil.tld/", "https", "google.com", null))
        assertFalse(OpenUrlPolicy.isOpenable(" https://google.com/", "https", "google.com", null))
    }

    @Test
    fun `the scheme Uri reports must be the string's own prefix`() {
        // A parser disagreement (Uri saying "https" for something that does not
        // start with "https://") is refused rather than trusted.
        assertFalse(OpenUrlPolicy.isOpenable("//google.com/", "https", "google.com", null))
        assertFalse(OpenUrlPolicy.isOpenable("https:google.com", "https", "google.com", null))
    }
}
