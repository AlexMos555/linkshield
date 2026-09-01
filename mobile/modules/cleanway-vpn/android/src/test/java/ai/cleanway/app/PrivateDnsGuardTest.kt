package ai.cleanway.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Pins the one decision that matters: when is the device in *strict* Private
 * DNS mode — the only mode that, combined with our tunnel, kills DNS for every
 * app (verified 2026-08-18: `PrivateDnsBroken` on the VPN network, strict
 * refuses to fall back to plaintext, `ping example.com` → unknown host).
 *
 * "off" and "opportunistic" coexist with the shield: opportunistic tries DoT
 * to our 10.0.0.1:853, times out, and falls back to plaintext DNS through the
 * tunnel — that is the path every green shield so far has taken.
 */
class PrivateDnsGuardTest {

    @Test
    fun `off and opportunistic are not strict`() {
        assertNull(PrivateDnsGuard.classify(mode = "off", specifier = null, linkServerNames = emptyList()))
        assertNull(PrivateDnsGuard.classify(mode = "opportunistic", specifier = null, linkServerNames = emptyList()))
        assertNull(PrivateDnsGuard.classify(mode = null, specifier = null, linkServerNames = emptyList()))
    }

    @Test
    fun `hostname mode is strict and reports the hostname`() {
        assertEquals(
            "dns.google",
            PrivateDnsGuard.classify(mode = "hostname", specifier = "dns.google", linkServerNames = emptyList()),
        )
    }

    @Test
    fun `hostname mode with a blank specifier still counts as strict`() {
        // The setting can be "hostname" with the specifier not yet written; the
        // resolver treats that as strict-with-nothing, which is still broken.
        assertEquals(
            PrivateDnsGuard.UNKNOWN_HOST,
            PrivateDnsGuard.classify(mode = "hostname", specifier = "  ", linkServerNames = emptyList()),
        )
    }

    @Test
    fun `a link that reports a private DNS server name is strict even when the setting is unreadable`() {
        // OEMs rename the global setting; LinkProperties.privateDnsServerName is
        // the public-API signal and must be enough on its own.
        assertEquals(
            "one.one.one.one",
            PrivateDnsGuard.classify(mode = null, specifier = null, linkServerNames = listOf(null, "one.one.one.one")),
        )
    }

    @Test
    fun `setting wins over link when both are present`() {
        assertEquals(
            "dns.adguard.com",
            PrivateDnsGuard.classify(mode = "hostname", specifier = "dns.adguard.com", linkServerNames = listOf("stale.example")),
        )
    }
}
