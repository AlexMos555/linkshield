package ai.cleanway.app

import ai.cleanway.app.ShieldPreference.TunnelEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Why the shield says it stopped (ShieldPreference.stopReasonAfter, kept by
 * StopReasonStore, recorded by CleanwayVpnService at each event).
 *
 * 1.0.2 said "usually after a reboot, one tap" whatever had happened. 1.0.3
 * names the cause — and the review of it found that the cause sat in the
 * backed-up preferences: on a phone restored from Google backup, the screen
 * could say a VPN permission had been switched off in its settings, on a
 * phone that never had it.
 */
class ShieldStopReasonTest {
    @get:Rule val tmp = TemporaryFolder()

    @Test
    fun `each event leaves the cause the screen names`() {
        val cases = listOf(
            // event, the tunnel came up on this install before → reason
            Triple(TunnelEvent.CAME_UP, true, null),
            Triple(TunnelEvent.STOPPED_BY_PERSON, true, null),
            Triple(TunnelEvent.TAKEN_AWAY, true, CleanwayVpnService.REASON_REVOKED),
            Triple(TunnelEvent.TAKEN_AWAY, false, CleanwayVpnService.REASON_REVOKED),
            Triple(TunnelEvent.NO_CONSENT, true, CleanwayVpnService.REASON_REVOKED),
            Triple(TunnelEvent.NO_CONSENT, false, null),     // never granted here: nothing was withdrawn
            Triple(TunnelEvent.PRIVATE_DNS, true, CleanwayVpnService.REASON_PRIVATE_DNS),
            Triple(TunnelEvent.PRIVATE_DNS, false, CleanwayVpnService.REASON_PRIVATE_DNS),
        )
        for ((event, cameUpHere, expected) in cases) {
            assertEquals("$event cameUpHere=$cameUpHere", expected, ShieldPreference.stopReasonAfter(event, cameUpHere))
        }
    }

    @Test
    fun `the cause is kept until the tunnel comes up again or the person turns it off`() {
        val store = StopReasonStore(tmp.newFolder())
        store.note(TunnelEvent.CAME_UP)
        assertNull(store.reason())
        store.note(TunnelEvent.TAKEN_AWAY)
        assertEquals("revoked", store.reason())
        store.note(TunnelEvent.CAME_UP)
        assertNull(store.reason())
        store.note(TunnelEvent.PRIVATE_DNS)
        assertEquals("private_dns", store.reason())
        store.note(TunnelEvent.STOPPED_BY_PERSON)
        assertNull(store.reason())
    }

    @Test
    fun `a missing permission after the tunnel ran here is a withdrawn one`() {
        // Revoked in Settings while the app was closed; the next start finds out.
        val store = StopReasonStore(tmp.newFolder())
        store.note(TunnelEvent.CAME_UP)
        store.note(TunnelEvent.NO_CONSENT)
        assertEquals("revoked", store.reason())
    }

    @Test
    fun `a new phone restored from backup names no cause`() {
        // "Protection was on" came back with the backup; the VPN permission and
        // this folder did not. The first start there finds no permission.
        val newPhone = StopReasonStore(tmp.newFolder())
        newPhone.note(TunnelEvent.NO_CONSENT)
        assertNull(newPhone.reason())
    }
}
