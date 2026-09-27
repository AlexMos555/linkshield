package ai.cleanway.app

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * What happens to a stored pause when the tunnel starts or stops
 * (ShieldPreference.pauseAfter, applied by CleanwayVpnService).
 *
 * Review of 1.0.2: only "Turn off" cleared the stored pause. After another
 * VPN took the tunnel away (onRevoke) or a crash, the person tapped «Включить»
 * and the shield came up still paused for the rest of the window — while the
 * home screen, which had seen no pause while the tunnel was down, showed a
 * green "on" and nothing was blocked.
 */
class ShieldPauseTest {

    private val until = 1_727_400_900_000L

    @Test
    fun `a pause survives the tunnel coming back by itself`() {
        // Process killed and restarted, reboot, Always-on VPN: the pause ends at its time, not earlier.
        assertEquals(until, ShieldPreference.pauseAfter(ShieldPreference.PauseEvent.CAME_BACK_BY_ITSELF, until))
    }

    @Test
    fun `the person turning protection on ends a pause`() {
        assertEquals(0L, ShieldPreference.pauseAfter(ShieldPreference.PauseEvent.STARTED_BY_PERSON, until))
    }

    @Test
    fun `turning protection off, or losing the tunnel to another VPN, ends a pause`() {
        assertEquals(0L, ShieldPreference.pauseAfter(ShieldPreference.PauseEvent.STOPPED_BY_PERSON, until))
        assertEquals(0L, ShieldPreference.pauseAfter(ShieldPreference.PauseEvent.TAKEN_AWAY, until))
    }

    @Test
    fun `no pause stays no pause`() {
        for (event in ShieldPreference.PauseEvent.values()) {
            assertEquals(0L, ShieldPreference.pauseAfter(event, 0L))
        }
    }
}
