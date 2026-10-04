package ai.cleanway.app

import ai.cleanway.app.CallState.Phase
import android.media.AudioManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What the phone's audio mode tells us about calls (CallState.Machine), and
 * the 30-minute window after one. No permission is involved anywhere in
 * this: the stop screen must never depend on READ_PHONE_STATE.
 */
class CallStateTest {

    private val t0 = 1_727_600_000_000L
    private val minute = 60_000L

    @Test
    fun `a SIM call and a messenger call are calls, ringing is not, anything else is idle`() {
        assertEquals(Phase.IN_CALL, CallState.phaseOf(AudioManager.MODE_IN_CALL))
        assertEquals(Phase.IN_CALL, CallState.phaseOf(AudioManager.MODE_IN_COMMUNICATION))
        assertEquals(Phase.RINGING, CallState.phaseOf(AudioManager.MODE_RINGTONE))
        assertEquals(Phase.IDLE, CallState.phaseOf(AudioManager.MODE_NORMAL))
        assertEquals(Phase.IDLE, CallState.phaseOf(AudioManager.MODE_CALL_SCREENING))
        assertEquals(Phase.IDLE, CallState.phaseOf(-1))
        assertEquals(Phase.IDLE, CallState.phaseOf(42))
    }

    @Test
    fun `ringing, answering and hanging up`() {
        val m = CallState.Machine()
        assertNull("idle to idle changes nothing", m.onMode(AudioManager.MODE_NORMAL, t0))

        val ringing = m.onMode(AudioManager.MODE_RINGTONE, t0)!!
        assertTrue(ringing.ringing)
        assertFalse(ringing.inCall)
        assertFalse("ringing is not yet a call for the stop screen", ringing.guardActive(t0))

        val answered = m.onMode(AudioManager.MODE_IN_CALL, t0 + 10_000)!!
        assertTrue(answered.inCall)
        assertEquals(t0 + 10_000, answered.callStartedAt)
        assertEquals(0L, answered.callEndedAt)
        assertTrue(answered.guardActive(t0 + 5 * minute))

        assertNull("the same mode again is not a new call", m.onMode(AudioManager.MODE_IN_CALL, t0 + 20_000))

        val ended = m.onMode(AudioManager.MODE_NORMAL, t0 + 3 * minute)!!
        assertFalse(ended.inCall)
        assertEquals(t0 + 10_000, ended.callStartedAt)
        assertEquals(t0 + 3 * minute, ended.callEndedAt)
    }

    @Test
    fun `the window after a call is 30 minutes, then the guard rests`() {
        val m = CallState.Machine()
        m.onMode(AudioManager.MODE_IN_COMMUNICATION, t0)
        val s = m.onMode(AudioManager.MODE_NORMAL, t0 + 2 * minute)!!
        assertEquals(t0 + 2 * minute + CallState.AFTER_CALL_WINDOW_MS, s.windowEndsAt())
        assertTrue(s.inAfterCallWindow(t0 + 2 * minute))
        assertTrue(s.guardActive(t0 + 31 * minute))
        assertFalse(s.inAfterCallWindow(t0 + 32 * minute))
        assertFalse(s.guardActive(t0 + 32 * minute))
        // A clock stepped back below the call's end is not "inside the window".
        assertFalse(s.inAfterCallWindow(t0))
    }

    @Test
    fun `an unanswered ring opens no window`() {
        val m = CallState.Machine()
        m.onMode(AudioManager.MODE_RINGTONE, t0)
        val s = m.onMode(AudioManager.MODE_NORMAL, t0 + 15_000)!!
        assertEquals(0L, s.callEndedAt)
        assertFalse(s.guardActive(t0 + 20_000))
    }

    @Test
    fun `a call in progress while the guard is not yet running is seen at the first read`() {
        // The service starts with a call already going on: the first mode read is IN_CALL.
        val m = CallState.Machine()
        val s = m.onMode(AudioManager.MODE_IN_CALL, t0)!!
        assertTrue(s.inCall)
        assertEquals(t0, s.callStartedAt)
    }

    @Test
    fun `a machine restored from storage keeps the last call's window`() {
        // The service was restarted 10 minutes after a call: the window still applies.
        val m = CallState.Machine(startedAt = t0, endedAt = t0 + 5 * minute)
        assertTrue(m.snapshot.inAfterCallWindow(t0 + 15 * minute))
        assertNull(m.onMode(AudioManager.MODE_NORMAL, t0 + 15 * minute))
    }

    @Test
    fun `a call back inside the window starts a new call and keeps nothing stale`() {
        val m = CallState.Machine()
        m.onMode(AudioManager.MODE_IN_CALL, t0)
        m.onMode(AudioManager.MODE_NORMAL, t0 + minute)
        val again = m.onMode(AudioManager.MODE_IN_CALL, t0 + 5 * minute)!!
        assertEquals(t0 + 5 * minute, again.callStartedAt)
        assertEquals("the previous end stays until this call ends", t0 + minute, again.callEndedAt)
        assertTrue(again.inCall)
        assertFalse("in a call is not 'after a call'", again.inAfterCallWindow(t0 + 6 * minute))
    }
}
