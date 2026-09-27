package ai.cleanway.app

import ai.cleanway.app.NetworkPresence.Level
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The summary an open home screen re-checks on (NetworkPresence). It must
 * change when the connection comes back — including onto a network Android
 * has not confirmed yet — and stay put for anything else.
 */
class NetworkPresenceTest {

    @Test
    fun `no network, an unconfirmed one, a confirmed one`() {
        assertEquals(Level.NONE, NetworkPresence.levelOf(emptyList()))
        assertEquals(Level.UNCONFIRMED, NetworkPresence.levelOf(listOf(false)))
        assertEquals(Level.ONLINE, NetworkPresence.levelOf(listOf(false, true)))
        assertEquals(Level.ONLINE, NetworkPresence.levelOf(listOf(true)))
    }
}
