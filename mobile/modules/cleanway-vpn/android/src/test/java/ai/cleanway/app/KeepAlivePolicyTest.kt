package ai.cleanway.app

import ai.cleanway.app.KeepAlivePolicy.OemFamily
import ai.cleanway.app.KeepAlivePolicy.Rearm
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * "Keep protection on" (KeepAlivePolicy): which battery manager the phone
 * has, which of its screens to open, and when a background re-arm may start
 * the shield. The last one is the dangerous one — a watchdog that starts a
 * VPN the person did not want, or takes the slot from another VPN they chose,
 * is worse than none.
 */
class KeepAlivePolicyTest {

    @Test
    fun `phone makers and their sub-brands map to one family`() {
        val cases = listOf(
            // Build.MANUFACTURER, Build.BRAND → family
            Triple("samsung", "samsung", OemFamily.SAMSUNG),
            Triple("Xiaomi", "Redmi", OemFamily.XIAOMI),
            Triple("Xiaomi", "POCO", OemFamily.XIAOMI),
            Triple("Xiaomi", "xiaomi", OemFamily.XIAOMI),
            Triple("HUAWEI", "HUAWEI", OemFamily.HUAWEI),
            Triple("HONOR", "HONOR", OemFamily.HUAWEI),
            Triple("OPPO", "OPPO", OemFamily.OPPO),
            Triple("realme", "realme", OemFamily.OPPO),
            Triple("OnePlus", "OnePlus", OemFamily.OPPO),
            Triple("vivo", "vivo", OemFamily.VIVO),
            Triple("vivo", "iQOO", OemFamily.VIVO),
            Triple("iQOO", "iQOO", OemFamily.VIVO),
            // A sub-brand that reports a generic maker: the brand decides.
            Triple("unknown", "Redmi", OemFamily.XIAOMI),
            Triple("  Samsung  ", null, OemFamily.SAMSUNG),
        )
        for ((maker, brand, family) in cases) {
            assertEquals("$maker/$brand", family, KeepAlivePolicy.oemFamily(maker, brand))
        }
    }

    @Test
    fun `stock-like Android has no extra step`() {
        for ((maker, brand) in listOf("Google" to "google", "motorola" to "motorola", "HMD Global" to "Nokia", null to null, "" to "")) {
            assertNull("$maker/$brand", KeepAlivePolicy.oemFamily(maker, brand))
        }
    }

    @Test
    fun `every family has screens to try, and only MIUI's battery page is told the package`() {
        for (family in OemFamily.values()) {
            val targets = KeepAlivePolicy.oemTargets(family)
            assertTrue("$family has targets", targets.isNotEmpty())
            assertEquals("$family has no duplicates", targets.size, targets.toSet().size)
            for (t in targets) {
                assertTrue("$t: class is fully qualified", t.cls.contains('.') && t.pkg.contains('.'))
            }
        }
        val withExtras = OemFamily.values().flatMap { KeepAlivePolicy.oemTargets(it) }.filter { it.packageExtras }
        assertEquals(listOf("com.miui.powerkeeper"), withExtras.map { it.pkg })
    }

    @Test
    fun `wire names are what JS expects`() {
        assertEquals(
            listOf("samsung", "xiaomi", "huawei", "oppo", "vivo"),
            OemFamily.values().map { it.wire },
        )
    }

    private fun decide(
        userEnabled: Boolean = true,
        running: Boolean = false,
        stopReason: String? = null,
        privateDnsStrict: Boolean = false,
        otherVpnActive: Boolean = false,
        budgetLeft: Boolean = true,
    ) = KeepAlivePolicy.decideRearm(userEnabled, running, stopReason, privateDnsStrict, otherVpnActive, budgetLeft)

    @Test
    fun `a shield the person left on and an OEM killed is started again`() {
        assertEquals(Rearm.START, decide())
        // Strict Private DNS is not a stop reason that blocks coming back by itself:
        // once the setting is changed back, the shield returns.
        assertEquals(Rearm.START, decide(stopReason = "private_dns"))
    }

    @Test
    fun `never starts what the person turned off, whatever else is true`() {
        assertEquals(Rearm.NOT_WANTED, decide(userEnabled = false))
        assertEquals(Rearm.NOT_WANTED, decide(userEnabled = false, running = true))
        assertEquals(Rearm.NOT_WANTED, decide(userEnabled = false, stopReason = "revoked", otherVpnActive = true))
    }

    @Test
    fun `a running shield is left alone`() {
        assertEquals(Rearm.RUNNING, decide(running = true))
        assertEquals(Rearm.RUNNING, decide(running = true, budgetLeft = false))
    }

    @Test
    fun `never takes the VPN slot back after Android took it away`() {
        // Another VPN app took over, or the permission was withdrawn:
        // prepare() would silently knock that other VPN off.
        assertEquals(Rearm.TAKEN_AWAY, decide(stopReason = CleanwayVpnService.REASON_REVOKED))
        assertEquals(Rearm.TAKEN_AWAY, decide(stopReason = "revoked", otherVpnActive = false))
    }

    @Test
    fun `waits while something on the phone would make a start fail or harm`() {
        assertEquals(Rearm.PRIVATE_DNS, decide(privateDnsStrict = true))
        assertEquals(Rearm.OTHER_VPN, decide(otherVpnActive = true))
        assertEquals(Rearm.BUDGET, decide(budgetLeft = false))
        // The first reason not to wins, so the log names the real one.
        assertEquals(Rearm.PRIVATE_DNS, decide(privateDnsStrict = true, otherVpnActive = true, budgetLeft = false))
    }

    @Test
    fun `the restart budget allows three re-arms an hour`() {
        val now = 10_000_000_000L
        val min = 60_000L
        var history = emptyList<Long>()
        repeat(KeepAlivePolicy.REARM_MAX) { i ->
            assertTrue("re-arm ${i + 1}", KeepAlivePolicy.budgetLeft(history, now + i * min))
            history = KeepAlivePolicy.recordRearm(history, now + i * min)
        }
        assertFalse(KeepAlivePolicy.budgetLeft(history, now + 10 * min))
        // An hour after the first one, a slot frees up again.
        assertTrue(KeepAlivePolicy.budgetLeft(history, now + KeepAlivePolicy.REARM_WINDOW_MS))
        // Entries older than the window are dropped when a new one is recorded.
        val later = now + KeepAlivePolicy.REARM_WINDOW_MS + 30_000L
        assertEquals(listOf(now + min, now + 2 * min, later), KeepAlivePolicy.recordRearm(history, later))
    }

    @Test
    fun `a clock stepped backwards never blocks re-arming for good`() {
        val now = 10_000_000_000L
        val future = listOf(now + 86_400_000L, now + 86_400_001L, now + 86_400_002L)
        assertTrue(KeepAlivePolicy.budgetLeft(future, now))
    }

    @Test
    fun `the stored history reads back and survives damage`() {
        val h = listOf(1L, 22L, 333L)
        assertEquals(h, KeepAlivePolicy.parseHistory(KeepAlivePolicy.formatHistory(h)))
        assertEquals(emptyList<Long>(), KeepAlivePolicy.parseHistory(null))
        assertEquals(emptyList<Long>(), KeepAlivePolicy.parseHistory(""))
        assertEquals(listOf(5L, 7L), KeepAlivePolicy.parseHistory("5,garbage,,7"))
    }

    @Test
    fun `decision names are what JS expects (rearmShield returns them in lower case)`() {
        // modules/cleanway-vpn/src/KeepAliveStatus.ts REARM_DECISIONS: an
        // unknown name reads as null there, never as "start".
        assertEquals(
            listOf("not_wanted", "running", "taken_away", "private_dns", "other_vpn", "budget", "start", "no_consent"),
            Rearm.values().map { it.name.lowercase() },
        )
    }

    @Test
    fun `the policy's copy of the revoked reason is the service's`() {
        // Kept as a literal so the policy needs no Android class; pinned here.
        assertEquals(CleanwayVpnService.REASON_REVOKED, KeepAlivePolicy.REASON_REVOKED)
    }
}
