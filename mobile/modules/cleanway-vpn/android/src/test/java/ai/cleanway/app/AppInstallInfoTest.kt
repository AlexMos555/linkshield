package ai.cleanway.app

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The SMS set-up screen trusts these two facts: whether this APK can check
 * SMS at all (only the RuStore build declares RECEIVE_SMS), and how it was
 * installed (a browser download on Android 15+ means "restricted settings").
 * A wrong "yes" would offer a switch that can never work; a wrong source
 * would send the person down the wrong set-up path.
 */
class AppInstallInfoTest {

    @Test
    fun `only a manifest that requests RECEIVE_SMS supports the automatic check`() {
        val rustore = arrayOf("android.permission.INTERNET", "android.permission.RECEIVE_SMS")
        val direct = arrayOf("android.permission.INTERNET", "android.permission.POST_NOTIFICATIONS")
        assertTrue(AppInstallInfo.declares(rustore, AppInstallInfo.RECEIVE_SMS))
        assertFalse(AppInstallInfo.declares(direct, AppInstallInfo.RECEIVE_SMS))
    }

    @Test
    fun `a similar permission is not RECEIVE_SMS, and no list declares nothing`() {
        assertFalse(AppInstallInfo.declares(arrayOf("android.permission.RECEIVE_MMS"), AppInstallInfo.RECEIVE_SMS))
        assertFalse(AppInstallInfo.declares(arrayOf("android.permission.RECEIVE_SMS_EXTRA"), AppInstallInfo.RECEIVE_SMS))
        assertFalse(AppInstallInfo.declares(null, AppInstallInfo.RECEIVE_SMS))
        assertFalse(AppInstallInfo.declares(emptyArray(), AppInstallInfo.RECEIVE_SMS))
    }

    @Test
    fun `a RuStore install is reported as is`() {
        val s = AppInstallInfo.of("ru.vk.store", "ru.vk.store", 2)
        assertEquals("ru.vk.store", s.installer)
        assertEquals("ru.vk.store", s.initiator)
        assertEquals(2, s.packageSource)
        assertEquals(mapOf("installer" to "ru.vk.store", "initiator" to "ru.vk.store", "packageSource" to 2), s.toWire())
    }

    @Test
    fun `an adb install on an older phone reports nothing, not an empty name`() {
        val s = AppInstallInfo.of("", null, null)
        assertNull(s.installer)
        assertNull(s.initiator)
        assertNull(s.packageSource)
    }

    @Test
    fun `a package source outside the platform's range reads as not reported`() {
        assertEquals(4, AppInstallInfo.of(null, null, 4).packageSource)
        assertEquals(0, AppInstallInfo.of(null, null, 0).packageSource)
        assertNull(AppInstallInfo.of(null, null, 5).packageSource)
        assertNull(AppInstallInfo.of(null, null, -1).packageSource)
    }
}
