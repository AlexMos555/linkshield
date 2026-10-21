package ai.cleanway.app

import ai.cleanway.app.SmsPermissionState.DENIED
import ai.cleanway.app.SmsPermissionState.GRANTED
import ai.cleanway.app.SmsPermissionState.NOT_REQUESTED
import ai.cleanway.app.SmsPermissionState.RESTRICTED_MAYBE
import android.app.AppOpsManager
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * What the SMS screen may claim about the permission. Android never says
 * whether a refusal came from the person or from "restricted settings", so
 * each state names only what can be observed — and the set-up screen sends
 * the person to a different place for each.
 */
class SmsShieldTest {
    private val source3 = 3 // PACKAGE_SOURCE_LOCAL_FILE
    private val source4 = 4 // PACKAGE_SOURCE_DOWNLOADED_FILE
    private val store = 2   // PACKAGE_SOURCE_STORE

    private fun state(
        granted: Boolean = false,
        asked: Boolean = true,
        rationale: Boolean = false,
        sdk: Int = 35,
        source: Int? = source4,
        mode: Int? = null,
    ) = SmsPermissionState.of(granted, asked, rationale, sdk, source, mode)

    @Test
    fun `granted is granted, whatever else is true`() {
        assertEquals(GRANTED, state(granted = true, asked = false))
        assertEquals(GRANTED, state(granted = true, mode = AppOpsManager.MODE_IGNORED))
    }

    @Test
    fun `never asked is not requested, even on a restricted install`() {
        assertEquals(NOT_REQUESTED, state(asked = false))
        assertEquals(NOT_REQUESTED, state(asked = false, sdk = 33))
        assertEquals(NOT_REQUESTED, state(asked = false, mode = AppOpsManager.MODE_ERRORED))
    }

    @Test
    fun `the system's own dialog-shown state means restricted, asked or not`() {
        assertEquals(RESTRICTED_MAYBE, state(mode = AppOpsManager.MODE_IGNORED))
        // Asked through another path (the marker is missing): the dialog still proves it.
        assertEquals(RESTRICTED_MAYBE, state(asked = false, mode = AppOpsManager.MODE_IGNORED))
    }

    @Test
    fun `before Android 15 SMS is never restricted, a refusal is the person's`() {
        assertEquals(DENIED, state(sdk = 34, source = source4))
        assertEquals(DENIED, state(sdk = 33, mode = AppOpsManager.MODE_IGNORED))
        assertEquals(DENIED, state(sdk = 34, rationale = true))
    }

    @Test
    fun `a rationale means the person said no in a real dialog`() {
        assertEquals(DENIED, state(rationale = true, source = source4))
    }

    @Test
    fun `on Android 15+ a refused sideload is probably restricted`() {
        assertEquals(RESTRICTED_MAYBE, state(source = source4))
        assertEquals(RESTRICTED_MAYBE, state(source = source3))
        assertEquals(RESTRICTED_MAYBE, state(source = source4, mode = AppOpsManager.MODE_ERRORED))
        // Source unknown: the restriction cannot be ruled out.
        assertEquals(RESTRICTED_MAYBE, state(source = null))
    }

    /**
     * Measured on an Android 15 emulator (2026-09-25): an install with
     * package source 4 still reads MODE_DEFAULT for the op — the system does
     * not stamp the guard at install time, it derives it from the source. So
     * "default" must fall through to the source, not read as "allowed".
     */
    @Test
    fun `the op reading default on Android 15 is decided by the install source`() {
        assertEquals(RESTRICTED_MAYBE, state(source = source4, mode = AppOpsManager.MODE_DEFAULT))
        assertEquals(DENIED, state(source = 1, mode = AppOpsManager.MODE_DEFAULT))
    }

    @Test
    fun `a store install, or restricted settings already allowed, is a plain refusal`() {
        assertEquals(DENIED, state(source = store))
        assertEquals(DENIED, state(source = 0))
        assertEquals(DENIED, state(source = source4, mode = AppOpsManager.MODE_ALLOWED))
    }

    /**
     * The warnings' way back on: the screen opened must hold the switch that
     * is off. Only the channel off → the channel's page; the whole app off
     * (or the Android 13+ permission refused, which reads the same) → the
     * app's notification page, whose main switch grants it.
     */
    @Test
    fun `notification settings open where the switch that is off lives`() {
        assertEquals(NotificationSettingsTarget.CHANNEL, NotificationSettingsTarget.of(35, appNotificationsOn = true, channelBlocked = true))
        assertEquals(NotificationSettingsTarget.APP_NOTIFICATIONS, NotificationSettingsTarget.of(35, appNotificationsOn = false, channelBlocked = true))
        assertEquals(NotificationSettingsTarget.APP_NOTIFICATIONS, NotificationSettingsTarget.of(33, appNotificationsOn = false, channelBlocked = false))
        // Everything on, yet the screen asked: the app page shows every switch at once.
        assertEquals(NotificationSettingsTarget.APP_NOTIFICATIONS, NotificationSettingsTarget.of(35, appNotificationsOn = true, channelBlocked = false))
        // Android 7 has no notification pages to open.
        assertEquals(NotificationSettingsTarget.APP_DETAILS, NotificationSettingsTarget.of(25, appNotificationsOn = false, channelBlocked = false))
    }
}
