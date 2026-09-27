package ai.cleanway.app

import android.app.NotificationManager
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Where a block notification lands. It used to open a fresh server check of
 * the site, which saved a second "dangerous" row on every tap and inflated
 * the Blocked counter; it now opens that site's entry in History. The route
 * parses this URL, so its shape is pinned here.
 */
class BlockNotifierTest {

    @Test
    fun `a block opens History filtered to blocked with the site`() {
        assertEquals(
            "cleanway:///history?filter=blocked&domain=evil.example",
            BlockNotifier.historyDeepLink("evil.example", BlockLog.KIND_BLOCKED),
        )
    }

    @Test
    fun `a warning opens History filtered to warnings`() {
        assertEquals(
            "cleanway:///history?filter=warned&domain=xn--80ak6aa92e.com",
            BlockNotifier.historyDeepLink("xn--80ak6aa92e.com", BlockLog.KIND_WARNED),
        )
    }

    @Test
    fun `alerts are on only when the app AND the block-alerts channel are on`() {
        // Settings showed a green check for "Block alerts" whenever the app-wide
        // switch was on — also with only this channel turned off, when every
        // block happens in silence.
        assertEquals(true, BlockNotifier.alertsAudible(true, NotificationManager.IMPORTANCE_HIGH))
        assertEquals(true, BlockNotifier.alertsAudible(true, NotificationManager.IMPORTANCE_LOW))
        assertEquals(false, BlockNotifier.alertsAudible(true, NotificationManager.IMPORTANCE_NONE))
        assertEquals(false, BlockNotifier.alertsAudible(false, NotificationManager.IMPORTANCE_HIGH))
        // No channel yet (nothing blocked so far, or Android 7): the first alert creates it switched on.
        assertEquals(true, BlockNotifier.alertsAudible(true, null))
        assertEquals(false, BlockNotifier.alertsAudible(false, null))
    }

    @Test
    fun `the domain is query-encoded, so it cannot add parameters`() {
        assertEquals(
            "cleanway:///history?filter=blocked&domain=a.example%26filter%3Dall",
            BlockNotifier.historyDeepLink("a.example&filter=all", BlockLog.KIND_BLOCKED),
        )
    }
}
