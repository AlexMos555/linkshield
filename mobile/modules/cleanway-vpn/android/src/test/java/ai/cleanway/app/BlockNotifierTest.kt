package ai.cleanway.app

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
    fun `the domain is query-encoded, so it cannot add parameters`() {
        assertEquals(
            "cleanway:///history?filter=blocked&domain=a.example%26filter%3Dall",
            BlockNotifier.historyDeepLink("a.example&filter=all", BlockLog.KIND_BLOCKED),
        )
    }
}
