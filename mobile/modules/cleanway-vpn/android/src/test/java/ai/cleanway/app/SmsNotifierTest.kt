package ai.cleanway.app

import expo.modules.cleanwayvpn.R
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What the SMS warning says and where it leads. The notification has room
 * for one reason, so which one it picks decides whether the person learns
 * "they will ask for your code" or only "it names a bank".
 */
class SmsNotifierTest {

    @Test
    fun `a listed site outranks everything`() {
        assertEquals(
            SmsAlertReason.LINK_LISTED,
            SmsAlertText.topReason(listOf("claims_organisation", "threat_or_urgency", "link_not_official", "link_blocklisted")),
        )
    }

    @Test
    fun `what the person would be asked to do outranks who the message claims to be`() {
        assertEquals(SmsAlertReason.CODE, SmsAlertText.topReason(listOf("claims_organisation", "asks_for_code")))
        assertEquals(
            SmsAlertReason.CALL,
            SmsAlertText.topReason(listOf("claims_organisation", "threat_or_urgency", "call_unknown_number")),
        )
        assertEquals(SmsAlertReason.SAFE_ACCOUNT, SmsAlertText.topReason(listOf("threat_or_urgency", "safe_account")))
        assertEquals(SmsAlertReason.INSTALL, SmsAlertText.topReason(listOf("link_not_official", "link_apk")))
    }

    @Test
    fun `a fake brand site is named as such, a plain foreign link as not official`() {
        assertEquals(
            SmsAlertReason.FAKE_SITE,
            SmsAlertText.topReason(listOf("claims_organisation", "link_not_official", "link_imitates_brand")),
        )
        assertEquals(SmsAlertReason.LINK, SmsAlertText.topReason(listOf("claims_organisation", "link_not_official")))
        assertEquals(SmsAlertReason.LINK, SmsAlertText.topReason(listOf("threat_or_urgency", "link_shortener")))
    }

    @Test
    fun `the sender lie outranks pressure and name-dropping`() {
        assertEquals(SmsAlertReason.SENDER, SmsAlertText.topReason(listOf("claims_organisation", "sender_mismatch")))
        assertEquals(SmsAlertReason.THREAT, SmsAlertText.topReason(listOf("claims_organisation", "threat_or_urgency")))
        assertEquals(SmsAlertReason.ORGANISATION, SmsAlertText.topReason(listOf("claims_organisation")))
    }

    @Test
    fun `every code the analyzer emits has a phrase, an unknown one reads as generic`() {
        assertEquals(emptySet<String>(), MessageAnalyzer.ALL_REASONS.toSet() - SmsAlertText.COVERED)
        assertEquals(SmsAlertReason.GENERIC, SmsAlertText.topReason(listOf("some_future_code")))
        assertEquals(SmsAlertReason.GENERIC, SmsAlertText.topReason(emptyList()))
    }

    @Test
    fun `the tap opens History on the SMS filter with that event`() {
        assertEquals("cleanway:///history?filter=sms&sms=00ff00ff00ff00ff", SmsAlertText.historyDeepLink("00ff00ff00ff00ff"))
        // Encoded: an id can never add parameters to the route.
        assertEquals("cleanway:///history?filter=sms&sms=a%26filter%3Dall", SmsAlertText.historyDeepLink("a&filter=all"))
    }

    private fun event(verdict: String, sender: String?, vararg reasons: String) = SmsEvent(
        id = "00000000000000aa", ts = 1L, sender = sender, verdict = verdict,
        reasons = reasons.toList(), hosts = listOf("gosuslugi-help.ru"),
    )

    @Test
    fun `the copy takes its title from the verdict and names one reason`() {
        val dangerous = SmsAlertText.copyFor(event("dangerous", "900", "claims_organisation", "asks_for_code"))
        assertTrue(dangerous.dangerous)
        assertEquals("900", dangerous.sender)
        assertEquals(SmsAlertReason.CODE, dangerous.reason)

        val caution = SmsAlertText.copyFor(event("caution", null, "link_shortener"))
        assertFalse(caution.dangerous)
        assertNull(caution.sender)
        assertEquals(SmsAlertReason.LINK, caution.reason)
    }

    @Test
    fun `each reason is shown with the phrase of the same name`() {
        for (reason in SmsAlertReason.values()) {
            val expected = R.string::class.java.getField("sms_reason_" + reason.name.lowercase()).getInt(null)
            assertEquals(reason.name, expected, SmsNotifier.reasonText(reason))
        }
    }

    /** What the person reads, built from the shipped strings the way SmsNotifier builds it. */
    private fun render(locale: String, event: SmsEvent): Pair<String, String> {
        val strings = strings(locale)
        val copy = SmsAlertText.copyFor(event)
        val title = strings.getValue(if (copy.dangerous) "sms_alert_title_dangerous" else "sms_alert_title_caution")
        val sender = copy.sender ?: strings.getValue("sms_alert_unknown_sender")
        val reason = strings.getValue("sms_reason_" + copy.reason.name.lowercase())
        return title to String.format(strings.getValue("sms_alert_text"), sender, reason)
    }

    private fun resDir(): File = listOf(File("src/main/res"), File("android/src/main/res")).first { it.exists() }

    private fun strings(dir: String): Map<String, String> =
        Regex("<string name=\"([^\"]+)\">([^<]*)</string>").findAll(File(resDir(), "$dir/strings.xml").readText())
            .associate { m ->
                m.groupValues[1] to m.groupValues[2]
                    .replace("\\'", "'").replace("\\\"", "\"")
                    .replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
            }

    @Test
    fun `the Russian warning reads as the founder wrote it, and holds no message text`() {
        val (title, text) = render("values-ru", event("dangerous", "900", "claims_organisation", "asks_for_code"))
        assertEquals("Похоже на мошенническое SMS", title)
        assertEquals(
            "От 900: просят назвать код из SMS. Не звоните по номеру из сообщения и не переходите по ссылкам.",
            text,
        )
        val (cautionTitle, unknown) = render("values-ru", event("caution", null, "threat_or_urgency"))
        assertEquals("Будьте осторожны с этим SMS", cautionTitle)
        assertEquals(
            "От неизвестного отправителя: пугают или торопят. Не звоните по номеру из сообщения и не переходите по ссылкам.",
            unknown,
        )
    }

    @Test
    fun `the English warning names the sender and the reason`() {
        val (title, text) = render("values", event("dangerous", "Sber", "link_blocklisted"))
        assertEquals("This SMS looks like a scam", title)
        assertTrue(text, text.startsWith("From Sber: the link leads to a known scam site."))
    }

    /**
     * The warning is one format string with two arguments, filled as
     * (sender, reason) by SmsNotifier. A translation that dropped or
     * renumbered one would show the wrong thing — or crash the format — in
     * that language only.
     */
    @Test
    fun `every locale's warning carries the sender and the reason, and names every phrase`() {
        val res = listOf(File("src/main/res"), File("android/src/main/res")).first { it.exists() }
        val locales = res.listFiles { f -> f.name.startsWith("values") }.orEmpty()
        assertEquals(10, locales.size)
        val phrases = SmsAlertReason.values().map { "sms_reason_" + it.name.lowercase() }
        for (dir in locales) {
            val xml = File(dir, "strings.xml").readText()
            val text = Regex("<string name=\"sms_alert_text\">([^<]*)</string>").find(xml)?.groupValues?.get(1)
            assertTrue("${dir.name}: sms_alert_text", text != null && "%1\$s" in text && "%2\$s" in text)
            for (p in phrases) assertTrue("${dir.name}: $p", xml.contains("<string name=\"$p\">"))
        }
    }
}
