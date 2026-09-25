package ai.cleanway.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * A long SMS arrives as several parts in one intent. Checked part by part, a
 * scam split across the boundary ("Госуслуги: аккаунт взломан" | "позвоните
 * +7 9…") would look harmless and one message would raise two alerts — so
 * the receiver groups by sender and joins in order before anything is judged.
 */
class IncomingSmsTest {
    @get:Rule val tmp = TemporaryFolder()

    @Test
    fun `the parts of one message are joined in arrival order`() {
        val sms = IncomingSmsParts.group(
            listOf(
                SmsPart("900", "Госуслуги: ваш аккаунт взло", 1_000L),
                SmsPart("900", "ман. Срочно позвоните +7 912 ", 1_000L),
                SmsPart("900", "345-67-89", 1_000L),
            )
        )
        assertEquals(1, sms.size)
        assertEquals("Госуслуги: ваш аккаунт взломан. Срочно позвоните +7 912 345-67-89", sms[0].text)
        assertEquals("900", sms[0].sender)
    }

    @Test
    fun `a scam split across parts is caught once the parts are joined`() {
        val analyzer = MessageTestSupport.analyzer()
        val parts = listOf(
            SmsPart("+79161234567", "Госуслуги: ваш аккаунт взломан. Срочно позвоните ", 1L),
            SmsPart("+79161234567", "+7 912 345-67-89", 1L),
        )
        val joined = IncomingSmsParts.group(parts).single()
        assertEquals(MessageVerdict.DANGEROUS, analyzer.analyze(joined.text, joined.sender).verdict)
        for (p in parts) {
            val alone = analyzer.analyze(p.body.orEmpty(), p.sender).verdict
            assertTrue("part alone: $alone", alone != MessageVerdict.DANGEROUS)
        }
    }

    /**
     * The receiver's whole path, minus Android: parts → one message → verdict
     * → event → store. The telephony stack re-broadcasts a message it did not
     * get acknowledged (a reboot mid-delivery); the person must get one
     * warning for one SMS, not one per part and not one per delivery.
     */
    @Test
    fun `a multipart scam delivered twice is one event and one alert`() {
        val analyzer = MessageTestSupport.analyzer(MessageTestSupport.list("gosuslugi-help.ru"))
        val parts = listOf(
            SmsPart("900", "Госуслуги: ваш аккаунт взломан. Срочно войдите: ", 1_700_000_000_000L),
            SmsPart("900", "https://gosuslugi-help.ru/login", 1_700_000_000_000L),
        )
        val store = SmsEventLog.of(tmp.newFolder())
        val alerts = (1..2).count {
            val sms = IncomingSmsParts.group(parts).single()
            val event = SmsEvents.eventFor(sms, analyzer.analyze(sms.text, sms.sender), now = 2_000L + it)
            assertNotNull(event)
            store.record(2_000L + it, event)
        }
        assertEquals(1, alerts)
        val log = store.read(now = 3_000L)
        assertEquals(1, log.events.size)
        assertEquals(2L, log.checked)
        assertEquals(listOf("gosuslugi-help.ru"), log.events[0].hosts)
    }

    @Test
    fun `a benign SMS leaves only the counter`() {
        val analyzer = MessageTestSupport.analyzer()
        val sms = IncomingSmsParts.group(listOf(SmsPart("Tele2", "Ваш баланс 120 руб.", 1L))).single()
        val store = SmsEventLog.of(tmp.newFolder())
        assertFalse(store.record(5L, SmsEvents.eventFor(sms, analyzer.analyze(sms.text, sms.sender), 5L)))
        val log = store.read(now = 5L)
        assertEquals(1L, log.checked)
        assertEquals(5L, log.lastCheckedAt)
        assertTrue(log.events.isEmpty())
    }

    @Test
    fun `two senders in one intent stay two messages, in order of first part`() {
        val sms = IncomingSmsParts.group(
            listOf(
                SmsPart("+79001112233", "a1", 5L),
                SmsPart("Tele2", "b1", 7L),
                SmsPart("+79001112233", "a2", 3L),
            )
        )
        assertEquals(listOf("+79001112233", "Tele2"), sms.map { it.sender })
        assertEquals(listOf("a1a2", "b1"), sms.map { it.text })
        // The earliest service-centre stamp names the message (its event id).
        assertEquals(3L, sms[0].sentAtMs)
    }

    @Test
    fun `a sender with stray spaces is the same sender`() {
        val sms = IncomingSmsParts.group(listOf(SmsPart(" 900", "a", 1L), SmsPart("900 ", "b", 1L)))
        assertEquals(1, sms.size)
        assertEquals("ab", sms[0].text)
    }

    @Test
    fun `a missing sender or body does not crash and does not invent one`() {
        val sms = IncomingSmsParts.group(listOf(SmsPart(null, null, 1L), SmsPart(null, "текст", 1L)))
        assertEquals(1, sms.size)
        assertNull(sms[0].sender)
        assertEquals("текст", sms[0].text)
    }

    @Test
    fun `no parts, no messages`() {
        assertEquals(emptyList<IncomingSms>(), IncomingSmsParts.group(emptyList()))
    }

    @Test
    fun `a right-to-left override cannot disguise the sender`() {
        // "\u202Eknabrebs" renders as "sberbank" if the override survives.
        assertEquals("knabrebs", IncomingSmsParts.cleanSender("\u202Eknabrebs"))
        assertEquals("Sber", IncomingSmsParts.cleanSender("S\u200Bb\u2066er\u0007"))
    }

    @Test
    fun `whitespace collapses and blank reads as no sender`() {
        assertEquals("MTS Bank", IncomingSmsParts.cleanSender("  MTS \n\t Bank "))
        assertEquals("MTS Bank", IncomingSmsParts.cleanSender("MTS\nBank"))
        assertNull(IncomingSmsParts.cleanSender("  \u200E "))
        assertNull(IncomingSmsParts.cleanSender(null))
    }

    @Test
    fun `a long sender is capped without splitting a character`() {
        val long = "😀".repeat(40)
        val cleaned = requireNotNull(IncomingSmsParts.cleanSender(long))
        assertEquals("😀".repeat(IncomingSmsParts.MAX_SENDER_CHARS) + "…", cleaned)
        assertEquals("+79001234567", IncomingSmsParts.cleanSender("+79001234567"))
    }
}
