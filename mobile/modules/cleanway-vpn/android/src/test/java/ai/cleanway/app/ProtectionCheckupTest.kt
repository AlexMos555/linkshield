package ai.cleanway.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Pins what "Позвонить близкому" may hand to the dialer. The number comes
 * from the person's own typing or address book, and it only fills the
 * dialer — but a stored "*#…#" would be a USSD code one tap away, so the
 * rule is: digits and one leading "+", nothing else. The same table runs
 * against the JS mirror in mobile/scripts/test-checkup.mjs.
 */
class ProtectionCheckupTest {

    @Test
    fun `russian numbers in the shapes people write them`() {
        assertEquals("+79161234567", ProtectionCheckup.dialable("+7 916 123-45-67"))
        assertEquals("+79161234567", ProtectionCheckup.dialable("+7 (916) 123-45-67"))
        assertEquals("89161234567", ProtectionCheckup.dialable("8 916 123 45 67"))
        assertEquals("89161234567", ProtectionCheckup.dialable("  8-916-123-45-67  "))
    }

    @Test
    fun `address book separators are dropped`() {
        // A non-breaking space and a non-breaking hyphen, as some contacts apps store them.
        assertEquals("+79161234567", ProtectionCheckup.dialable("+7 916‑123.45.67"))
    }

    @Test
    fun `short service numbers are dialable`() {
        assertEquals("112", ProtectionCheckup.dialable("112"))
        assertEquals("900", ProtectionCheckup.dialable("900"))
    }

    @Test
    fun `USSD codes, extensions and pauses are refused`() {
        assertNull(ProtectionCheckup.dialable("*#06#"))
        assertNull(ProtectionCheckup.dialable("*100#"))
        assertNull(ProtectionCheckup.dialable("+79161234567;ext=12"))
        assertNull(ProtectionCheckup.dialable("+79161234567,1"))
        assertNull(ProtectionCheckup.dialable("89161234567p12"))
    }

    @Test
    fun `letters, a second plus and non-ASCII digits are refused`() {
        assertNull(ProtectionCheckup.dialable("Саша"))
        assertNull(ProtectionCheckup.dialable("++79161234567"))
        assertNull(ProtectionCheckup.dialable("7+9161234567"))
        assertNull(ProtectionCheckup.dialable("٨٩١٦١٢٣٤٥٦٧"))
    }

    @Test
    fun `empty, too short and too long are refused`() {
        assertNull(ProtectionCheckup.dialable(null))
        assertNull(ProtectionCheckup.dialable(""))
        assertNull(ProtectionCheckup.dialable("  "))
        assertNull(ProtectionCheckup.dialable("+"))
        assertNull(ProtectionCheckup.dialable("12"))
        assertNull(ProtectionCheckup.dialable("1234567890123456"))
    }
}
