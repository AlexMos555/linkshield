package ai.cleanway.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** The "close one" number as the phone app takes it (CloseContact.normalize). */
class CloseContactTest {

    @Test
    fun `numbers as people type them`() {
        assertEquals("+79161234567", CloseContact.normalize("+7 916 123-45-67"))
        assertEquals("89161234567", CloseContact.normalize("8 (916) 123 45 67"))
        assertEquals("112", CloseContact.normalize("112"))
        assertEquals("+79161234567", CloseContact.normalize("  +7 916 123 45 67 "))
    }

    @Test
    fun `not a number`() {
        assertNull(CloseContact.normalize(""))
        assertNull(CloseContact.normalize("Саша"))
        assertNull(CloseContact.normalize("12"))
        assertNull(CloseContact.normalize("+7 916 123 45 67 доб. 5"))
        assertNull(CloseContact.normalize("tel:+79161234567"))
        assertNull(CloseContact.normalize("123456789012345678901"))
    }
}
