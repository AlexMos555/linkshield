package ai.cleanway.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

/**
 * The install number sent with site checks (InstallId): renewed every day,
 * and stored where Android's backup does not reach.
 *
 * Review of 1.0.2 found the first version kept one UUID for the life of the
 * install in a SharedPreferences file — which Android Auto Backup (the
 * expo-secure-store rules include every shared_prefs file) copied to Google
 * Drive and back after a reinstall, and onto a new phone. So "deleted with the
 * app" was false, and one number could tie together every tapped site of an
 * install for as long as it lived. The rate limit it exists for counts per
 * hour; a day-old number is all it needs.
 */
class InstallIdTest {

    private val day = InstallId.ROTATE_AFTER_MS
    private val a = "3f2b8c1e-9d4a-4e7b-8a61-0c5d2e9f7b13"
    private val b = "a1c4e7f0-2b5d-4c8e-9f13-6a7b8c9d0e1f"
    private fun make(id: String) = { id }

    @Test
    fun `a number younger than a day is kept`() {
        val stored = InstallId.Stamped(a, 1_000L)
        assertSame(stored, InstallId.current(stored, 1_000L + day - 1, make(b)))
    }

    @Test
    fun `after a day a new number is made`() {
        val next = InstallId.current(InstallId.Stamped(a, 1_000L), 1_000L + day, make(b))
        assertEquals(InstallId.Stamped(b, 1_000L + day), next)
    }

    @Test
    fun `a clock that went backwards renews rather than keeps a number forever`() {
        assertEquals(b, InstallId.current(InstallId.Stamped(a, 5_000L), 4_000L, make(b)).id)
    }

    @Test
    fun `nothing stored, or something that is not a random UUID, gets a new number`() {
        assertEquals(InstallId.Stamped(b, 7L), InstallId.current(null, 7L, make(b)))
        assertEquals(b, InstallId.current(InstallId.Stamped("android-id-1234", 7L), 8L, make(b)).id)
    }

    @Test
    fun `the stored form reads back, and anything else reads as nothing`() {
        val s = InstallId.Stamped(a, 1_727_400_000_000L)
        assertEquals(s, InstallId.parse(InstallId.format(s)))
        assertNull(InstallId.parse(null))
        assertNull(InstallId.parse(""))
        assertNull(InstallId.parse(a))
        assertNull(InstallId.parse("$a\nsoon"))
        assertNotEquals(s, InstallId.parse(InstallId.format(InstallId.Stamped(a, 1L))))
    }
}
