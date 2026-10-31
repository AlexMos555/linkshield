package ai.cleanway.app

import android.content.pm.PackageManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Which apps the shield keeps out of its tunnel (AppExclusions).
 *
 * The rules that matter: Cleanway itself is never excluded (its canary lookup
 * must cross the tunnel, or the shield can never prove it is on); an app that
 * is not installed is skipped, never fatal; the person's choices survive and
 * can be undone; and the shipped list stays in step with the manifest's
 * <queries> — without package visibility the shield cannot even see that MAX
 * is installed.
 */
class AppExclusionsTest {

    private val self = "ai.cleanway.app"

    // ── The shipped data file ─────────────────────────────────────────────

    private val assetFile: File by lazy {
        listOf(
            File("src/main/assets/${AppExclusions.ASSET}"),
            File("android/src/main/assets/${AppExclusions.ASSET}"),
        ).firstOrNull { it.exists() } ?: error("${AppExclusions.ASSET} not found from ${File(".").absolutePath}")
    }

    private val manifestFile: File by lazy {
        listOf(File("src/main/AndroidManifest.xml"), File("android/src/main/AndroidManifest.xml"))
            .firstOrNull { it.exists() } ?: error("AndroidManifest.xml not found")
    }

    private val shipped by lazy { AppExclusions.parseKnown(assetFile.readText()) }

    @Test
    fun `the shipped list parses whole and keeps MAX and Gosuslugi out by default`() {
        val raw = org.json.JSONObject(assetFile.readText()).getJSONArray("apps")
        assertEquals("every entry survives parsing", raw.length(), shipped.size)
        val defaults = shipped.filter { it.default }.map { it.pkg }
        assertTrue("MAX", "ru.oneme.app" in defaults)
        assertTrue("Gosuslugi", "ru.rostel" in defaults)
        assertEquals("no duplicates", shipped.size, shipped.map { it.pkg }.toSet().size)
        assertFalse("never Cleanway", shipped.any { it.pkg.startsWith("ai.cleanway") })
    }

    @Test
    fun `every shipped entry names its source`() {
        val raw = org.json.JSONObject(assetFile.readText()).getJSONArray("apps")
        for (i in 0 until raw.length()) {
            val o = raw.getJSONObject(i)
            val pkg = o.getString("package")
            assertTrue("$pkg: name", o.optString("name").isNotBlank())
            assertTrue("$pkg: package_source", o.optString("package_source").isNotBlank())
            assertTrue("$pkg: certain is a boolean", o.opt("certain") is Boolean)
            assertTrue("$pkg: default is a boolean", o.opt("default") is Boolean)
        }
    }

    @Test
    fun `the manifest makes every shipped package visible, and nothing else by name`() {
        val manifest = manifestFile.readText()
        val queried = Regex("""<package\s+android:name="([^"]+)"""").findAll(manifest).map { it.groupValues[1] }.toSet()
        val listed = shipped.map { it.pkg }.toSet()
        assertEquals("missing from <queries>", emptySet<String>(), listed - queried)
        assertEquals("in <queries> but not in the list", emptySet<String>(), queried - listed)
    }

    // ── Parsing ───────────────────────────────────────────────────────────

    @Test
    fun `a malformed file is an empty list, not a crash`() {
        assertEquals(emptyList<AppExclusions.Known>(), AppExclusions.parseKnown(null))
        assertEquals(emptyList<AppExclusions.Known>(), AppExclusions.parseKnown(""))
        assertEquals(emptyList<AppExclusions.Known>(), AppExclusions.parseKnown("{not json"))
        assertEquals(emptyList<AppExclusions.Known>(), AppExclusions.parseKnown("""{"apps": 3}"""))
    }

    @Test
    fun `a bad or repeated entry is dropped on its own`() {
        val parsed = AppExclusions.parseKnown(
            """{"apps": [
                {"package": "ru.oneme.app", "name": "МАКС", "default": true},
                {"package": "not a package", "default": true},
                {"package": "single", "default": true},
                {"package": "ru.oneme.app", "name": "dup", "default": false},
                {"package": "com.example.shop"}
            ]}""",
        )
        assertEquals(
            listOf(
                AppExclusions.Known("ru.oneme.app", "МАКС", true),
                AppExclusions.Known("com.example.shop", "com.example.shop", false),
            ),
            parsed,
        )
    }

    @Test
    fun `package names are checked the way Android spells them`() {
        assertTrue(AppExclusions.isPackageName("ru.letobank.Prometheus"))
        assertTrue(AppExclusions.isPackageName("logo.com.mbanking"))
        assertTrue(AppExclusions.isPackageName("ru.sovcomcard.halva.v1"))
        assertFalse(AppExclusions.isPackageName(null))
        assertFalse(AppExclusions.isPackageName("oneword"))
        assertFalse(AppExclusions.isPackageName("ru..double"))
        assertFalse(AppExclusions.isPackageName("ru.1digit"))
        assertFalse(AppExclusions.isPackageName("ru.oneme.app "))
        assertFalse(AppExclusions.isPackageName("ru/oneme"))
    }

    // ── What the tunnel keeps out ─────────────────────────────────────────

    @Test
    fun `defaults then the person's additions, in order, without repeats`() {
        assertEquals(
            listOf("ru.oneme.app", "ru.rostel", "com.example.bank"),
            AppExclusions.effective(
                defaults = listOf("ru.oneme.app", "ru.rostel"),
                added = listOf("com.example.bank", "ru.oneme.app"),
                refiltered = emptySet(),
                self = self,
            ),
        )
    }

    @Test
    fun `Cleanway itself is never kept out, whoever asks`() {
        val out = AppExclusions.effective(
            defaults = listOf(self, "ru.oneme.app"),
            added = listOf(self),
            refiltered = emptySet(),
            self = self,
        )
        assertEquals(listOf("ru.oneme.app"), out)
    }

    @Test
    fun `a default put back under the filter stays filtered`() {
        assertEquals(
            listOf("ru.rostel"),
            AppExclusions.effective(listOf("ru.oneme.app", "ru.rostel"), emptyList(), setOf("ru.oneme.app"), self),
        )
    }

    // ── Applying to the builder ───────────────────────────────────────────

    private val installedAll: (String) -> Boolean = { true }

    @Test
    fun `an app that is not installed never reaches the builder`() {
        // Android 15's builder accepted 12 uninstalled packages without a
        // NameNotFoundException (emulator, 2026-09-27): installed-ness has to
        // be asked, not inferred from the builder.
        val disallowed = mutableListOf<String>()
        val applied = AppExclusions.applyTo(
            listOf("ru.oneme.app", "ru.rostel", "com.example.bank"),
            self,
            isInstalled = { it != "ru.rostel" },
        ) { disallowed += it }
        assertEquals(listOf("ru.oneme.app", "com.example.bank"), disallowed)
        assertEquals(listOf("ru.oneme.app", "com.example.bank"), applied.excluded)
        assertEquals(listOf("ru.rostel"), applied.notInstalled)
        assertEquals(emptyList<String>(), applied.failed)
    }

    @Test
    fun `a builder that does throw NameNotFoundException is not fatal either`() {
        val applied = AppExclusions.applyTo(listOf("ru.oneme.app", "ru.rostel"), self, installedAll) { pkg ->
            if (pkg == "ru.rostel") throw PackageManager.NameNotFoundException(pkg)
        }
        assertEquals(listOf("ru.oneme.app"), applied.excluded)
        assertEquals(listOf("ru.rostel"), applied.notInstalled)
    }

    @Test
    fun `any other failure of one app never stops the shield`() {
        val applied = AppExclusions.applyTo(listOf("ru.oneme.app", "ru.rostel"), self, installedAll) { pkg ->
            if (pkg == "ru.oneme.app") throw UnsupportedOperationException("allowed list already set")
        }
        assertEquals(listOf("ru.rostel"), applied.excluded)
        assertEquals(listOf("ru.oneme.app"), applied.failed)
    }

    @Test
    fun `a failing installed-check is not fatal`() {
        val applied = AppExclusions.applyTo(
            listOf("ru.oneme.app", "ru.rostel"),
            self,
            isInstalled = { if (it == "ru.oneme.app") throw SecurityException("no") else true },
        ) {}
        assertEquals(listOf("ru.rostel"), applied.excluded)
        assertEquals(listOf("ru.oneme.app"), applied.failed)
    }

    @Test
    fun `the builder never sees Cleanway or a malformed name`() {
        val seen = mutableListOf<String>()
        val asked = mutableListOf<String>()
        AppExclusions.applyTo(
            listOf(self, "bad name", "ru.oneme.app", "ru.oneme.app"),
            self,
            isInstalled = { asked += it; true },
        ) { seen += it }
        assertEquals(listOf("ru.oneme.app"), seen)
        assertEquals(listOf("ru.oneme.app"), asked)
    }

    // ── The person's choices ──────────────────────────────────────────────

    private val defaults = listOf("ru.oneme.app", "ru.rostel")

    @Test
    fun `adding an app puts it first and adding it again changes nothing`() {
        val (added, refiltered) = AppExclusions.afterAdd("com.example.shop", defaults, listOf("com.example.bank"), emptySet())
        assertEquals(listOf("com.example.shop", "com.example.bank"), added)
        assertEquals(emptySet<String>(), refiltered)
        assertEquals(added to refiltered, AppExclusions.afterAdd("com.example.shop", defaults, added, refiltered))
    }

    @Test
    fun `re-adding a default only undoes putting it back under the filter`() {
        val (added, refiltered) = AppExclusions.afterAdd("ru.oneme.app", defaults, emptyList(), setOf("ru.oneme.app"))
        assertEquals(emptyList<String>(), added)
        assertEquals(emptySet<String>(), refiltered)
    }

    @Test
    fun `removing an added app forgets it, removing a default remembers the choice`() {
        val (added1, ref1) = AppExclusions.afterRemove("com.example.bank", defaults, listOf("com.example.bank"), emptySet())
        assertEquals(emptyList<String>(), added1)
        assertEquals(emptySet<String>(), ref1)

        val (added2, ref2) = AppExclusions.afterRemove("ru.oneme.app", defaults, emptyList(), emptySet())
        assertEquals(emptyList<String>(), added2)
        assertEquals(setOf("ru.oneme.app"), ref2)
        assertEquals(listOf("ru.rostel"), AppExclusions.effective(defaults, added2, ref2, self))
    }

    // ── Stored choices ────────────────────────────────────────────────────

    @Test
    fun `stored choices survive a round trip`() {
        val choices = AppExclusions.Choices(listOf("com.example.shop", "com.example.bank"), setOf("ru.rostel", "ru.oneme.app"))
        assertEquals(choices, AppExclusions.parseChoices(AppExclusions.renderChoices(choices)))
    }

    @Test
    fun `a damaged store reads as no choices, and bad names inside it are dropped`() {
        val none = AppExclusions.Choices(emptyList(), emptySet())
        assertEquals(none, AppExclusions.parseChoices(null))
        assertEquals(none, AppExclusions.parseChoices(""))
        assertEquals(none, AppExclusions.parseChoices("{\"added\": [\"com.exa"))
        assertEquals(none, AppExclusions.parseChoices("[1,2,3]"))
        assertEquals(
            AppExclusions.Choices(listOf("com.example.bank"), setOf("ru.rostel")),
            AppExclusions.parseChoices(
                """{"added": ["com.example.bank", "no spaces allowed", 7, "com.example.bank"], "refiltered": ["ru.rostel", ""]}""",
            ),
        )
    }

    @Test
    fun `the person's list is capped`() {
        val full = (1..AppExclusions.MAX).map { "com.example.app$it" }
        val (added, _) = AppExclusions.afterAdd("com.example.newest", defaults, full, emptySet())
        assertEquals(AppExclusions.MAX, added.size)
        assertEquals("com.example.newest", added.first())
    }
}
