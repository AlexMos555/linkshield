package ai.cleanway.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * What this build must never ask for — pinned in a test so that a "small"
 * change cannot slip it in:
 *
 *  - no SMS permissions (the browser-downloaded APK never reads messages);
 *  - no phone-state, call-log, call-answering permissions and no
 *    call-screening role (call awareness comes from the audio mode alone);
 *  - no notification listener, no accessibility service, no overlay
 *    (SYSTEM_ALERT_WINDOW stays blocked).
 *
 * The same list is checked in CI by mobile/scripts/check-android-permissions.mjs
 * (this suite runs only in the local build sandbox). The second test keeps
 * our own notifications free of links and phone numbers: the site name is
 * plain text, and nothing in them is tappable except the notification itself.
 */
class PolicyGuardTest {

    private val forbidden = listOf(
        "RECEIVE_SMS", "READ_SMS", "SEND_SMS", "RECEIVE_MMS",
        "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "READ_CALL_LOG", "WRITE_CALL_LOG",
        "ANSWER_PHONE_CALLS", "CALL_PHONE", "PROCESS_OUTGOING_CALLS",
        "ROLE_CALL_SCREENING", "CallScreeningService", "InCallService",
        "BIND_NOTIFICATION_LISTENER_SERVICE", "NotificationListenerService",
        "BIND_ACCESSIBILITY_SERVICE", "AccessibilityService",
        "SYSTEM_ALERT_WINDOW", "RECORD_AUDIO",
        // Play special-access permissions the shield does not use. The one it
        // does (REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, the module manifest) is
        // pinned with its justification by check-android-permissions.mjs.
        "SCHEDULE_EXACT_ALARM", "USE_EXACT_ALARM", "QUERY_ALL_PACKAGES", "REQUEST_INSTALL_PACKAGES",
        "MANAGE_EXTERNAL_STORAGE", "ACCESS_BACKGROUND_LOCATION", "PACKAGE_USAGE_STATS",
    )

    /** The module's manifest and sources (the app's config is checked by the CI script). */
    private fun moduleFiles(): List<File> =
        File("src/main").walkTopDown().filter { it.isFile && (it.extension == "kt" || it.extension == "xml") }.toList()

    @Test
    fun `the manifest and sources never gain a call, SMS, listener or overlay permission`() {
        val manifest = File("src/main/AndroidManifest.xml")
        assertTrue("run from the module directory: ${manifest.absolutePath}", manifest.isFile)
        val hits = moduleFiles().flatMap { f ->
            val text = f.readText()
            forbidden.filter { needle ->
                // A mention in a comment is fine; a declaration, a string
                // constant or a class reference is not.
                Regex("""(uses-permission[^>]*$needle|permission\.$needle|"[A-Z_.]*$needle"|extends\s+$needle|:\s*$needle\(|import\s+[\w.]*$needle)""")
                    .containsMatchIn(text)
            }.map { "${f.path}: $it" }
        }
        assertEquals("forbidden permissions/roles found", emptyList<String>(), hits)
    }

    @Test
    fun `the app config asks for none of them either`() {
        // expo prebuild merges app.json's android.permissions into the manifest.
        val appJson = File("../../../app.json")
        if (!appJson.isFile) return
        val text = appJson.readText()
        val permissions = Regex(""""permissions"\s*:\s*\[(.*?)\]""", RegexOption.DOT_MATCHES_ALL).find(text)?.groupValues?.get(1) ?: ""
        val hits = forbidden.filter { needle -> permissions.contains(needle) }
        assertEquals("forbidden permissions in app.json", emptyList<String>(), hits)
    }

    @Test
    fun `our own notifications carry no links and no phone numbers`() {
        val res = File("src/main/res")
        if (!res.isDirectory) return
        val xmls = res.walkTopDown().filter { it.isFile && it.name == "strings.xml" }.toList()
        assertTrue("generated strings present", xmls.isNotEmpty())
        val bad = xmls.flatMap { f ->
            Regex("""<string name="([^"]+)">(.*?)</string>""").findAll(f.readText()).mapNotNull { m ->
                val (name, text) = m.destructured
                val link = Regex("""https?://|www\.|tel:""", RegexOption.IGNORE_CASE).containsMatchIn(text)
                val phone = Regex("""\+?\d[\d\s\-()]{6,}\d""").containsMatchIn(text)
                if (link || phone) "${f.parentFile?.name}/$name" else null
            }.toList()
        }
        assertEquals(emptyList<String>(), bad)
    }
}
