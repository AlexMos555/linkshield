package ai.cleanway.app

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.Drawable
import android.net.Uri
import android.util.Base64
import java.io.ByteArrayOutputStream

/**
 * The apps on this phone, as the "Apps without the filter" screens show them:
 * the app's own name and icon, read locally. Nothing here leaves the phone or
 * reaches the log.
 *
 * Visibility (Android 11+): the module manifest's <queries> make visible every
 * app with a launcher icon and every app in assets/vpn_exclusions.json — no
 * QUERY_ALL_PACKAGES. An app outside both reads as not installed.
 */
object InstalledApps {
    /** Icon edge in pixels: sharp at 48 dp on a 2x screen, small over the bridge. */
    private const val ICON_PX = 96

    data class App(
        val pkg: String,
        val label: String,
        val icon: String?,
        /** In the shipped list (default or suggested). */
        val known: Boolean,
        /** A shipped default, not something the person added. */
        val isDefault: Boolean,
        /** Opens ordinary web links — excluding it would leave browsing unfiltered. */
        val isBrowser: Boolean,
    ) {
        fun toWire(): Map<String, Any?> = mapOf(
            "package" to pkg,
            "label" to label,
            "icon" to icon,
            "suggested" to known,
            "isDefault" to isDefault,
            "isBrowser" to isBrowser,
        )
    }

    /** The apps kept out of the tunnel that are installed, in the list's order. */
    fun excluded(context: Context): List<App> {
        val pm = context.packageManager
        val defaults = AppExclusions.defaults(context).toSet()
        val known = AppExclusions.known(context).map { it.pkg }.toSet()
        val browsers = browsers(context)
        return AppExclusions.current(context).mapNotNull { pkg ->
            info(pm, pkg)?.let { describe(pm, it, known = pkg in known, isDefault = pkg in defaults, browsers = browsers) }
        }
    }

    /**
     * What the person can pick from: apps with a launcher icon, plus installed
     * apps from the shipped list, minus Cleanway and minus those already
     * kept out. Unsorted — the screen sorts by the name it shows.
     */
    fun pickable(context: Context): List<App> {
        val pm = context.packageManager
        val self = context.packageName
        val current = AppExclusions.current(context).toSet()
        val known = AppExclusions.known(context).map { it.pkg }.toSet()
        val browsers = browsers(context)
        val infos = LinkedHashMap<String, ApplicationInfo>()
        val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        for (ri in pm.queryIntentActivities(launcher, 0)) {
            val info = ri.activityInfo?.applicationInfo ?: continue
            infos.putIfAbsent(info.packageName, info)
        }
        for (pkg in known) {
            if (pkg !in infos) info(pm, pkg)?.let { infos[pkg] = it }
        }
        return infos.values
            .filter { it.packageName != self && it.packageName !in current }
            .map { describe(pm, it, known = it.packageName in known, isDefault = false, browsers = browsers) }
    }

    /**
     * Would excluding [pkg] unfilter browsing? The picker refuses these, and
     * so does excludeApp: every site opened in a browser outside the tunnel
     * would go unchecked.
     */
    fun isBrowser(context: Context, pkg: String): Boolean = pkg in browsers(context)

    private fun info(pm: PackageManager, pkg: String): ApplicationInfo? = try {
        pm.getApplicationInfo(pkg, 0)
    } catch (_: PackageManager.NameNotFoundException) {
        null
    }

    private fun describe(
        pm: PackageManager,
        info: ApplicationInfo,
        known: Boolean,
        isDefault: Boolean,
        browsers: Set<String>,
    ): App = App(
        pkg = info.packageName,
        label = try {
            pm.getApplicationLabel(info).toString()
        } catch (_: Exception) {
            info.packageName
        },
        icon = try {
            dataUri(pm.getApplicationIcon(info))
        } catch (_: Exception) {
            null
        },
        known = known,
        isDefault = isDefault,
        isBrowser = info.packageName in browsers,
    )

    /** Packages that open an ordinary web link (visible through the module's http/https <queries>). */
    private fun browsers(context: Context): Set<String> = try {
        val probe = Intent(Intent.ACTION_VIEW, Uri.parse("https://example.com")).addCategory(Intent.CATEGORY_BROWSABLE)
        // MATCH_ALL: with Cleanway holding the browser role, flags=0 returns
        // only the role holder (see LinkGuardActivity).
        context.packageManager.queryIntentActivities(probe, PackageManager.MATCH_ALL)
            .mapNotNull { it.activityInfo?.packageName }
            .toSet()
    } catch (_: Exception) {
        emptySet()
    }

    private fun dataUri(drawable: Drawable): String? {
        val bitmap = Bitmap.createBitmap(ICON_PX, ICON_PX, Bitmap.Config.ARGB_8888)
        return try {
            val canvas = Canvas(bitmap)
            drawable.setBounds(0, 0, ICON_PX, ICON_PX)
            drawable.draw(canvas)
            val out = ByteArrayOutputStream()
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
            "data:image/png;base64," + Base64.encodeToString(out.toByteArray(), Base64.NO_WRAP)
        } catch (_: Exception) {
            null
        } finally {
            bitmap.recycle()
        }
    }
}
