package ai.cleanway.app

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build

/**
 * What THIS installed APK is and how it got onto the phone — the facts the
 * SMS set-up screen needs to tell the truth.
 *
 * [smsAutoSupported]: only the RuStore APK declares RECEIVE_SMS (see
 * mobile/plugins/withRustoreVariant.js); the browser-downloaded one must not,
 * because Play Protect hard-blocks sideloaded apps that do. Read from the
 * installed manifest, not a build flag, so the answer cannot disagree with
 * what Android will actually let the app ask for.
 *
 * [installSource]: on Android 15+ an app installed from a browser download or
 * a local file (package source 4 or 3) is under "restricted settings": its
 * first SMS permission request is refused with a system dialog, and the
 * person must first allow restricted settings in App info. Whether a RuStore
 * install is exempt is not known, so the UI reads this and handles both.
 */
object AppInstallInfo {
    const val RECEIVE_SMS = "android.permission.RECEIVE_SMS"

    /** PackageInstaller.PACKAGE_SOURCE_* range (API 33+): 0 unspecified … 4 downloaded file. */
    private val PACKAGE_SOURCES = 0..4

    /**
     * Who installed the app, as Android reports it. Each field is null when
     * the platform does not say (older Android, or no installer recorded).
     */
    data class InstallSource(
        /** The installing package: "ru.vk.store" for RuStore, the system package installer for a sideload. */
        val installer: String?,
        /** The package that started the install (API 30+). */
        val initiator: String?,
        /** PackageInstaller.PACKAGE_SOURCE_* (API 33+). */
        val packageSource: Int?,
    ) {
        fun toWire(): Map<String, Any?> =
            mapOf("installer" to installer, "initiator" to initiator, "packageSource" to packageSource)
    }

    /** True only when this APK's manifest requests RECEIVE_SMS: the RuStore build. */
    fun smsAutoSupported(context: Context): Boolean =
        declares(requestedPermissions(context), RECEIVE_SMS)

    fun installSource(context: Context): InstallSource {
        val pm = context.packageManager
        val pkg = context.packageName
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val info = pm.getInstallSourceInfo(pkg)
            val source = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) info.packageSource else null
            return of(info.installingPackageName, info.initiatingPackageName, source)
        }
        @Suppress("DEPRECATION")
        return of(pm.getInstallerPackageName(pkg), null, null)
    }

    /** Pure: does the requested-permission list include [permission]? A missing list includes nothing. */
    fun declares(requested: Array<String>?, permission: String): Boolean =
        requested?.contains(permission) == true

    /** Pure: blank package names and out-of-range sources read as "not reported". */
    fun of(installer: String?, initiator: String?, packageSource: Int?): InstallSource =
        InstallSource(
            installer = installer?.takeIf { it.isNotBlank() },
            initiator = initiator?.takeIf { it.isNotBlank() },
            packageSource = packageSource?.takeIf { it in PACKAGE_SOURCES },
        )

    private fun requestedPermissions(context: Context): Array<String>? {
        val pm = context.packageManager
        val info = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageInfo(context.packageName, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
        }
        return info.requestedPermissions
    }
}
