package ai.cleanway.app

/**
 * The pure half of "keep protection on after the app is closed" — no
 * android.* imports, so it runs on the JVM (KeepAlivePolicyTest). The Android
 * half is [KeepAlive] (settings screens) and [ShieldWatchdog] (re-arming).
 *
 * Three questions live here:
 *  1. Which phone maker's battery manager are we up against ([oemFamily])?
 *  2. Which of its settings screens to try, newest first ([oemTargets])?
 *  3. Should a background re-arm start the shield right now ([decideRearm])?
 */
internal object KeepAlivePolicy {

    /**
     * Phone makers whose own battery managers stop background apps beyond
     * what stock Android does (dontkillmyapp.com's worst offenders). The wire
     * name goes to JS, which picks the localized steps by it.
     */
    enum class OemFamily(val wire: String) {
        SAMSUNG("samsung"),
        /** Xiaomi, Redmi, POCO — MIUI and HyperOS. */
        XIAOMI("xiaomi"),
        /** Huawei (EMUI) and Honor (Magic UI / MagicOS), which share the "App launch" screen. */
        HUAWEI("huawei"),
        /** OPPO, realme and OnePlus — ColorOS and its OxygenOS/realme UI branches. */
        OPPO("oppo"),
        /** vivo and iQOO — Funtouch OS / OriginOS. */
        VIVO("vivo"),
    }

    /**
     * The family for Build.MANUFACTURER / Build.BRAND, or null for a phone
     * whose battery management is stock Android (Pixel, Motorola, Nokia, …):
     * there the battery exemption is the whole story and no extra step is shown.
     * The brand is consulted too because sub-brands report it differently
     * (a POCO says MANUFACTURER=Xiaomi, an iQOO may say vivo or iQOO).
     */
    fun oemFamily(manufacturer: String?, brand: String?): OemFamily? {
        for (raw in listOf(manufacturer, brand)) {
            val name = raw?.trim()?.lowercase() ?: continue
            when {
                name.startsWith("samsung") -> return OemFamily.SAMSUNG
                name.startsWith("xiaomi") || name.startsWith("redmi") || name.startsWith("poco") -> return OemFamily.XIAOMI
                name.startsWith("huawei") || name.startsWith("honor") -> return OemFamily.HUAWEI
                name.startsWith("oppo") || name.startsWith("realme") || name.startsWith("oneplus") -> return OemFamily.OPPO
                name.startsWith("vivo") || name.startsWith("iqoo") -> return OemFamily.VIVO
            }
        }
        return null
    }

    /**
     * An OEM settings screen, by explicit component. [packageExtras]: the
     * screen wants to be told which app (MIUI's battery saver page reads
     * `package_name` / `package_label`).
     */
    data class SettingsTarget(val pkg: String, val cls: String, val packageExtras: Boolean = false)

    /**
     * The OEM's own screens to try, best first. None of these are public
     * API: each was moved or renamed by some firmware update, which is why
     * there are several and why every caller falls back to this app's page in
     * system Settings (App info), from where every one of these OEMs exposes
     * its battery options. An activity that is missing or not exported throws
     * on start, and the next one is tried — nothing here may crash the app.
     */
    fun oemTargets(family: OemFamily): List<SettingsTarget> = when (family) {
        OemFamily.SAMSUNG -> listOf(
            // "Background usage limits" itself (sleeping / never-sleeping apps).
            // Resolves on a Galaxy A16, One UI 8 / Android 16 (2026-10, read-only check).
            SettingsTarget("com.samsung.android.lool", "com.samsung.android.sm.battery.ui.setting.AppPowerManagementActivity"),
            // Device care → Battery, one level up (One UI 1–8).
            SettingsTarget("com.samsung.android.lool", "com.samsung.android.sm.battery.ui.BatteryActivity"),
            SettingsTarget("com.samsung.android.sm", "com.samsung.android.sm.ui.battery.BatteryActivity"),
        )
        OemFamily.XIAOMI -> listOf(
            // Security → Autostart: off by default for sideloaded and new apps.
            SettingsTarget("com.miui.securitycenter", "com.miui.permcenter.autostart.AutoStartManagementActivity"),
            // App battery saver → "No restrictions", opened on this app.
            SettingsTarget("com.miui.powerkeeper", "com.miui.powerkeeper.ui.HiddenAppsConfigActivity", packageExtras = true),
        )
        OemFamily.HUAWEI -> listOf(
            // Battery → App launch (EMUI 9+); Honor's MagicOS moved the package.
            SettingsTarget("com.huawei.systemmanager", "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity"),
            SettingsTarget("com.hihonor.systemmanager", "com.hihonor.systemmanager.startupmgr.ui.StartupNormalAppListActivity"),
            // Older EMUI: "Protected apps".
            SettingsTarget("com.huawei.systemmanager", "com.huawei.systemmanager.optimize.process.ProtectActivity"),
        )
        OemFamily.OPPO -> listOf(
            // ColorOS "Startup manager" / auto launch, across its renames.
            SettingsTarget("com.coloros.safecenter", "com.coloros.safecenter.permission.startup.StartupAppListActivity"),
            SettingsTarget("com.coloros.safecenter", "com.coloros.safecenter.startupapp.StartupAppListActivity"),
            SettingsTarget("com.oppo.safe", "com.oppo.safe.permission.startup.StartupAppListActivity"),
            // OnePlus (OxygenOS before the ColorOS merge): "Auto-launch".
            SettingsTarget("com.oneplus.security", "com.oneplus.security.chainlaunch.view.ChainLaunchAppListActivity"),
        )
        OemFamily.VIVO -> listOf(
            // i Manager → background start / high background power use.
            SettingsTarget("com.vivo.permissionmanager", "com.vivo.permissionmanager.activity.BgStartUpManagerActivity"),
            SettingsTarget("com.iqoo.secure", "com.iqoo.secure.ui.phoneoptimize.BgStartUpManager"),
            SettingsTarget("com.iqoo.secure", "com.iqoo.secure.ui.phoneoptimize.AddWhiteListActivity"),
        )
    }

    /** What a background re-arm decided, in the order it is checked. */
    enum class Rearm {
        /** The person turned protection off (or never on): nothing to bring back. */
        NOT_WANTED,
        /** The tunnel is up; nothing to do. */
        RUNNING,
        /**
         * Android took the tunnel away (onRevoke): the VPN permission was
         * withdrawn, or another VPN app took the slot. With the permission
         * still granted, VpnService.prepare() would silently take the slot
         * BACK from that other VPN — the person's latest choice — so we wait
         * for them to tap "Turn on" instead.
         */
        TAKEN_AWAY,
        /** Strict Private DNS: the service would refuse to start anyway (PrivateDnsGuard). */
        PRIVATE_DNS,
        /** Another VPN is up right now: starting ours would knock it off. */
        OTHER_VPN,
        /** Too many re-arms in a short while: something keeps killing it; stop fighting until later. */
        BUDGET,
        /** Start the service. It still checks the VPN permission itself (prepare()) and stops if it is gone. */
        START,
        /**
         * Not from [decideRearm]: after it said START, the VPN permission
         * turned out to be gone (ShieldWatchdog checks it last, because the
         * check itself takes the VPN slot). Only the person can grant it again.
         */
        NO_CONSENT,
    }

    /**
     * Should a background trigger (the watchdog job, a boot) start the shield?
     * Pure, and ordered so that the first reason not to wins. VPN consent is
     * deliberately not an input: the only way to ask is VpnService.prepare(),
     * which has the side effect of taking the VPN slot — the service makes
     * that call itself, after these checks, exactly as on a boot.
     */
    fun decideRearm(
        userEnabled: Boolean,
        running: Boolean,
        stopReason: String?,
        privateDnsStrict: Boolean,
        otherVpnActive: Boolean,
        budgetLeft: Boolean,
    ): Rearm = when {
        !userEnabled -> Rearm.NOT_WANTED
        running -> Rearm.RUNNING
        stopReason == REASON_REVOKED -> Rearm.TAKEN_AWAY
        privateDnsStrict -> Rearm.PRIVATE_DNS
        otherVpnActive -> Rearm.OTHER_VPN
        !budgetLeft -> Rearm.BUDGET
        else -> Rearm.START
    }

    /** Mirrors CleanwayVpnService.REASON_REVOKED (kept literal so this file needs no Android class). */
    const val REASON_REVOKED = "revoked"

    /** At most this many background re-arms in [REARM_WINDOW_MS]. */
    const val REARM_MAX = 3
    const val REARM_WINDOW_MS = 60L * 60_000

    /**
     * Restart budget: a service that dies again right after each re-arm (a
     * crash, an OEM that kills it on sight) must not be restarted every 15
     * minutes all day — each start costs a cold start of the app's process.
     */
    fun budgetLeft(history: List<Long>, nowMs: Long): Boolean =
        recent(history, nowMs).size < REARM_MAX

    /** [history] with a re-arm at [nowMs] added, older entries dropped. */
    fun recordRearm(history: List<Long>, nowMs: Long): List<Long> = recent(history, nowMs) + nowMs

    /** Entries inside the window. A clock stepped backwards drops future entries rather than blocking forever. */
    private fun recent(history: List<Long>, nowMs: Long): List<Long> =
        history.filter { it in (nowMs - REARM_WINDOW_MS + 1)..nowMs }

    /** Stored form: comma-separated epoch ms. Unreadable entries are skipped: a damaged file never blocks a re-arm. */
    fun parseHistory(raw: String?): List<Long> =
        raw?.split(',')?.mapNotNull { it.trim().toLongOrNull() } ?: emptyList()

    fun formatHistory(history: List<Long>): String = history.joinToString(",")
}
