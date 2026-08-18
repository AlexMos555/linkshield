package ai.cleanway.app

import android.content.Context
import android.database.ContentObserver
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings

/**
 * Detects Android's *strict* Private DNS mode (Settings → Network → Private
 * DNS → "Private DNS provider hostname").
 *
 * Why this exists (verified on a rebooted emulator, 2026-08-18): with strict
 * Private DNS on AND our tunnel up, the resolver tries DNS-over-TLS to the
 * chosen provider *through the VPN network*, whose only route is our
 * 10.0.0.1/32 — the TLS connection can never leave, the network is flagged
 * `PrivateDnsBroken`, and strict mode refuses to fall back to plaintext. Net
 * effect: **no app on the phone can resolve a name** while both are on
 * (`ping example.com` → unknown host; `ping 1.1.1.1` fine). The user
 * experiences "Cleanway broke my internet". "Off" and "Automatic"
 * (opportunistic) coexist with the shield fine.
 *
 * Every DNS-filter VPN app on Android (AdGuard, RethinkDNS, Blokada) hits the
 * same wall and does the same thing: detect it, refuse to run, tell the user
 * which setting to change, and deep-link them there. That is what this does.
 *
 * Two independent signals, either sufficient:
 *  1. `Settings.Global` "private_dns_mode" == "hostname" — the user's choice,
 *     readable without permission, present even before any network is up.
 *     (The constant is @hide, so it is spelled out; OEMs have kept the name.)
 *  2. `LinkProperties.privateDnsServerName` on any non-VPN internet network —
 *     the public API, non-null only in strict mode.
 */
object PrivateDnsGuard {
    const val UNKNOWN_HOST = "?"

    private const val MODE_KEY = "private_dns_mode"
    private const val SPECIFIER_KEY = "private_dns_specifier"
    private const val MODE_STRICT = "hostname"

    /**
     * Pure decision. Returns the strict-mode hostname, [UNKNOWN_HOST] when
     * strict is set without a readable hostname, or null when not strict.
     */
    fun classify(mode: String?, specifier: String?, linkServerNames: List<String?>): String? {
        if (mode == MODE_STRICT) {
            return specifier?.trim()?.takeIf { it.isNotEmpty() } ?: UNKNOWN_HOST
        }
        return linkServerNames.firstOrNull { !it.isNullOrBlank() }
    }

    /** Strict-mode hostname if the device is in strict Private DNS mode, else null. */
    fun strictHostname(context: Context): String? {
        val resolver = context.contentResolver
        val mode = runCatching { Settings.Global.getString(resolver, MODE_KEY) }.getOrNull()
        val specifier = runCatching { Settings.Global.getString(resolver, SPECIFIER_KEY) }.getOrNull()
        return classify(mode, specifier, linkServerNames(context))
    }

    private fun linkServerNames(context: Context): List<String?> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return emptyList()
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return emptyList()
        return runCatching {
            @Suppress("DEPRECATION")
            cm.allNetworks.mapNotNull { network ->
                val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return@mapNotNull null
                cm.getLinkProperties(network)?.privateDnsServerName
            }
        }.getOrDefault(emptyList())
    }

    /**
     * Watches the Private DNS setting while the tunnel is up. The user can
     * flip it to strict at any moment; the service must step aside then, not
     * on the next foreground. Returns an unregister function.
     */
    fun watch(context: Context, onChange: () -> Unit): () -> Unit {
        val observer = object : ContentObserver(Handler(Looper.getMainLooper())) {
            override fun onChange(selfChange: Boolean) = onChange()
        }
        val resolver = context.contentResolver
        runCatching {
            resolver.registerContentObserver(Settings.Global.getUriFor(MODE_KEY), false, observer)
            resolver.registerContentObserver(Settings.Global.getUriFor(SPECIFIER_KEY), false, observer)
        }
        return { runCatching { resolver.unregisterContentObserver(observer) } }
    }
}
