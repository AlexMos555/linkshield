package ai.cleanway.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import java.util.concurrent.ConcurrentHashMap

/**
 * Tells an open app when the phone's connection comes or goes, so the home
 * screen follows it instead of polling. In 1.0.2 the screen checked only on
 * opening and on returning to the foreground: it kept «Нет сети» for five
 * minutes and more after the network was back, on a phone that was protected.
 *
 * Watches the NOT_VPN networks, like UnderlyingNetworks: our own VPN is the
 * default network for this app, and it stays "up" with no connection under
 * it. [onChange] runs on the ConnectivityManager's thread and only when the
 * summary changes ([Level]) — never for the signal-strength updates that
 * arrive every few seconds. Registered only while the app's JS listens (the
 * module's observers); a callback costs nothing between network changes.
 */
class NetworkPresence(context: Context, private val onChange: (Level) -> Unit) {

    /** No network; a network the phone has not confirmed internet on (yet); a confirmed one. */
    enum class Level { NONE, UNCONFIRMED, ONLINE }

    private val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val validated = ConcurrentHashMap<Network, Boolean>()
    private var last: Level? = null
    private var registered = false

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return
            validated[network] = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            publish()
        }

        override fun onLost(network: Network) {
            validated.remove(network)
            publish()
        }
    }

    fun start() {
        if (registered) return
        // Start from what is there now, so the callbacks that describe the
        // existing networks right after registering change nothing and
        // announce nothing: the screen has just checked this connection itself.
        synchronized(this) {
            validated.putAll(snapshot())
            last = levelOf(validated.values)
        }
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        try {
            cm.registerNetworkCallback(request, callback)
            registered = true
        } catch (e: Exception) {
            // No events: the screen still re-checks on every foreground.
            Log.w(TAG, "presence_callback_failed: ${e.javaClass.simpleName}")
        }
    }

    fun stop() {
        if (!registered) return
        try {
            cm.unregisterNetworkCallback(callback)
        } catch (_: Exception) {
        }
        registered = false
        synchronized(this) {
            validated.clear()
            last = null
        }
    }

    @Synchronized
    private fun publish() {
        val level = levelOf(validated.values)
        if (level == last) return
        last = level
        onChange(level)
    }

    /** The non-VPN internet networks right now, and whether each is validated. */
    private fun snapshot(): Map<Network, Boolean> = try {
        @Suppress("DEPRECATION")
        cm.allNetworks.mapNotNull { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return@mapNotNull null
            network to caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        }.toMap()
    } catch (e: Exception) {
        emptyMap()
    }

    companion object {
        private const val TAG = "CleanwayVPN"

        /** Pure: the summary of the non-VPN networks' "validated" flags. */
        fun levelOf(validated: Collection<Boolean>): Level = when {
            validated.isEmpty() -> Level.NONE
            validated.any { it } -> Level.ONLINE
            else -> Level.UNCONFIRMED
        }
    }
}
