package ai.cleanway.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.util.Log
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * Follows the phone's non-VPN networks and says whose resolver the shield
 * should forward to first. Android glue only — the choice itself is
 * [UnderlyingDns.choose], JVM-tested.
 *
 * Our own VPN is the default network for this app too, and its DNS server is
 * ourselves, so the default-network APIs cannot answer this. The callback asks
 * for NOT_VPN networks instead: Wi-Fi, mobile data, Ethernet — the ones the
 * tunnel runs over.
 *
 * [onChange] runs on the ConnectivityManager's thread, only when the answer
 * actually changes: another network, other servers, or Android confirming
 * (or no longer confirming) that the network reaches the internet.
 */
class UnderlyingNetworks(
    context: Context,
    private val excluded: Set<InetAddress>,
    private val onChange: (UpstreamNetwork<Network>?) -> Unit,
) {
    private val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val known = ConcurrentHashMap<Network, NetworkCandidate<Network>>()
    private var current: UpstreamNetwork<Network>? = null
    private var registered = false

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = update(network, caps, null)

        override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) = update(network, null, lp)

        override fun onLost(network: Network) {
            known.remove(network)
            publish()
        }
    }

    fun start() {
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        try {
            cm.registerNetworkCallback(request, callback)
            registered = true
        } catch (e: Exception) {
            // No callback, no network resolver: the public chain still works.
            Log.w(TAG, "network_callback_failed: ${e.javaClass.simpleName}")
        }
    }

    fun stop() {
        if (registered) {
            try {
                cm.unregisterNetworkCallback(callback)
            } catch (_: Exception) {
            }
            registered = false
        }
        synchronized(this) {
            known.clear()
            current = null
        }
    }

    /** A network appeared or changed: record what the choice needs, then re-choose. */
    @Synchronized
    private fun update(network: Network, caps: NetworkCapabilities?, lp: LinkProperties?) {
        val capabilities = caps ?: cm.getNetworkCapabilities(network) ?: return
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return
        val props = lp ?: cm.getLinkProperties(network) ?: return
        known[network] = NetworkCandidate(
            handle = network,
            kind = kindOf(capabilities),
            validated = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
            dnsServers = props.dnsServers,
            sinceMs = known[network]?.sinceMs ?: System.currentTimeMillis(),
        )
        publish()
    }

    @Synchronized
    private fun publish() {
        val next = UnderlyingDns.choose(known.values, excluded)
        if (next == current) return
        current = next
        onChange(next)
    }

    private fun kindOf(caps: NetworkCapabilities): NetKind = when {
        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> NetKind.ETHERNET
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetKind.WIFI
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetKind.CELLULAR
        else -> NetKind.OTHER
    }

    private companion object {
        const val TAG = "CleanwayVPN"
    }
}
