package ai.cleanway.app

import java.net.Inet4Address
import java.net.InetAddress

/** How a network reaches the internet — only what the choice below needs. */
enum class NetKind { ETHERNET, WIFI, CELLULAR, OTHER }

/**
 * One non-VPN network the phone is connected to, as the service's network
 * callback last saw it. [handle] is the platform's Network object (opaque
 * here, so the choice stays JVM-testable); [sinceMs] is when it appeared.
 */
data class NetworkCandidate<T>(
    val handle: T,
    val kind: NetKind,
    val validated: Boolean,
    val dnsServers: List<InetAddress>,
    val sinceMs: Long,
)

/**
 * The resolver to forward to first, and the network it must be reached over.
 * [validated]: Android has confirmed this network reaches the internet.
 */
data class UpstreamNetwork<T>(
    val handle: T,
    val kind: NetKind,
    val servers: List<InetAddress>,
    val validated: Boolean,
)

/**
 * Which network's own DNS servers the shield forwards to first.
 *
 * Without Cleanway the phone asks the resolver of the network it is on — the
 * operator's on mobile data, the router's at home. The shield used to replace
 * that with Cloudflare and Quad9 for every query. In Russia in 2026 that is
 * the fragile choice: providers intercept or throttle foreign resolvers, and
 * a whitelist-mode mobile network may not reach them at all — then every app
 * loses the internet with Cleanway on, apps that would work without it. It
 * also switched off the operator's own anti-phishing DNS without a word. So
 * the network's resolver goes first, and the public ones are the fallback.
 *
 * Our VPN is itself a network, and its DNS server is ourselves; the choice is
 * made only among the UNDERLYING networks (the callback asks for NOT_VPN), so
 * the shield can never forward into its own tunnel.
 *
 * Pure: JVM-tested in UnderlyingDnsTest.
 */
object UnderlyingDns {
    /** Queries go to this many of the network's servers at once; the first answer wins. */
    const val MAX_SERVERS = 2

    /**
     * The network whose resolver to use, or null when none is known — the
     * chain is then the public resolvers alone.
     *
     * Android routes through a validated network in preference to one that
     * has not passed its internet check, and through Wi-Fi or Ethernet in
     * preference to mobile data; the shield follows the same order, so its
     * DNS goes the way the rest of the traffic does. Among equals the newest
     * wins: the one the phone just switched to.
     *
     * [excluded] holds addresses a server must never be — the tunnel's own.
     */
    fun <T> choose(candidates: Collection<NetworkCandidate<T>>, excluded: Set<InetAddress>): UpstreamNetwork<T>? =
        candidates
            .map { it to usableServers(it.dnsServers, excluded) }
            .filter { (_, servers) -> servers.isNotEmpty() }
            .sortedWith(
                compareBy<Pair<NetworkCandidate<T>, List<InetAddress>>> { (c, _) -> if (c.validated) 0 else 1 }
                    .thenBy { (c, _) -> c.kind.ordinal }
                    .thenByDescending { (c, _) -> c.sinceMs },
            )
            .firstOrNull()
            ?.let { (c, servers) -> UpstreamNetwork(c.handle, c.kind, servers, c.validated) }

    /**
     * Did the phone just get a connection worth retrying a failed download
     * on? Another network, or the same one Android has now confirmed reaches
     * the internet — a Wi-Fi after its sign-in page, a cellular link that took
     * its time in a basement. Both arrive before they work: a network is
     * published as soon as it has an address and DNS servers, confirmed or
     * not, and its confirmation used to publish nothing at all.
     */
    fun <T> isArrival(previous: UpstreamNetwork<T>?, next: UpstreamNetwork<T>): Boolean =
        next.handle != previous?.handle || (next.validated && previous?.validated == false)

    /**
     * The servers worth asking, best first: IPv4 before IPv6 (the IPv6 path
     * of a mobile network is the likelier to be half-broken), never a
     * wildcard, loopback, multicast or [excluded] address, at most
     * [MAX_SERVERS].
     */
    fun usableServers(servers: List<InetAddress>, excluded: Set<InetAddress>): List<InetAddress> =
        servers
            .asSequence()
            .filterNot { it.isAnyLocalAddress || it.isLoopbackAddress || it.isMulticastAddress || it in excluded }
            .distinct()
            .sortedBy { if (it is Inet4Address) 0 else 1 }
            .take(MAX_SERVERS)
            .toList()

    /**
     * Can this answer from the network's resolver be handed to the app?
     *
     * SERVFAIL (2) and REFUSED (5) say the resolver could not answer, not
     * that the name is bad; passing them on would break a lookup the public
     * resolvers could still make. They count as a failure of the transport,
     * so the chain moves on. Every other code is an answer — NXDOMAIN
     * included, and so is the operator's own block of a phishing name, which
     * is exactly what must reach the app.
     */
    fun isUsableAnswer(dnsPayload: ByteArray, offset: Int, length: Int): Boolean {
        if (length < DNS_HEADER) return false
        val rcode = dnsPayload[offset + 3].toInt() and 0x0F
        return rcode != RCODE_SERVFAIL && rcode != RCODE_REFUSED
    }

    private const val DNS_HEADER = 12
    private const val RCODE_SERVFAIL = 2
    private const val RCODE_REFUSED = 5
}
