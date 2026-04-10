/**
 * LinkShield Android VPN Service
 *
 * DNS-only local VPN. Intercepts DNS queries to check domains
 * against blocklist. Does NOT inspect traffic content.
 *
 * Setup: Add VPN permission in AndroidManifest.xml:
 *   <uses-permission android:name="android.permission.BIND_VPN_SERVICE" />
 */

package io.linkshield.app

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.nio.ByteBuffer

class LinkShieldVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var running = false

    // Blocked domains cache
    private val blockedDomains = mutableSetOf<String>()
    private val safeDomains = mutableSetOf<String>()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") {
            stopVpn()
            return START_NOT_STICKY
        }

        startVpn()
        return START_STICKY
    }

    private fun startVpn() {
        val builder = Builder()
            .setSession("LinkShield")
            .addAddress("10.0.0.2", 32)
            .addDnsServer("10.0.0.1") // Our local DNS
            .addRoute("10.0.0.1", 32) // Only route DNS
            .setMtu(1500)
            .setBlocking(true)

        // Allow all apps except ourselves
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Exception) {}

        vpnInterface = builder.establish()
        running = true

        // Start DNS proxy in background thread
        Thread { dnsProxyLoop() }.start()
    }

    private fun stopVpn() {
        running = false
        vpnInterface?.close()
        vpnInterface = null
        stopSelf()
    }

    private fun dnsProxyLoop() {
        val vpn = vpnInterface ?: return
        val input = FileInputStream(vpn.fileDescriptor)
        val output = FileOutputStream(vpn.fileDescriptor)
        val buffer = ByteBuffer.allocate(32767)

        while (running) {
            try {
                buffer.clear()
                val length = input.read(buffer.array())
                if (length <= 0) continue

                buffer.limit(length)

                // Parse DNS query
                val domain = parseDNSDomain(buffer.array(), length)

                if (domain != null && shouldBlock(domain)) {
                    // Send NXDOMAIN response
                    val response = createNXDOMAIN(buffer.array(), length)
                    if (response != null) {
                        output.write(response)
                    }
                    continue
                }

                // Forward to real DNS (upstream)
                forwardToUpstream(buffer.array(), length, output)

            } catch (e: Exception) {
                if (!running) break
            }
        }
    }

    private fun shouldBlock(domain: String): Boolean {
        val normalized = domain.lowercase().trimEnd('.')

        // System domains — never block
        val systemSuffixes = listOf("google.com", "googleapis.com", "android.com", "linkshield.io")
        if (systemSuffixes.any { normalized.endsWith(it) }) return false

        if (safeDomains.contains(normalized)) return false
        if (blockedDomains.contains(normalized)) return true

        // Check API in background (non-blocking for first request)
        checkDomainAsync(normalized)
        return false
    }

    private fun checkDomainAsync(domain: String) {
        Thread {
            try {
                val url = java.net.URL("https://api.linkshield.io/api/v1/public/check/$domain")
                val conn = url.openConnection() as java.net.HttpURLConnection
                conn.connectTimeout = 3000
                conn.readTimeout = 3000

                if (conn.responseCode == 200) {
                    val body = conn.inputStream.bufferedReader().readText()
                    if (body.contains("\"dangerous\"")) {
                        blockedDomains.add(domain)
                        // Notify UI
                        sendBroadcast(Intent("io.linkshield.DOMAIN_BLOCKED").apply {
                            putExtra("domain", domain)
                        })
                    } else {
                        safeDomains.add(domain)
                        if (safeDomains.size > 10000) {
                            safeDomains.remove(safeDomains.first())
                        }
                    }
                }
            } catch (e: Exception) {
                // API unavailable — fail open
            }
        }.start()
    }

    private fun parseDNSDomain(packet: ByteArray, length: Int): String? {
        // Simplified DNS domain parser
        // Skip IP header (20 bytes) + UDP header (8 bytes) + DNS header (12 bytes)
        val offset = 40
        if (length <= offset) return null

        val sb = StringBuilder()
        var pos = offset

        while (pos < length) {
            val labelLen = packet[pos].toInt() and 0xFF
            if (labelLen == 0) break
            pos++
            if (pos + labelLen > length) break

            if (sb.isNotEmpty()) sb.append(".")
            sb.append(String(packet, pos, labelLen))
            pos += labelLen
        }

        return if (sb.isEmpty()) null else sb.toString()
    }

    private fun createNXDOMAIN(query: ByteArray, length: Int): ByteArray? {
        if (length < 44) return null
        val response = query.copyOf(length)
        // Set QR=1, RCODE=3 (NXDOMAIN)
        response[30] = 0x81.toByte()
        response[31] = 0x83.toByte()
        return response
    }

    private fun forwardToUpstream(packet: ByteArray, length: Int, output: FileOutputStream) {
        // In production: forward DNS query to 1.1.1.1 or 8.8.8.8
        // and write response back to VPN tunnel
        // This requires a proper UDP socket implementation
        output.write(packet, 0, length)
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}
