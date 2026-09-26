package ai.cleanway.app

import java.io.InputStream
import java.net.HttpURLConnection
import java.net.SocketTimeoutException
import java.net.URL

/** How one request to the check endpoint ended. */
sealed class CheckFetch {
    data class Answered(val body: String) : CheckFetch()
    object TimedOut : CheckFetch()
    data class Failed(val reason: String) : CheckFetch()
}

/** HTTP abstraction so the retry rule is JVM-testable with a fake. */
fun interface CheckFetcher {
    fun fetch(host: String): CheckFetch
}

/**
 * The link guard's background check of one host: at most two requests.
 *
 * A first check of a site the server has never seen runs its whole analysis
 * and can take 10 s or more (measured 2026-09-25: 8 of 31 first checks over
 * 6 s, the slowest 10.9 s); the second request for the same site is answered
 * from the server's cache in tens of milliseconds. So a timeout is retried
 * once — by then the answer is usually waiting — and anything else (an HTTP
 * error, no network) is final: retrying a rate limit only digs deeper.
 *
 * Pure: JVM-tested in LinkVerdictPolicyTest.
 */
object LinkCheckRunner {
    fun run(host: String, fetcher: CheckFetcher): LinkAnswer? {
        var result = fetcher.fetch(host)
        if (result is CheckFetch.TimedOut) result = fetcher.fetch(host)
        return (result as? CheckFetch.Answered)?.let { LinkVerdictPolicy.parse(it.body) }
    }
}

/**
 * GET {apiBase}/api/v1/public/check/{host}. Only the host is sent — never the
 * path, never the page — plus the install number ([InstallId]) the server
 * rate-limits by.
 */
class HttpCheckFetcher(
    private val apiBase: String,
    private val installId: () -> String?,
) : CheckFetcher {
    override fun fetch(host: String): CheckFetch {
        var conn: HttpURLConnection? = null
        return try {
            conn = (URL("$apiBase/api/v1/public/check/$host").openConnection() as HttpURLConnection).apply {
                connectTimeout = CONNECT_TIMEOUT_MS
                readTimeout = READ_TIMEOUT_MS
                requestMethod = "GET"
                instanceFollowRedirects = false
                setRequestProperty("Accept", "application/json")
                setRequestProperty("User-Agent", "Cleanway-Android")
                installId()?.let { setRequestProperty(InstallId.HEADER, it) }
            }
            val code = conn.responseCode
            if (code == 200) {
                conn.inputStream.use { stream -> readCapped(stream)?.let { CheckFetch.Answered(it) } }
                    ?: CheckFetch.Failed("body too large")
            } else {
                CheckFetch.Failed("http $code")
            }
        } catch (_: SocketTimeoutException) {
            CheckFetch.TimedOut
        } catch (e: Exception) {
            CheckFetch.Failed(e.javaClass.simpleName)
        } finally {
            conn?.disconnect()
        }
    }

    /** The body as text, or null past [MAX_BODY_BYTES] — stops reading there. */
    private fun readCapped(input: InputStream): String? {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(8 * 1024)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            out.write(buf, 0, n)
            if (out.size() > MAX_BODY_BYTES) return null
        }
        return out.toString("UTF-8")
    }

    companion object {
        const val CONNECT_TIMEOUT_MS = 5_000
        /** "Wait up to ~12 s": a first check can legitimately take ten. */
        const val READ_TIMEOUT_MS = 12_000
        private const val MAX_BODY_BYTES = 64 * 1024
    }
}
