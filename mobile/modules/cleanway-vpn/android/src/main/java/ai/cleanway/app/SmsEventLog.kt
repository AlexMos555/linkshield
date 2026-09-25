package ai.cleanway.app

import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import java.security.MessageDigest
import org.json.JSONArray
import org.json.JSONObject

/** One SMS the automatic check flagged, as History keeps it. Never the text. */
data class SmsEvent(
    /** 16 hex characters. The notification's deep link names it; History opens only ids it finds here. */
    val id: String,
    /** When it arrived on the phone. */
    val ts: Long,
    /** As the phone showed it, cleaned (IncomingSmsParts.cleanSender); null when there was none. */
    val sender: String?,
    /** MessageVerdict.wire: "dangerous" or "caution" — nothing else is ever recorded. */
    val verdict: String,
    /** MessageAnalyzer reason codes, most important first. */
    val reasons: List<String>,
    /** Lowercase punycode hosts of the links, at most [SmsEvents.MAX_HOSTS]. */
    val hosts: List<String>,
) {
    fun toWire(): Map<String, Any?> = mapOf(
        "id" to id,
        "ts" to ts.toDouble(),
        "sender" to sender,
        "verdict" to verdict,
        "reasons" to reasons,
        "hosts" to hosts,
    )
}

/** Everything the store holds: counters for every checked SMS, events for the flagged ones. */
data class SmsLog(
    /** Every SMS checked, benign included — only ever a number: the proof the check runs. */
    val checked: Long,
    val lastCheckedAt: Long,
    /** Lifetime flagged totals. The event list is capped; these are not. */
    val dangerous: Long,
    val caution: Long,
    /** Newest first. */
    val events: List<SmsEvent>,
) {
    val flagged: Long get() = dangerous + caution

    companion object {
        val EMPTY = SmsLog(checked = 0L, lastCheckedAt = 0L, dangerous = 0L, caution = 0L, events = emptyList())
    }
}

/**
 * The pure half of [SmsEventLog]: format, record, prune. JVM-tested in
 * SmsEventLogTest.
 *
 * File format, version [VERSION] (JSON):
 *   {"v":1,"checked":N,"lastCheckedAt":ms,"dangerous":N,"caution":N,
 *    "events":[{"id":"…","t":ms,"s":"900","v":"dangerous","r":["…"],"h":["…"]}]}
 * Readers skip what they do not know: an unknown field is ignored, an event
 * with an unknown verdict or no id is dropped, a missing counter reads as 0.
 * A newer build may add fields; this one keeps working on its file.
 */
object SmsEvents {
    const val VERSION = 1
    const val DEFAULT_CAP = 200
    const val MAX_AGE_MS = 90L * 24 * 60 * 60 * 1000
    const val MAX_HOSTS = 5
    const val MAX_REASONS = 12
    /** Only these are ever written. A "no signals" message leaves nothing but the counter. */
    val VERDICTS = setOf(MessageVerdict.DANGEROUS.wire, MessageVerdict.CAUTION.wire)
    private val ID = Regex("^[0-9a-f]{16}$")

    /**
     * The record of a flagged message, or null for "no signals". The id
     * hashes what identifies the message — who sent it, the service centre's
     * timestamp, and what was found — so the same SMS delivered twice (the
     * telephony stack re-broadcasts unacknowledged messages after a reboot)
     * gets the same id and raises one alert, not two.
     */
    fun eventFor(sms: IncomingSms, analysis: MessageAnalysis, now: Long): SmsEvent? {
        if (analysis.verdict == MessageVerdict.NO_SIGNALS) return null
        val hosts = analysis.links.map { it.host }.distinct().take(MAX_HOSTS)
        val reasons = analysis.reasons.take(MAX_REASONS)
        return SmsEvent(
            id = eventId(sms.sender, sms.sentAtMs, analysis.verdict.wire, reasons, hosts),
            ts = now,
            sender = sms.sender,
            verdict = analysis.verdict.wire,
            reasons = reasons,
            hosts = hosts,
        )
    }

    fun eventId(sender: String?, sentAtMs: Long, verdict: String, reasons: List<String>, hosts: List<String>): String {
        val key = listOf("v1", sender.orEmpty(), sentAtMs.toString(), verdict, reasons.joinToString(","), hosts.joinToString(","))
            .joinToString("\u0000")
        return MessageDigest.getInstance("SHA-256").digest(key.toByteArray(Charsets.UTF_8))
            .take(8).joinToString("") { "%02x".format(it) }
    }

    /**
     * Count one checked message and, when it was flagged, add its event —
     * newest first, pruned to [maxAgeMs] and [cap]. The second value is false
     * when an event with that id is already there (a re-delivered SMS): then
     * nothing is added and no second alert may go out. The counter still
     * counts it: it was checked again.
     */
    fun record(
        log: SmsLog,
        now: Long,
        event: SmsEvent?,
        cap: Int = DEFAULT_CAP,
        maxAgeMs: Long = MAX_AGE_MS,
    ): Pair<SmsLog, Boolean> {
        val isNew = event != null && log.events.none { it.id == event.id }
        val events = if (isNew && event != null) listOf(event) + log.events else log.events
        val next = log.copy(
            checked = log.checked + 1,
            lastCheckedAt = now,
            dangerous = log.dangerous + if (isNew && event?.verdict == MessageVerdict.DANGEROUS.wire) 1 else 0,
            caution = log.caution + if (isNew && event?.verdict == MessageVerdict.CAUTION.wire) 1 else 0,
            events = prune(events, now, cap, maxAgeMs),
        )
        return next to isNew
    }

    /**
     * Events older than [maxAgeMs] go, then all past [cap]. An event stamped
     * in the future (the clock was stepped back since) is kept: dropping it
     * would lose a real warning over a clock.
     */
    fun prune(events: List<SmsEvent>, now: Long, cap: Int = DEFAULT_CAP, maxAgeMs: Long = MAX_AGE_MS): List<SmsEvent> =
        events.filter { now - it.ts < maxAgeMs }.take(cap.coerceAtLeast(0))

    /** A corrupt or unreadable file reads as empty: the next write starts it over. */
    fun parse(json: String?): SmsLog {
        if (json.isNullOrBlank()) return SmsLog.EMPTY
        return try {
            val o = JSONObject(json)
            SmsLog(
                checked = o.optLong("checked", 0L).coerceAtLeast(0L),
                lastCheckedAt = o.optLong("lastCheckedAt", 0L).coerceAtLeast(0L),
                dangerous = o.optLong("dangerous", 0L).coerceAtLeast(0L),
                caution = o.optLong("caution", 0L).coerceAtLeast(0L),
                events = parseEvents(o.optJSONArray("events")),
            )
        } catch (_: Exception) {
            SmsLog.EMPTY
        }
    }

    private fun parseEvents(arr: JSONArray?): List<SmsEvent> {
        if (arr == null) return emptyList()
        return (0 until arr.length()).mapNotNull { i ->
            val o = arr.optJSONObject(i) ?: return@mapNotNull null
            val id = o.opt("id") as? String ?: return@mapNotNull null
            val verdict = o.opt("v") as? String ?: return@mapNotNull null
            if (!ID.matches(id) || verdict !in VERDICTS) return@mapNotNull null
            SmsEvent(
                id = id,
                ts = o.optLong("t", 0L),
                sender = (o.opt("s") as? String)?.takeIf { it.isNotBlank() },
                verdict = verdict,
                reasons = strings(o.optJSONArray("r")).take(MAX_REASONS),
                hosts = strings(o.optJSONArray("h")).take(MAX_HOSTS),
            )
        }
    }

    private fun strings(arr: JSONArray?): List<String> {
        if (arr == null) return emptyList()
        return (0 until arr.length()).mapNotNull { i -> (arr.opt(i) as? String)?.takeIf { it.isNotBlank() } }
    }

    fun render(log: SmsLog): String {
        val events = JSONArray()
        log.events.forEach { e ->
            val o = JSONObject()
                .put("id", e.id)
                .put("t", e.ts)
                .put("v", e.verdict)
                .put("r", JSONArray(e.reasons))
                .put("h", JSONArray(e.hosts))
            if (e.sender != null) o.put("s", e.sender)
            events.put(o)
        }
        return JSONObject()
            .put("v", VERSION)
            .put("checked", log.checked)
            .put("lastCheckedAt", log.lastCheckedAt)
            .put("dangerous", log.dangerous)
            .put("caution", log.caution)
            .put("events", events)
            .toString()
    }
}

/**
 * What the automatic SMS check leaves behind: a counter for every checked
 * message, and for a flagged one only time, sender, verdict, reason codes
 * and link hosts. Never the text.
 *
 * Why a file and not SharedPreferences like BlockLog: the receiver runs in
 * the ":sms" process (see SmsReceiver) and the app reads from the main one.
 * SharedPreferences cache per process and lose writes across processes. So:
 *  - writes (the ":sms" process) happen under an exclusive FileLock on a
 *    side file plus a JVM lock (a FileLock is per process, and two channels
 *    in one process would throw), read-modify-write, then a temp file is
 *    fsynced and renamed over the log — a reader sees the old file or the new
 *    one, never half of either;
 *  - reads (the main process) take no lock and are never cached, so History
 *    shows an alert the moment it was written.
 *
 * It lives in filesDir/cleanway next to the blocklist: app-private, and
 * outside Android Auto Backup (the app's backup rules include only
 * SharedPreferences), so sender numbers never reach a cloud backup.
 */
class SmsEventLog(private val dir: File) {
    companion object {
        fun of(filesDir: File): SmsEventLog = SmsEventLog(BlocklistStore.dirFor(filesDir))

        /** All instances in one process share it: FileLock does not exclude threads of the same process. */
        private val processLock = Any()
    }

    private val file get() = File(dir, "sms-events.json")
    private val lockFile get() = File(dir, "sms-events.lock")

    fun read(now: Long = System.currentTimeMillis()): SmsLog {
        val log = SmsEvents.parse(readText())
        return log.copy(events = SmsEvents.prune(log.events, now))
    }

    /** Count one checked message and add [event] if new. Returns true when [event] was new. */
    fun record(now: Long, event: SmsEvent?): Boolean = locked {
        val (next, isNew) = SmsEvents.record(SmsEvents.parse(readText()), now, event)
        writeAtomic(SmsEvents.render(next))
        isNew
    }

    private fun readText(): String? = try {
        if (file.exists()) file.readText() else null
    } catch (_: Exception) {
        null
    }

    private fun <T> locked(block: () -> T): T = synchronized(processLock) {
        dir.mkdirs()
        RandomAccessFile(lockFile, "rw").use { raf ->
            val lock = raf.channel.lock()
            try {
                block()
            } finally {
                lock.release()
            }
        }
    }

    private fun writeAtomic(content: String) {
        val tmp = File(dir, file.name + ".tmp")
        FileOutputStream(tmp).use { out ->
            out.write(content.toByteArray(Charsets.UTF_8))
            out.fd.sync()
        }
        if (!tmp.renameTo(file)) {
            file.delete()
            tmp.renameTo(file)
        }
    }
}
