package ai.cleanway.app

import java.io.File
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The automatic SMS check's only memory. Written by the ":sms" process, read
 * by the app — so the format must survive another build reading it, a
 * crash mid-write, a corrupt file and two writers at once; and it must keep
 * nothing but what the privacy contract allows.
 */
class SmsEventLogTest {
    private val dirs = mutableListOf<File>()

    private fun tempDir(): File = Files.createTempDirectory("cleanway-sms").toFile().also { dirs += it }

    @After
    fun cleanUp() {
        dirs.forEach { it.deleteRecursively() }
    }

    private val day = 24L * 60 * 60 * 1000

    private fun event(id: String, ts: Long, verdict: String = "dangerous") = SmsEvent(
        id = id, ts = ts, sender = "900", verdict = verdict,
        reasons = listOf("claims_organisation", "call_unknown_number"), hosts = listOf("gosuslugi-help.ru"),
    )

    private fun id(n: Int) = "%016x".format(n)

    // ── record (pure) ───────────────────────────────────────────────────

    @Test
    fun `a benign message only moves the counter`() {
        val (log, isNew) = SmsEvents.record(SmsLog.EMPTY, now = 1_000L, event = null)
        assertFalse(isNew)
        assertEquals(1L, log.checked)
        assertEquals(1_000L, log.lastCheckedAt)
        assertEquals(0L, log.flagged)
        assertTrue(log.events.isEmpty())
    }

    @Test
    fun `a flagged message is added newest first and counted by verdict`() {
        var log = SmsLog.EMPTY
        log = SmsEvents.record(log, 1_000L, event(id(1), 1_000L, "caution")).first
        log = SmsEvents.record(log, 2_000L, event(id(2), 2_000L, "dangerous")).first
        assertEquals(listOf(id(2), id(1)), log.events.map { it.id })
        assertEquals(1L, log.dangerous)
        assertEquals(1L, log.caution)
        assertEquals(2L, log.checked)
    }

    @Test
    fun `the same message delivered twice is one event and one alert`() {
        val first = SmsEvents.record(SmsLog.EMPTY, 1_000L, event(id(7), 1_000L))
        val second = SmsEvents.record(first.first, 5_000L, event(id(7), 5_000L))
        assertTrue(first.second)
        assertFalse(second.second)
        assertEquals(1, second.first.events.size)
        assertEquals(1L, second.first.dangerous)
        // It was checked twice, and the counter says so.
        assertEquals(2L, second.first.checked)
    }

    @Test
    fun `the list is capped, the lifetime counters are not`() {
        var log = SmsLog.EMPTY
        for (i in 1..5) log = SmsEvents.record(log, i * 1_000L, event(id(i), i * 1_000L), cap = 3).first
        assertEquals(listOf(id(5), id(4), id(3)), log.events.map { it.id })
        assertEquals(5L, log.dangerous)
    }

    @Test
    fun `events older than 90 days fall off, a future-stamped one stays`() {
        val now = 200 * day
        val events = listOf(event(id(1), now + day), event(id(2), now - 10 * day), event(id(3), now - 91 * day))
        assertEquals(listOf(id(1), id(2)), SmsEvents.prune(events, now).map { it.id })
    }

    // ── the event itself ────────────────────────────────────────────────

    @Test
    fun `no signals leaves no event, a flagged message keeps only what the contract allows`() {
        val analyzer = MessageTestSupport.analyzer(MessageTestSupport.list("gosuslugi-help.ru"))
        val clean = IncomingSms("Tele2", "Ваш баланс 120 руб.", 1L)
        assertNull(SmsEvents.eventFor(clean, analyzer.analyze(clean.text, clean.sender), 10L))

        val scam = IncomingSms("900", "Госуслуги: ваш аккаунт взломан. Срочно войдите: https://gosuslugi-help.ru/login?id=42", 1L)
        val e = requireNotNull(SmsEvents.eventFor(scam, analyzer.analyze(scam.text, scam.sender), 10L))
        assertEquals("dangerous", e.verdict)
        assertEquals(listOf("gosuslugi-help.ru"), e.hosts)
        assertTrue(e.reasons.contains(MessageAnalyzer.R_LINK_BLOCKLISTED))
        // Host only: the path and query of the link are not kept.
        assertFalse(SmsEvents.render(SmsEvents.record(SmsLog.EMPTY, 10L, e).first).contains("login"))
        assertFalse(SmsEvents.render(SmsEvents.record(SmsLog.EMPTY, 10L, e).first).contains("взломан"))
    }

    @Test
    fun `the id is stable for one message and differs between messages`() {
        val a = SmsEvents.eventId("900", 1_000L, "dangerous", listOf("x"), listOf("a.ru"))
        assertEquals(a, SmsEvents.eventId("900", 1_000L, "dangerous", listOf("x"), listOf("a.ru")))
        assertNotEquals(a, SmsEvents.eventId("900", 2_000L, "dangerous", listOf("x"), listOf("a.ru")))
        assertNotEquals(a, SmsEvents.eventId("901", 1_000L, "dangerous", listOf("x"), listOf("a.ru")))
        assertTrue(Regex("^[0-9a-f]{16}$").matches(a))
    }

    // ── format ──────────────────────────────────────────────────────────

    @Test
    fun `render and parse round-trip`() {
        val log = SmsEvents.record(SmsLog.EMPTY, 42L, event(id(9), 42L)).first
        assertEquals(log, SmsEvents.parse(SmsEvents.render(log)))
    }

    @Test
    fun `a corrupt file reads as empty`() {
        assertEquals(SmsLog.EMPTY, SmsEvents.parse("{\"checked\": 3, \"events\": [trunc"))
        assertEquals(SmsLog.EMPTY, SmsEvents.parse("[]"))
        assertEquals(SmsLog.EMPTY, SmsEvents.parse(""))
        assertEquals(SmsLog.EMPTY, SmsEvents.parse(null))
    }

    @Test
    fun `a file from another build keeps what this one understands`() {
        // Missing counters and fields, an unknown field, an unknown verdict,
        // a bad id, a number where a string belongs, a negative counter.
        val json = """
            {"v":7,"checked":-4,"newField":{"x":1},"events":[
              {"id":"00000000000000aa","t":5,"v":"dangerous","r":["asks_for_code",42,null],"h":["a.ru"],"extra":true},
              {"id":"00000000000000bb","t":4,"v":"no_signals"},
              {"id":"not-hex","t":3,"v":"caution"},
              {"id":"00000000000000cc","v":"caution","s":null},
              {"id":12,"v":"caution"}
            ]}
        """.trimIndent()
        val log = SmsEvents.parse(json)
        assertEquals(0L, log.checked)
        assertEquals(0L, log.lastCheckedAt)
        assertEquals(listOf("00000000000000aa", "00000000000000cc"), log.events.map { it.id })
        assertEquals(listOf("asks_for_code"), log.events[0].reasons)
        assertNull(log.events[1].sender)
        assertEquals(emptyList<String>(), log.events[1].hosts)
    }

    @Test
    fun `version 1 field names are pinned`() {
        val log = SmsLog(checked = 3, lastCheckedAt = 9, dangerous = 1, caution = 0, events = listOf(event(id(1), 9)))
        val o = JSONObject(SmsEvents.render(log))
        assertEquals(1, o.getInt("v"))
        assertEquals(setOf("v", "checked", "lastCheckedAt", "dangerous", "caution", "events"), o.keySet())
        val e = o.getJSONArray("events").getJSONObject(0)
        assertEquals(setOf("id", "t", "s", "v", "r", "h"), e.keySet())
        assertEquals("0000000000000001", e.getString("id"))
        assertEquals("900", e.getString("s"))
        // An event without a sender writes no "s" rather than a null.
        val anonymous = JSONObject(SmsEvents.render(log.copy(events = listOf(event(id(2), 9).copy(sender = null)))))
        assertFalse(anonymous.getJSONArray("events").getJSONObject(0).has("s"))
    }

    // ── the store ───────────────────────────────────────────────────────

    @Test
    fun `the store records and reads back, and leaves no temp file`() {
        val filesDir = tempDir()
        val store = SmsEventLog.of(filesDir)
        assertTrue(store.record(1_000L, event(id(1), 1_000L)))
        assertFalse(store.record(2_000L, event(id(1), 2_000L)))
        store.record(3_000L, null)
        val log = store.read(now = 3_000L)
        assertEquals(3L, log.checked)
        assertEquals(listOf(id(1)), log.events.map { it.id })
        val dir = BlocklistStore.dirFor(filesDir)
        assertEquals(setOf("sms-events.json", "sms-events.lock"), dir.list()?.toSet())
    }

    @Test
    fun `a corrupt file is started over on the next write`() {
        val filesDir = tempDir()
        val dir = BlocklistStore.dirFor(filesDir).apply { mkdirs() }
        File(dir, "sms-events.json").writeText("\u0000\u0000garbage{")
        val store = SmsEventLog.of(filesDir)
        assertEquals(SmsLog.EMPTY, store.read())
        assertTrue(store.record(10L, event(id(3), 10L)))
        assertEquals(1L, store.read(now = 10L).checked)
    }

    @Test
    fun `reading hides events past 90 days without writing`() {
        val filesDir = tempDir()
        val store = SmsEventLog.of(filesDir)
        store.record(1_000L, event(id(1), 1_000L))
        assertEquals(0, store.read(now = 1_000L + 91 * day).events.size)
        assertEquals(1, SmsEvents.parse(File(BlocklistStore.dirFor(filesDir), "sms-events.json").readText()).events.size)
    }

    @Test
    fun `concurrent writers lose no update`() {
        val filesDir = tempDir()
        val writers = 8
        val each = 40
        val pool = Executors.newFixedThreadPool(writers)
        val start = CountDownLatch(1)
        repeat(writers) { w ->
            pool.execute {
                // A fresh instance per writer, as two processes would have.
                val store = SmsEventLog.of(filesDir)
                start.await()
                repeat(each) { i -> store.record(1_000L + i, if (i % 10 == 0) event(id(w * 1000 + i), 1_000L + i) else null) }
            }
        }
        start.countDown()
        pool.shutdown()
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS))
        val log = SmsEventLog.of(filesDir).read(now = 2_000L)
        assertEquals((writers * each).toLong(), log.checked)
        assertEquals((writers * each / 10).toLong(), log.dangerous)
        assertEquals(writers * each / 10, log.events.size)
    }

    /**
     * The real layout: the ":sms" process writes while another process does
     * too. Two child JVMs and this one hammer the same file; FileLock is what
     * has to hold here — the in-process lock cannot see across processes.
     */
    @Test
    fun `writers in separate processes lose no update`() {
        val filesDir = tempDir()
        val records = 60
        val children = 2
        val java = File(System.getProperty("java.home"), "bin/java").path
        val classpath = (
            System.getProperty("java.class.path").orEmpty().split(File.pathSeparator) +
                listOf(SmsEventLogWriterMain::class.java, SmsEventLog::class.java, JSONObject::class.java, Unit::class.java)
                    .mapNotNull { it.protectionDomain?.codeSource?.location?.toURI()?.let(::File)?.path }
            ).filter { it.isNotEmpty() }.distinct().joinToString(File.pathSeparator)
        val procs = (1..children).map { w ->
            ProcessBuilder(java, "-cp", classpath, SmsEventLogWriterMain::class.java.name, filesDir.path, "$w", "$records")
                .redirectErrorStream(true)
                .start()
        }
        try {
            val deadline = System.currentTimeMillis() + 30_000L
            while ((1..children).any { !File(filesDir, "ready-$it").exists() }) {
                assertTrue("child processes did not start", System.currentTimeMillis() < deadline)
                Thread.sleep(5)
            }
            File(filesDir, "go").createNewFile()
            val store = SmsEventLog.of(filesDir)
            repeat(records) { i -> store.record(1_000L + i, SmsEventLogWriterMain.eventFor(0, i)) }
            for (p in procs) {
                assertTrue("a writer hung", p.waitFor(60, TimeUnit.SECONDS))
                assertEquals(p.inputStream.bufferedReader().readText(), 0, p.exitValue())
            }
        } finally {
            procs.forEach { it.destroyForcibly() }
        }
        val log = SmsEventLog.of(filesDir).read(now = 2_000L)
        val writers = children + 1
        assertEquals((writers * records).toLong(), log.checked)
        assertEquals((writers * records / 10).toLong(), log.dangerous)
        assertEquals(writers * records / 10, log.events.map { it.id }.toSet().size)
    }
}
