package ai.cleanway.app

import java.io.File

/**
 * The second PROCESS in SmsEventLogTest: on a phone the ":sms" receiver and
 * the app are separate processes, and a lock that only works inside one JVM
 * would pass every in-process test and still lose writes there.
 *
 * Args: <filesDir> <writer number> <records>. Signals "ready-N" in filesDir,
 * waits for "go", then records — so the writers really overlap.
 */
object SmsEventLogWriterMain {
    @JvmStatic
    fun main(args: Array<String>) {
        val filesDir = File(args[0])
        val writer = args[1].toInt()
        val records = args[2].toInt()
        File(filesDir, "ready-$writer").createNewFile()
        val go = File(filesDir, "go")
        val deadline = System.currentTimeMillis() + 30_000L
        while (!go.exists()) {
            check(System.currentTimeMillis() < deadline) { "no go signal" }
            Thread.sleep(5)
        }
        val store = SmsEventLog.of(filesDir)
        repeat(records) { i -> store.record(1_000L + i, eventFor(writer, i)) }
    }

    /** Every tenth record is a flagged message with an id unique to this writer. */
    fun eventFor(writer: Int, i: Int): SmsEvent? =
        if (i % 10 != 0) null
        else SmsEvent(
            id = "%016x".format(writer * 100_000L + i), ts = 1_000L + i, sender = "900", verdict = "dangerous",
            reasons = listOf("asks_for_code"), hosts = emptyList(),
        )
}
