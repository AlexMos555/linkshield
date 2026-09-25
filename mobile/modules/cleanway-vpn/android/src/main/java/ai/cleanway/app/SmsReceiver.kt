package ai.cleanway.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The automatic SMS check: every incoming SMS is analysed on the phone the
 * moment it arrives, and a scam-looking one raises a warning.
 *
 * Only the RuStore build declares it (with RECEIVE_SMS), in the manifest
 * overlay app/src/rustore/AndroidManifest.xml written by
 * mobile/plugins/withRustoreVariant.js; the browser-downloaded APK compiles
 * the class and never declares it, so it can never run there. Declared
 * disabled: it runs only after the person turns the SMS check on in the app
 * (SmsShield.setEnabled flips the component; the permission stays granted).
 *
 * Process ":sms", not the main one. SMS_RECEIVED is an ordered foreground
 * broadcast with a 10 s budget that includes starting the process; the main
 * process is the React Native app (Firebase, ML Kit, Sentry — about 15 s on
 * a cold boot, exactly when queued messages are delivered). Here only
 * MainApplication.onCreate runs (SoLoader init, Expo's lifecycle listeners —
 * the ":boot" receiver has proven that start fast), the content providers
 * that start the crash and analytics SDKs never do, so message text cannot
 * end up in a crash report. What this process may touch is listed in
 * [SmsCheck].
 *
 * Privacy contract:
 *  - the text is analysed in memory and dropped: never sent, never written,
 *    never logged (not even "a message arrived"), never shown;
 *  - nothing leaves the phone at all — links are judged by the on-device
 *    list and the rules, no domain lookup;
 *  - a flagged message leaves time, sender, verdict, reason codes and link
 *    hosts (SmsEventLog); any other message only bumps a counter.
 */
class SmsReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        // The manifest filter and BROADCAST_SMS already see to it; a stray
        // explicit intent from our own process must not count as an SMS.
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return
        SmsCheck.submit(context.applicationContext, intent, goAsync())
    }
}

/**
 * Runs one SMS_RECEIVED off the main thread, inside the broadcast's budget.
 *
 * Budget: the broadcast must be finished within ~10 s of delivery, process
 * start included. The work is small — the first check in a fresh process
 * parses the ~2.6 MB list (100-300 ms), later ones take milliseconds — but a
 * phone waking from a long sleep can be slow, so a watchdog finishes the
 * broadcast at [BUDGET_MS] whatever happens; the check itself carries on.
 * One worker thread: messages that arrive together are checked in order,
 * and the list is parsed once.
 *
 * What the ":sms" process touches: the list on disk (read), the allow list
 * and the language choice (read, re-read if the app changed them), and
 * SmsEventLog (written — the only writer). Never BlockLog, never the block
 * notifier's throttle: those belong to the main process.
 */
internal object SmsCheck {
    private const val TAG = "CleanwaySms"
    /** Well inside the 10 s foreground-broadcast limit. */
    const val BUDGET_MS = 8_000L

    private val worker = Executors.newSingleThreadExecutor { r -> Thread(r, "Cleanway-Sms").apply { isDaemon = true } }
    private val watchdog = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "Cleanway-SmsBudget").apply { isDaemon = true }
    }

    fun submit(context: Context, intent: Intent, pending: BroadcastReceiver.PendingResult) {
        val done = AtomicBoolean(false)
        val finish = Runnable {
            if (done.compareAndSet(false, true)) {
                try {
                    pending.finish()
                } catch (e: Exception) {
                    Log.w(TAG, "finish_failed: ${e.javaClass.simpleName}")
                }
            }
        }
        try {
            val timer = watchdog.schedule(finish, BUDGET_MS, TimeUnit.MILLISECONDS)
            worker.execute {
                try {
                    handle(context, intent)
                } catch (e: Throwable) {
                    // Throwable: a pathological message must not crash the process
                    // (a regex can overflow the stack). The class name only.
                    Log.w(TAG, "sms_check_failed: ${e.javaClass.simpleName}")
                } finally {
                    timer.cancel(false)
                    finish.run()
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "sms_check_not_started: ${e.javaClass.simpleName}")
            finish.run()
        }
    }

    private fun handle(context: Context, intent: Intent) {
        val messages = IncomingSmsParts.group(IncomingSmsParts.fromIntent(intent))
        if (messages.isEmpty()) return
        val log = SmsEventLog.of(context.filesDir)
        for (sms in messages) {
            val analysis = MessageCheck.analyzeIncoming(context, sms.text, sms.sender)
            val now = System.currentTimeMillis()
            val event = SmsEvents.eventFor(sms, analysis, now)
            val isNew = try {
                log.record(now, event)
            } catch (e: Exception) {
                // Unrecorded is still worth a warning; History just cannot open it.
                Log.w(TAG, "sms_record_failed: ${e.javaClass.simpleName}")
                true
            }
            if (event != null && isNew) SmsNotifier.notify(context, event)
        }
    }
}
