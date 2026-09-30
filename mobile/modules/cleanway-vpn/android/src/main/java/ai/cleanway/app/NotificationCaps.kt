package ai.cleanway.app

/**
 * How often Cleanway may interrupt a person with an alert. Pure; JVM-tested
 * in NotificationCapsTest.
 *
 * The person this app is for swipes a third needless notification away
 * together with the one that mattered. So, for the SMS warnings (the rule
 * set of the elderly-first notification plan, 2026-09-29):
 *  - only "dangerous" pops up (LOUD: the high-importance channel, sound,
 *    heads-up), at most [MAX_LOUD_PER_HOUR] an hour;
 *  - "be careful" arrives quietly (QUIET: a low-importance channel, no
 *    sound, no pop-up);
 *  - at most [MAX_PER_DAY] warnings of either kind in 24 hours, and one per
 *    sender in [PER_SENDER_WINDOW_MS]: a scammer who sends five messages in
 *    a row is one warning, not five;
 *  - everything past those limits is FOLDED into one quiet, collapsed
 *    "more suspicious SMS" notification that only counts them.
 *
 * State is a list of what went out in the last 24 hours ([Shown]); the
 * caller keeps it (SmsEventLog does, on disk — the ":sms" process that
 * decides is short-lived). Nothing here reads the clock or the phone.
 *
 * One object on purpose: the site-block alerts (BlockNotifier) get their
 * own caps in a parallel change; when that lands, both should read their
 * limits from here.
 */
object NotificationCaps {
    const val MAX_LOUD_PER_HOUR = 3
    const val MAX_PER_DAY = 10
    const val PER_SENDER_WINDOW_MS = 6L * 60 * 60_000
    const val HOUR_MS = 60L * 60_000
    const val DAY_MS = 24L * HOUR_MS

    /** How a warning went out. The wire name is what SmsEventLog writes. */
    enum class Kind(val wire: String) {
        LOUD("loud"), QUIET("quiet"), FOLDED("folded");

        companion object {
            fun ofWire(wire: String?): Kind? = values().firstOrNull { it.wire == wire }
        }
    }

    /** One warning that went out: when, how, and to whom the message was attributed. */
    data class Shown(val ts: Long, val kind: Kind, val sender: String?)

    sealed class Decision {
        abstract val kind: Kind

        /** Pop up with sound: a dangerous message, within the limits. */
        object Loud : Decision() {
            override val kind get() = Kind.LOUD
        }

        /** Sit quietly in the shade: a "be careful" message, within the limits. */
        object Quiet : Decision() {
            override val kind get() = Kind.QUIET
        }

        /** Past a limit: the one collapsed notification, now counting [count] in the last 24 hours. */
        data class Folded(val count: Int) : Decision() {
            override val kind get() = Kind.FOLDED
        }
    }

    /**
     * What to do with one more flagged message, given what went out in the
     * last 24 hours ([shown], pruned or not). A warning stamped in the future
     * (the clock was set back since) still counts as recent: the cautious
     * reading, one warning fewer rather than one more.
     */
    fun decide(dangerous: Boolean, sender: String?, shown: List<Shown>, now: Long): Decision {
        val recent = prune(shown, now)
        val toldOfSender = sender != null && recent.any {
            it.kind != Kind.FOLDED && it.sender == sender && now - it.ts < PER_SENDER_WINDOW_MS
        }
        val today = recent.count { it.kind != Kind.FOLDED }
        val loudThisHour = recent.count { it.kind == Kind.LOUD && now - it.ts < HOUR_MS }
        val folded = recent.count { it.kind == Kind.FOLDED } + 1
        return when {
            toldOfSender || today >= MAX_PER_DAY -> Decision.Folded(folded)
            !dangerous -> Decision.Quiet
            loudThisHour >= MAX_LOUD_PER_HOUR -> Decision.Folded(folded)
            else -> Decision.Loud
        }
    }

    /** What still matters: the last 24 hours (a future-stamped entry stays, see [decide]). */
    fun prune(shown: List<Shown>, now: Long): List<Shown> = shown.filter { now - it.ts < DAY_MS }
}
