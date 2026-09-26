package ai.cleanway.app

import android.content.Context

/**
 * Remembers whether the user turned protection on.
 *
 * Without this the shield is single-session: a reboot, or an OEM battery
 * manager force-stopping the app (Samsung "Put app to sleep", MIUI autostart,
 * Oppo/realme), leaves the user unprotected with no signal — the persistent
 * notification is gone and nothing re-arms. For someone who was set up once by
 * a relative that is the difference between a product and a demo.
 *
 * The flag records intent, not state: it is set when the user enables the
 * shield and cleared only when they turn it off themselves. A tunnel that the
 * system tore down still has intent=true, which is exactly what lets us bring
 * it back.
 *
 * Read from two processes: the main (React Native) one writes it, and the
 * lightweight ":boot" process reads it after a reboot. Each process opens the
 * file itself, and the boot process is always freshly started, so it sees the
 * committed value without any cross-process cache concern.
 */
internal object ShieldPreference {

    private const val PREFS = "cleanway_shield"
    private const val KEY_ENABLED = "user_enabled"

    fun setUserEnabled(context: Context, enabled: Boolean) {
        context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_ENABLED, enabled)
            // commit(): the writing process may be killed right after (an OEM
            // force-stop, or the user toggling then swiping the app away), and a
            // lost write means protection silently does not come back.
            .commit()
    }

    fun isUserEnabled(context: Context): Boolean =
        context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_ENABLED, false)

    /**
     * End of a timed pause (epoch ms), 0 when not paused. Stored so a pause
     * ends at its time even if the service restarts in between — and never
     * turns into "paused until the next reboot".
     */
    fun setPausedUntil(context: Context, untilMs: Long) {
        context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putLong(KEY_PAUSED_UNTIL, untilMs)
            .commit()
    }

    fun pausedUntil(context: Context): Long =
        context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getLong(KEY_PAUSED_UNTIL, 0L)

    private const val KEY_PAUSED_UNTIL = "paused_until_ms"
}
