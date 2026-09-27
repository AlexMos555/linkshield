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

    /** What happened to the tunnel, as far as a stored pause is concerned. */
    enum class PauseEvent {
        /** The person tapped "Turn on" in the app. */
        STARTED_BY_PERSON,
        /** The system brought the service back: a killed process, a reboot, Always-on VPN. */
        CAME_BACK_BY_ITSELF,
        /** The person tapped "Turn off". */
        STOPPED_BY_PERSON,
        /** Another VPN took the tunnel, or VPN access was revoked in Settings. */
        TAKEN_AWAY,
    }

    /**
     * Pure: the stored pause after [event]. A pause outlives the service
     * coming back by itself, so a restart can neither cut it short nor let it
     * run past its time. Anything the person does — or the tunnel being taken
     * away — ends it: "Turn on" must mean on.
     */
    fun pauseAfter(event: PauseEvent, storedUntilMs: Long): Long =
        if (event == PauseEvent.CAME_BACK_BY_ITSELF) storedUntilMs else 0L

    /** What happened to the tunnel, as far as the recorded stop reason is concerned. */
    enum class TunnelEvent {
        /** The tunnel came up, whoever started it. */
        CAME_UP,
        /** The person tapped "Turn off". */
        STOPPED_BY_PERSON,
        /** Android took the tunnel away (onRevoke): VPN access withdrawn in Settings, or another VPN app. */
        TAKEN_AWAY,
        /** A start found no VPN permission (prepare() would have to ask). */
        NO_CONSENT,
        /** Strict Private DNS: the service would not start, or stepped aside. */
        PRIVATE_DNS,
    }

    /**
     * Pure: why the tunnel went down without the person turning it off, after
     * [event] — [CleanwayVpnService.REASON_REVOKED] or
     * [CleanwayVpnService.REASON_PRIVATE_DNS], null when nobody told us (a
     * killed process, a battery manager, a boot that did not bring it back).
     * The app says what happened and what it takes to come back; 1.0.2 said
     * "usually after a reboot, one tap" even after a Private DNS conflict or a
     * withdrawn VPN permission.
     *
     * A start without the permission means it was withdrawn only on a phone
     * where the tunnel has run before ([cameUpHere]). On a new phone restored
     * from a Google backup, "protection was on" comes back but the permission
     * does not: nothing was withdrawn there, and telling someone that a
     * permission on her phone was switched off is the kind of scare a scam
     * call feeds on. Then no cause is named.
     */
    fun stopReasonAfter(event: TunnelEvent, cameUpHere: Boolean): String? = when (event) {
        TunnelEvent.CAME_UP, TunnelEvent.STOPPED_BY_PERSON -> null
        TunnelEvent.TAKEN_AWAY -> CleanwayVpnService.REASON_REVOKED
        TunnelEvent.NO_CONSENT -> if (cameUpHere) CleanwayVpnService.REASON_REVOKED else null
        TunnelEvent.PRIVATE_DNS -> CleanwayVpnService.REASON_PRIVATE_DNS
    }

    /** Record [event] for [stopReason]. Kept outside the backed-up preferences: see [StopReasonStore]. */
    fun noteTunnel(context: Context, event: TunnelEvent) = stopReasons(context).note(event)

    /** The cause [stopReasonAfter] gave for the last stop, or null. */
    fun stopReason(context: Context): String? = stopReasons(context).reason()

    private fun stopReasons(context: Context) = StopReasonStore(context.applicationContext.noBackupFilesDir)

    private const val KEY_PAUSED_UNTIL = "paused_until_ms"
}
