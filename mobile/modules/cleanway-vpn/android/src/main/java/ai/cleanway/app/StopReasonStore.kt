package ai.cleanway.app

import android.util.Log
import java.io.File

/**
 * Where [ShieldPreference.stopReasonAfter]'s answer is kept, next to the one
 * fact it needs: has the tunnel ever come up on this install.
 *
 * Both live in [dir] — the app's noBackupFilesDir, which Android's backup and
 * device-to-device transfer never copy (like InstallId), and which goes with
 * the app. The first version kept the reason in the backed-up preferences: a
 * phone restored from Google backup then named a cause from the old phone,
 * one that never happened on this one.
 *
 * Written only in the main process (the service and the module); also read
 * by BootReceiver in the ":boot" process, which never writes it.
 */
internal class StopReasonStore(private val dir: File) {

    private val reasonFile get() = File(dir, "cleanway_stop_reason")
    private val cameUpFile get() = File(dir, "cleanway_tunnel_came_up")

    fun note(event: ShieldPreference.TunnelEvent) {
        try {
            if (event == ShieldPreference.TunnelEvent.CAME_UP) cameUpFile.createNewFile()
            val reason = ShieldPreference.stopReasonAfter(event, cameUpHere = cameUpFile.exists())
            if (reason == null) reasonFile.delete() else reasonFile.writeText(reason)
        } catch (e: Exception) {
            // Best effort: only the wording of the "stopped" screen depends on it.
            Log.w(TAG, "stop_reason_write_failed: ${e.javaClass.simpleName}")
        }
    }

    fun reason(): String? = try {
        reasonFile.takeIf { it.isFile }?.readText()?.trim()?.ifEmpty { null }
    } catch (_: Exception) {
        null
    }

    private companion object {
        const val TAG = "CleanwayVPN"
    }
}
