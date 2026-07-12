package expo.modules.cleanwayvpn

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import androidx.core.content.ContextCompat
import ai.cleanway.app.CleanwayVpnService
import expo.modules.kotlin.Promise
import expo.modules.kotlin.exception.Exceptions
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

// Arbitrary request code for the system VPN-consent dialog.
private const val VPN_CONSENT_REQUEST = 0x7A11

/**
 * JS <-> native bridge for Cleanway's local DNS-filtering VPN (Android).
 * Wraps the hardened CleanwayVpnService: startVpn (consent then start), stopVpn,
 * isRunning (real service state), and forwards ACTION_DOMAIN_BLOCKED to JS as an event.
 * iOS has a separate no-op module (Organization Apple account gates the NE VPN there).
 */
class CleanwayVpnModule : Module() {
  private val context: Context
    get() = appContext.reactContext ?: throw Exceptions.ReactContextLost()

  private var pendingStart: Promise? = null
  private var blockReceiver: BroadcastReceiver? = null

  override fun definition() = ModuleDefinition {
    Name("CleanwayVpn")

    Events("onDomainBlocked")

    AsyncFunction("startVpn") { promise: Promise ->
      if (pendingStart != null) {
        // A consent dialog from a previous startVpn() is still up; don't stack a second one.
        promise.reject("E_CONSENT_IN_PROGRESS", "A VPN consent request is already in progress", null)
        return@AsyncFunction
      }
      // prepare() returns a consent Intent the first time (or after revoke); null = allowed.
      val consent = VpnService.prepare(context)
      if (consent != null) {
        val activity: Activity = appContext.currentActivity
          ?: run {
            promise.reject("E_NO_ACTIVITY", "No foreground activity to request VPN consent", null)
            return@AsyncFunction
          }
        pendingStart = promise
        activity.startActivityForResult(consent, VPN_CONSENT_REQUEST)
      } else {
        startService()
        promise.resolve(true)
      }
    }

    AsyncFunction("stopVpn") {
      val intent = Intent(context, CleanwayVpnService::class.java).apply {
        action = CleanwayVpnService.ACTION_STOP
      }
      context.startService(intent)
      // startService returns ComponentName?; a non-Promise AsyncFunction resolves with the
      // lambda's last value, and ComponentName has no JS converter → the promise would REJECT.
      // Return Unit so stopVpn() resolves void (matches TS Promise<void> + iOS/web stubs).
      Unit
    }

    Function("isRunning") {
      CleanwayVpnService.isRunning
    }

    OnActivityResult { _, payload ->
      if (payload.requestCode == VPN_CONSENT_REQUEST) {
        val promise = pendingStart
        pendingStart = null
        if (payload.resultCode == Activity.RESULT_OK) {
          startService()
          promise?.resolve(true)
        } else {
          promise?.resolve(false)
        }
      }
    }

    OnStartObserving { registerBlockReceiver() }
    OnStopObserving { unregisterBlockReceiver() }
    OnDestroy {
      unregisterBlockReceiver()
      pendingStart?.reject("E_MODULE_DESTROYED", "VPN module destroyed before consent completed", null)
      pendingStart = null
    }
  }

  private fun startService() {
    ContextCompat.startForegroundService(context, Intent(context, CleanwayVpnService::class.java))
  }

  private fun registerBlockReceiver() {
    if (blockReceiver != null) return
    val receiver = object : BroadcastReceiver() {
      override fun onReceive(ctx: Context?, intent: Intent?) {
        val domain = intent?.getStringExtra(CleanwayVpnService.EXTRA_DOMAIN) ?: return
        val ts = intent.getLongExtra(CleanwayVpnService.EXTRA_TIMESTAMP, 0L)
        sendEvent("onDomainBlocked", mapOf("domain" to domain, "ts" to ts))
      }
    }
    val filter = IntentFilter(CleanwayVpnService.ACTION_DOMAIN_BLOCKED)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
      context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
    } else {
      @Suppress("UnspecifiedRegisterReceiverFlag")
      context.registerReceiver(receiver, filter)
    }
    blockReceiver = receiver
  }

  private fun unregisterBlockReceiver() {
    blockReceiver?.let {
      try { context.unregisterReceiver(it) } catch (_: Exception) {}
    }
    blockReceiver = null
  }
}
