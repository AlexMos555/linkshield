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

    Events("onDomainBlocked", "onVpnStopped")

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

    /**
     * Open Settings → VPN, where the user can switch on "Always-on VPN".
     *
     * The shield does come back by itself after a reboot (BootReceiver +
     * prepare()-before-establish in the service). Always-on is still worth
     * offering: the system starts it with the phone, before BOOT_COMPLETED
     * reaches any app — a gap of seconds to minutes during which nothing is
     * filtered — and it is not subject to background-start restrictions.
     */
    Function("openVpnSettings") {
      val intent = Intent("android.net.vpn.SETTINGS").apply {
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
      }
      try {
        context.startActivity(intent)
        true
      } catch (e: Exception) {
        try {
          context.startActivity(
            Intent(android.provider.Settings.ACTION_VPN_SETTINGS)
              .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
          )
          true
        } catch (e2: Exception) {
          false
        }
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

    /**
     * Whether the user last chose to have the shield ON. Combined with
     * isRunning() this lets the app tell "never set up" apart from "was on,
     * and something turned it off" — a reboot without always-on, an OEM
     * battery manager, a force-stop. The second case deserves "turn it back
     * on" in one tap, not the first-run "let's set up your protection".
     */
    Function("wasUserEnabled") {
      ai.cleanway.app.ShieldPreference.isUserEnabled(context)
    }

    /**
     * Hostname of the device's strict Private DNS provider, or null when the
     * setting is Off/Automatic. Strict + our tunnel = no DNS for any app, so
     * the app must not even try to start the shield while this is non-null.
     * See ai.cleanway.app.PrivateDnsGuard.
     */
    Function("privateDnsStrictHost") {
      ai.cleanway.app.PrivateDnsGuard.strictHostname(context)
    }

    /**
     * Open the screen where Private DNS lives. Android has no public intent
     * for the Private DNS dialog itself; "Network & internet" is the closest
     * public entry point on every version since 9.
     */
    Function("openPrivateDnsSettings") {
      val candidates = listOf(
        "android.settings.PRIVATE_DNS_SETTINGS",           // some OEM builds expose it
        android.provider.Settings.ACTION_WIRELESS_SETTINGS,
        android.provider.Settings.ACTION_SETTINGS,
      )
      candidates.any { action ->
        try {
          context.startActivity(Intent(action).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
          true
        } catch (e: Exception) {
          false
        }
      }
    }

    /**
     * Monotonic count of canary queries the service has answered. The app
     * reads it before and after triggering a lookup — a delta is proof the
     * query reached THIS tunnel and was filtered. Double because JS has no
     * 64-bit integer; probe counts stay far below 2^53.
     */
    Function("canaryAnswerCount") {
      CleanwayVpnService.canaryAnswerCount.toDouble()
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
        when (intent?.action) {
          CleanwayVpnService.ACTION_VPN_STOPPED -> {
            // The tunnel went away without the user asking. The UI must stop
            // claiming protection immediately, not on the next foreground.
            val reason = intent.getStringExtra(CleanwayVpnService.EXTRA_REASON) ?: "unknown"
            sendEvent("onVpnStopped", mapOf("reason" to reason))
          }
          CleanwayVpnService.ACTION_DOMAIN_BLOCKED -> {
            val domain = intent.getStringExtra(CleanwayVpnService.EXTRA_DOMAIN) ?: return
            val ts = intent.getLongExtra(CleanwayVpnService.EXTRA_TIMESTAMP, 0L)
            sendEvent("onDomainBlocked", mapOf("domain" to domain, "ts" to ts))
          }
        }
      }
    }
    val filter = IntentFilter(CleanwayVpnService.ACTION_DOMAIN_BLOCKED).apply {
      addAction(CleanwayVpnService.ACTION_VPN_STOPPED)
    }
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
