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
     * The shield's persisted block log, newest first: [{domain, ts, kind}].
     * kind is "blocked" (site never opened) or "warned" (verdict arrived after
     * the first lookup had been forwarded — future lookups blocked). Lets the
     * app count and list what the service did while no JS was alive.
     */
    Function("recentBlocks") { limit: Int ->
      ai.cleanway.app.BlockLog.recent(context, limit).map {
        mapOf("domain" to it.domain, "ts" to it.ts.toDouble(), "kind" to it.kind)
      }
    }

    /** How many block-log entries since [sinceMs] (epoch millis, Double for JS). */
    Function("blockCountSince") { sinceMs: Double ->
      ai.cleanway.app.BlockLog.countSince(context, sinceMs.toLong())
    }

    /**
     * Remember the app's chosen UI locale so native NOTIFICATIONS are shown in
     * it, not the phone's system language. Called from JS whenever the language
     * changes and at startup. See ai.cleanway.app.LocalizedContext.
     */
    Function("setNotificationLocale") { code: String ->
      ai.cleanway.app.LocalizedContext.set(context, code)
    }

    /**
     * Is Cleanway currently the default handler for web links (the browser
     * role)? When true, every tapped link routes through the link guard.
     */
    // RoleManager (and therefore any way to VERIFY we hold the browser role)
    // exists only on Android 10+. On 7-9 the link guard can still work if the
    // user picks Cleanway in the system "Open with" chooser, but we cannot
    // confirm it — and this app does not show protection it cannot verify.
    Function("isLinkHandlerSupported") {
      Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
    }

    Function("isDefaultLinkHandler") {
      if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return@Function false
      val rm = context.getSystemService(android.app.role.RoleManager::class.java)
      try {
        rm != null && rm.isRoleAvailable(android.app.role.RoleManager.ROLE_BROWSER) &&
          rm.isRoleHeld(android.app.role.RoleManager.ROLE_BROWSER)
      } catch (e: Exception) {
        false
      }
    }

    /**
     * Ask the system to make Cleanway the default link handler (browser role),
     * so every tapped link is checked. Shows the OS "make default" dialog on
     * Android 10+; older versions fall back to the default-apps settings.
     * Returns false if we could not present anything.
     */
    AsyncFunction("requestLinkHandler") { promise: Promise ->
      val activity = appContext.currentActivity
      if (activity == null) { promise.resolve(false); return@AsyncFunction }
      try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
          val rm = context.getSystemService(android.app.role.RoleManager::class.java)
          if (rm != null && rm.isRoleAvailable(android.app.role.RoleManager.ROLE_BROWSER) &&
              !rm.isRoleHeld(android.app.role.RoleManager.ROLE_BROWSER)) {
            activity.startActivityForResult(
              rm.createRequestRoleIntent(android.app.role.RoleManager.ROLE_BROWSER), 0x7A13
            )
            promise.resolve(true); return@AsyncFunction
          }
        }
        // Fallback: the "Default apps" settings, where the user picks the
        // browser app manually.
        activity.startActivity(
          Intent(android.provider.Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
        promise.resolve(true)
      } catch (e: Exception) {
        promise.resolve(false)
      }
    }

    /**
     * Open a URL in a real browser that is NOT Cleanway — used by the link-
     * guard screen's "Open anyway". Explicit package so it can never bounce
     * back into our own link guard. Returns false if no other browser exists.
     */
    Function("openInBrowser") { url: String ->
      try {
        val view = android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse(url))
          .addCategory(android.content.Intent.CATEGORY_BROWSABLE)
          .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
        val probe = android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse("http://example.com"))
          .addCategory(android.content.Intent.CATEGORY_BROWSABLE)
        val browser = context.packageManager.queryIntentActivities(probe, 0)
          .map { it.activityInfo.packageName }.firstOrNull { it != context.packageName }
        // No other browser: an implicit VIEW resolves straight back to
        // LinkGuardActivity when Cleanway holds the browser role, so "Open
        // anyway" bounced into our own guard while this reported success and
        // the screen closed. Report false and let the caller tell the user.
        if (browser == null) return@Function false
        view.setPackage(browser)
        context.startActivity(view)
        true
      } catch (e: Exception) {
        false
      }
    }

    /**
     * Lifetime totals per kind: {blocked, warned, allowed}. Counted outside
     * the trimmed ring buffer, so "Blocked N sites" keeps growing past 200 —
     * it is the honest number of times the shield acted, not a page of recent
     * history.
     */
    Function("blockLifetimeCounts") {
      ai.cleanway.app.BlockLog.lifetimeCounts(context).mapValues { it.value.toDouble() }
    }

    /** Sites the person marked "not a scam", newest first. */
    Function("allowedDomains") {
      ai.cleanway.app.UserAllow.list(context)
    }

    /** Mark a site as not-a-scam (idempotent). Returns false for a bad name. */
    Function("allowDomain") { domain: String ->
      val ok = ai.cleanway.app.UserAllow.add(context, domain)
      if (ok) {
        ai.cleanway.app.BlockLog.record(context, domain.lowercase(), System.currentTimeMillis(), ai.cleanway.app.BlockLog.KIND_ALLOWED)
        CleanwayVpnService.instance?.reloadAllowed()
      }
      ok
    }

    /** Undo an allow — the site can be blocked again. */
    Function("removeAllowedDomain") { domain: String ->
      ai.cleanway.app.UserAllow.remove(context, domain)
      CleanwayVpnService.instance?.reloadAllowed()
      Unit
    }

    /**
     * What blocklist the service has loaded and how fresh it is:
     * {version, count, revoked, ageMs, stale, hasCanary, lastError, lastFetchAt}.
     * Reads the service's static snapshot; when the service is not running the
     * list is by definition not filtering, so the app should not show it.
     */
    Function("blocklistStatus") {
      CleanwayVpnService.instance?.blocklistStatus()
        ?: mapOf("version" to 0.0, "count" to 0, "revoked" to false, "ageMs" to null,
                 "stale" to true, "hasCanary" to false, "lastError" to null, "lastFetchAt" to 0.0)
    }

    /** Fetch the blocklist now (background); no-op when the service is not running. */
    Function("refreshBlocklist") {
      CleanwayVpnService.instance?.refreshBlocklistAsync()
      Unit
    }

    /** Monotonic count of list-canary answers — proof the LOADED LIST is live. */
    Function("listCanaryAnswerCount") {
      CleanwayVpnService.listCanaryAnswerCount.toDouble()
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
            val kind = intent.getStringExtra(CleanwayVpnService.EXTRA_KIND) ?: ai.cleanway.app.BlockLog.KIND_BLOCKED
            sendEvent("onDomainBlocked", mapOf("domain" to domain, "ts" to ts, "kind" to kind))
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
