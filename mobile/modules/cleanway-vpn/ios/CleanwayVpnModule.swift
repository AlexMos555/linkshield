import ExpoModulesCore
import NetworkExtension

// The iOS half of the cleanway-vpn module. The JS API (modules/cleanway-vpn/index.ts)
// is shared with Android, where it drives a local DNS-filter VPN; every
// Android-only function is optional in JS and simply absent here, so the app
// treats it as "not on this platform".
//
// iOS does NOT get a VPN (App Review 5.4 restricts VPN apps to Organization
// accounts). Its protection layers (docs/MOBILE_AUTO_PROTECTION.md, docs/IOS.md)
// report their status to the home screen through src/utils/platform-features.ts:
//   - DNS protection: NEDNSSettingsManager — the functions below;
//   - scam-text filter: an ILMessageFilterExtension target;
//   - Safari Web Extension target.
// The VPN calls are honest no-ops: never "running".
public class CleanwayVpnModule: Module {
  private var dnsObserver: NSObjectProtocol?

  public func definition() -> ModuleDefinition {
    Name("CleanwayVpn")

    Events("onDomainBlocked", "onDnsSettingsChanged")

    AsyncFunction("startVpn") { () -> Bool in
      return false
    }

    AsyncFunction("stopVpn") { () in
    }

    Function("isRunning") { () -> Bool in
      return false
    }

    // ── DNS protection (docs/IOS.md §4) ────────────────────────────────
    // Every call answers with a report, never a rejection: the screen needs
    // the state the phone is in after a failure as much as the failure.

    /** Reads the saved configuration: is ours there, and has the person turned it on in Settings? */
    AsyncFunction("dnsSettingsStatus") { (promise: Promise) in
      CleanwayDnsSettings.status { promise.resolve($0) }
    }

    /** Saves Cleanway's encrypted-DNS configuration. iOS leaves it off until the person picks it in Settings. */
    AsyncFunction("installDnsSettings") { (promise: Promise) in
      CleanwayDnsSettings.install { promise.resolve($0) }
    }

    /** Removes the configuration from iOS (Settings → … → DNS no longer lists Cleanway). */
    AsyncFunction("removeDnsSettings") { (promise: Promise) in
      CleanwayDnsSettings.remove { promise.resolve($0) }
    }

    // The person turns the configuration on or off in Settings while the app
    // is in the background; iOS posts this when it changes. The screen also
    // re-reads on every foreground, so this is the fast path, not the only one.
    OnStartObserving {
      guard self.dnsObserver == nil else { return }
      self.dnsObserver = NotificationCenter.default.addObserver(
        forName: .NEDNSSettingsConfigurationDidChange, object: nil, queue: .main
      ) { [weak self] _ in
        self?.sendEvent("onDnsSettingsChanged", [:])
      }
    }

    OnStopObserving {
      if let observer = self.dnsObserver {
        NotificationCenter.default.removeObserver(observer)
        self.dnsObserver = nil
      }
    }
  }
}

/// System-wide encrypted DNS through NEDNSSettingsManager (iOS 14+), pointed
/// at Cleanway's DNS-over-HTTPS gateway (api/routers/doh.py).
///
/// Decisions (docs/IOS.md §4 has the sources):
///  • No server IP addresses. With none, iOS resolves the URL's host itself
///    (Apple's DNSSettings payload reference, ServerURL). dns.cleanway.ai is a
///    CNAME to Railway's edge, whose addresses are Railway's to change: pinned
///    IPs would one day point at someone else and break every lookup.
///  • No on-demand rules. Without them the setting applies on every network,
///    which is the point of it. Captive-network (hotel / café Wi-Fi) login is
///    exempted by iOS itself (WWDC20 "Enable encrypted DNS"); a "disconnect on
///    Wi-Fi/cellular" rule would only switch protection off where it matters.
///  • Failover allowed (iOS 26+): if the gateway cannot answer, iOS may fall
///    back to the network's own resolver instead of failing every lookup — the
///    gateway's own policy (fail open: a missed block is better than a phone
///    with no internet). Below iOS 26 there is no such switch; the setup sheet
///    says how to turn it off if sites stop opening.
enum CleanwayDnsSettings {
  static let serverURL = "https://dns.cleanway.ai/dns-query"
  static let displayName = "Cleanway"

  typealias Report = [String: Any]

  static func status(_ done: @escaping (Report) -> Void) {
    let manager = NEDNSSettingsManager.shared()
    manager.loadFromPreferences { error in
      done(report(manager, error: error, step: "load"))
    }
  }

  static func install(_ done: @escaping (Report) -> Void) {
    let manager = NEDNSSettingsManager.shared()
    // Load first: saving over a stale copy fails with configurationStale.
    manager.loadFromPreferences { loadError in
      if let loadError = loadError {
        done(report(manager, error: loadError, step: "load"))
        return
      }
      guard let url = URL(string: serverURL) else {
        done(report(manager, error: nil, step: "save", fallback: "invalid"))
        return
      }
      let settings = NEDNSOverHTTPSSettings(servers: [])
      settings.serverURL = url
      #if compiler(>=6.2) // Xcode 26 SDK; older SDKs (an older EAS image) build without it.
      if #available(iOS 26.0, *) {
        settings.allowFailover = true
      }
      #endif
      manager.dnsSettings = settings
      manager.localizedDescription = displayName
      manager.onDemandRules = nil
      manager.saveToPreferences { saveError in
        if let saveError = saveError {
          done(report(manager, error: saveError, step: "save"))
          return
        }
        // Re-read what iOS kept, so the answer is the system's, not ours.
        manager.loadFromPreferences { reloadError in
          done(report(manager, error: reloadError, step: "load"))
        }
      }
    }
  }

  static func remove(_ done: @escaping (Report) -> Void) {
    let manager = NEDNSSettingsManager.shared()
    manager.loadFromPreferences { loadError in
      if let loadError = loadError {
        done(report(manager, error: loadError, step: "load"))
        return
      }
      guard manager.dnsSettings != nil else {
        done(report(manager, error: nil, step: "remove"))
        return
      }
      manager.removeFromPreferences { removeError in
        if let removeError = removeError {
          done(report(manager, error: removeError, step: "remove"))
          return
        }
        // removeFromPreferences leaves the old values on the object until
        // the next load (Apple's docs) — load so the report says "gone".
        manager.loadFromPreferences { reloadError in
          done(report(manager, error: reloadError, step: "load"))
        }
      }
    }
  }

  /// The shape src/IosDnsSettings.ts parses. `installed`: a configuration of
  /// this app is saved; `current`: it is ours and points at today's gateway;
  /// `enabled`: the person picked it in Settings (iOS's isEnabled — the app
  /// cannot set it).
  private static func report(
    _ manager: NEDNSSettingsManager, error: Error?, step: String, fallback: String? = nil
  ) -> Report {
    let doh = manager.dnsSettings as? NEDNSOverHTTPSSettings
    var out: Report = [
      "installed": manager.dnsSettings != nil,
      "current": doh?.serverURL?.absoluteString == serverURL,
      "enabled": manager.isEnabled,
      "step": step,
    ]
    if let error = error {
      let ns = error as NSError
      out["error"] = errorCode(ns)
      out["message"] = "\(ns.domain) \(ns.code): \(ns.localizedDescription)"
    } else if let fallback = fallback {
      out["error"] = fallback
    }
    return out
  }

  private static func errorCode(_ error: NSError) -> String {
    if error.domain == NEDNSSettingsErrorDomain,
       let code = NEDNSSettingsManagerError(rawValue: error.code) {
      switch code {
      case .configurationInvalid: return "invalid"
      case .configurationDisabled: return "disabled"
      case .configurationStale: return "stale"
      case .configurationCannotBeRemoved: return "cannot_remove"
      @unknown default: return "failed"
      }
    }
    // A build without the Network Extensions (dns-settings) entitlement is
    // refused by the system; the exact domain/code is not documented, so the
    // raw message travels along for the log.
    return "failed"
  }
}
