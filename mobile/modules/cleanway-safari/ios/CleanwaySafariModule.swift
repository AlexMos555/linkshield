import ExpoModulesCore
import SafariServices
import UIKit

// The Safari Web Extension's status for the "Protection on iPhone" card
// (src/hooks/useSafariExtension.ts, docs/IOS.md §2.5).
//
// Two facts, each honest about what iOS lets an app know:
//   • enabled — is the extension switched on in Safari's settings? Only
//     iOS 26.2+ answers (SFSafariExtensionManager); older iOS gives nil.
//   • lastSeenMs — when the extension last ran on a real web page. Its
//     native half (SafariWebExtensionHandler, mobile/plugins/
//     withSafariExtension.js) writes it into the app group. That is the
//     only proof that "Allow on all websites" was granted too.
//
// The bundle id of the extension and the app group come from the app's
// Info.plist (written by the same plugin), so nothing here is hard-coded.
public class CleanwaySafariModule: Module {
  private static let lastSeenKey = "safariExtensionLastSeenMs"

  private var extensionId: String? {
    Bundle.main.object(forInfoDictionaryKey: "CleanwaySafariExtensionBundleId") as? String
  }

  private var lastSeenMs: Double? {
    guard let group = Bundle.main.object(forInfoDictionaryKey: "CleanwayAppGroup") as? String,
          let defaults = UserDefaults(suiteName: group) else { return nil }
    let value = defaults.double(forKey: Self.lastSeenKey)
    return value > 0 ? value : nil
  }

  public func definition() -> ModuleDefinition {
    Name("CleanwaySafari")

    // { bundled, stateKnown, enabled, lastSeenMs, settingsApi }
    AsyncFunction("getStatus") { (promise: Promise) in
      let base: [String: Any] = [
        "bundled": self.extensionId != nil,
        "stateKnown": false,
        "enabled": false,
        "lastSeenMs": self.lastSeenMs ?? NSNull(),
        "settingsApi": false,
      ]
      guard let id = self.extensionId else {
        promise.resolve(base)
        return
      }
      // SFSafariExtensionManager is in the iOS 26.2 SDK (Xcode 26.2, Swift
      // 6.2.3). An older Xcode still builds the app; the card then relies on
      // lastSeenMs alone.
      #if compiler(>=6.2.3)
      if #available(iOS 26.2, *) {
        // Answer once: with iOS's state, or without it after 3 s — a call
        // iOS never completes must not leave the card waiting.
        var withApi = base
        withApi["settingsApi"] = true // SFSafariSettings can open the extension's page
        let once = ResolveOnce(promise)
        DispatchQueue.global().asyncAfter(deadline: .now() + 3) { once.resolve(withApi) }
        SFSafariExtensionManager.getStateOfExtension(withIdentifier: id) { state, error in
          var result = withApi
          if let state, error == nil {
            result["stateKnown"] = true
            result["enabled"] = state.isEnabled
          }
          once.resolve(result)
        }
        return
      }
      #endif
      promise.resolve(base)
    }

    // Opens Settings → Apps → Safari → Extensions → Cleanway (iOS 26.2+).
    // False where iOS has no such call; the card shows the steps instead.
    AsyncFunction("openSettings") { (promise: Promise) in
      guard let id = self.extensionId else {
        promise.resolve(false)
        return
      }
      #if compiler(>=6.2.3)
      if #available(iOS 26.2, *) {
        let once = ResolveOnce(promise)
        DispatchQueue.global().asyncAfter(deadline: .now() + 5) { once.resolve(false) }
        SFSafariSettings.openExtensionsSettings(forIdentifiers: [id]) { error in
          once.resolve(error == nil)
        }
        return
      }
      #endif
      promise.resolve(false)
    }.runOnQueue(.main)
  }
}

/// Resolves a promise the first time only (a reply racing a timeout).
private final class ResolveOnce {
  private let lock = NSLock()
  private var promise: Promise?

  init(_ promise: Promise) { self.promise = promise }

  func resolve(_ value: Any) {
    lock.lock()
    let p = promise
    promise = nil
    lock.unlock()
    p?.resolve(value)
  }
}
