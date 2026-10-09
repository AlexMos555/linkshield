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

    // { bundled, stateKnown, enabled, lastSeenMs }
    AsyncFunction("getStatus") { (promise: Promise) in
      var result: [String: Any] = [
        "bundled": self.extensionId != nil,
        "stateKnown": false,
        "enabled": false,
        "lastSeenMs": self.lastSeenMs ?? NSNull(),
      ]
      guard let id = self.extensionId else {
        promise.resolve(result)
        return
      }
      // SFSafariExtensionManager is in the iOS 26.2 SDK (Xcode 26.2, Swift
      // 6.2.3). An older Xcode still builds the app; the card then relies on
      // lastSeenMs alone.
      #if compiler(>=6.2.3)
      if #available(iOS 26.2, *) {
        SFSafariExtensionManager.getStateOfExtension(withIdentifier: id) { state, error in
          if let state, error == nil {
            result["stateKnown"] = true
            result["enabled"] = state.isEnabled
          }
          promise.resolve(result)
        }
        return
      }
      #endif
      promise.resolve(result)
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
        SFSafariSettings.openExtensionsSettings(forIdentifiers: [id]) { error in
          promise.resolve(error == nil)
        }
        return
      }
      #endif
      promise.resolve(false)
    }.runOnQueue(.main)
  }
}
