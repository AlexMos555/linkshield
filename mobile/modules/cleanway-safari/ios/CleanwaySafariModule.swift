import AuthenticationServices
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
//
// Also the sign-in captcha's in-app web sheet (openAuthSession, below;
// src/services/captcha.ts): App Review 4.0 rejects a sign-in step that
// leaves the app for Safari.
public class CleanwaySafariModule: Module {
  private static let lastSeenKey = "safariExtensionLastSeenMs"

  // The one in-app sheet that may be up. The session must be held strongly or
  // it closes at once; the presenter too (the session keeps it weakly).
  private var authSession: ASWebAuthenticationSession?
  private var authSessionId = 0
  private let authPresenter = AuthSessionPresenter()

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

    // Opens an https page in an in-app sheet (ASWebAuthenticationSession) and
    // resolves the <callbackScheme>://… URL the page navigates to — the sheet
    // catches it, so the app's own deep-link route never fires. Null when the
    // person closes the sheet or it cannot start. One sheet at a time: a new
    // call cancels the previous one, which then resolves null.
    AsyncFunction("openAuthSession") { (url: String, callbackScheme: String, promise: Promise) in
      guard let start = URL(string: url), start.scheme?.lowercased() == "https", !callbackScheme.isEmpty else {
        promise.resolve(NSNull())
        return
      }
      self.authSession?.cancel()
      self.authSessionId += 1
      let id = self.authSessionId
      let once = ResolveOnce(promise)
      let session = ASWebAuthenticationSession(url: start, callbackURLScheme: callbackScheme) { callbackURL, _ in
        DispatchQueue.main.async {
          if self.authSessionId == id { self.authSession = nil }
          once.resolve(callbackURL?.absoluteString ?? NSNull())
        }
      }
      session.presentationContextProvider = self.authPresenter
      // No Safari cookies shared, and so no "wants to use … to Sign In" alert:
      // a captcha needs neither.
      session.prefersEphemeralWebBrowserSession = true
      self.authSession = session
      if !session.start() {
        self.authSession = nil
        once.resolve(NSNull())
      }
    }.runOnQueue(.main)

    // Dismisses the sheet (timeout, or the sign-in screen gave up); its
    // openAuthSession call resolves null.
    AsyncFunction("cancelAuthSession") {
      self.authSession?.cancel()
      self.authSession = nil
    }.runOnQueue(.main)
  }
}

/// Where the sheet appears: the app's key window.
private final class AuthSessionPresenter: NSObject, ASWebAuthenticationPresentationContextProviding {
  func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
    let windows = UIApplication.shared.connectedScenes
      .compactMap { $0 as? UIWindowScene }
      .flatMap { $0.windows }
    return windows.first(where: { $0.isKeyWindow }) ?? windows.first ?? ASPresentationAnchor()
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
