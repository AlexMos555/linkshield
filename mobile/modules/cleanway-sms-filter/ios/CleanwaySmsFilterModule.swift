import ExpoModulesCore
import Foundation

// The app's side of the iPhone scam-text filter (docs/IOS.md §5). The filter
// is the CleanwaySmsFilter extension; the app can:
//   - leave the server's switches for it in the app group (the Android twin is
//     RemoteConfigStore in SharedPreferences): remote_config.json, the same
//     snake_case keys as the server and RemoteConfig.kt;
//   - say whether this build carries the extension at all;
//   - run the same engine on a pasted or shared message (the in-app "Check a
//     text message"), so iPhone gives the answer Android's MessageCheck gives.
// Apple gives an app no way to learn whether the person turned the filter on
// in Settings, and a filter extension cannot write anything back, so there is
// no "is it on" function here — on purpose.
public class CleanwaySmsFilterModule: Module {
  static let fileName = "remote_config.json"
  static let kEnabled = "sms_text_model_enabled"
  static let kCaution = "sms_text_model_caution_threshold_override"
  static let kDanger = "sms_text_model_danger_threshold_override"

  public func definition() -> ModuleDefinition {
    Name("CleanwaySmsFilter")

    /// True when the filter extension is embedded in this build (PlugIns/CleanwaySmsFilter.appex).
    Function("isInstalled") { () -> Bool in
      guard let plugIns = Bundle.main.builtInPlugInsURL else { return false }
      return FileManager.default.fileExists(atPath: plugIns.appendingPathComponent("CleanwaySmsFilter.appex").path)
    }

    /// The in-app message check: the filter's engine on one pasted or shared
    /// message, in memory, offline. Same wire shape as Android's
    /// MessageCheck.toWire(). There is no blocklist on an iPhone, so every link
    /// is "unknown" and `listAvailable` is false: the app then asks the server
    /// about the link hosts only, as it does for links the Android list lacks.
    /// The text is never logged, stored or sent.
    AsyncFunction("analyzeMessage") { (text: String) -> [String: Any] in
      guard let engine = Self.engine else {
        throw Exception(name: "E_MESSAGE_CHECK", description: "The message check is not in this build", code: "E_MESSAGE_CHECK")
      }
      let remote = SmsFilterEngine.remoteConfig(in: Self.container())
      return Self.wire(engine.analyze(text, sender: nil, remote: remote))
    }

    /// Store the server's switches for the filter. False, with the old ones kept,
    /// when `json` is not a config or the app group is unavailable.
    Function("setRemoteConfig") { (json: String) -> Bool in
      guard let normalized = Self.normalize(json), let dir = Self.container() else { return false }
      do {
        try normalized.write(to: dir.appendingPathComponent(Self.fileName), options: .atomic)
        return true
      } catch {
        return false
      }
    }
  }

  /// The engine with the shipped vocabulary, root zone and model (the
  /// CleanwayMessageEngineAssets bundle), loaded lazily by the engine itself.
  /// Nil when the bundle is missing: the check then reports itself unavailable
  /// instead of answering "no signals" from an empty vocabulary.
  static let engine: SmsFilterEngine? = {
    let candidates = [Bundle(for: CleanwaySmsFilterModule.self), Bundle.main]
    for base in candidates {
      if let url = base.url(forResource: "CleanwayMessageEngineAssets", withExtension: "bundle"),
         let bundle = Bundle(url: url),
         let assets = SmsFilterEngine.Assets.inBundle(bundle) {
        return SmsFilterEngine(assets: assets)
      }
    }
    return nil
  }()

  /// MessageAnalyzer.kt toWire() + MessageCheck.Result's list flags.
  static func wire(_ a: MessageAnalysis) -> [String: Any] {
    [
      "verdict": a.verdict.rawValue,
      "reasons": a.reasons,
      "links": a.links.map { link -> [String: Any] in
        [
          "text": link.text,
          "host": link.host,
          "status": link.status.rawValue,
          "shortener": link.shortener,
          "messenger": link.messenger,
        ]
      },
      "phones": a.phones,
      "legitShape": a.legitShape ?? NSNull(),
      "organisations": a.organisations,
      "truncated": a.truncated,
      "listAvailable": false,
      "listStale": false,
    ]
  }

  /// group.<bundle id>: the group the share extension and the filter also use.
  static func container() -> URL? {
    guard let id = Bundle.main.bundleIdentifier else { return nil }
    return FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.\(id)")
  }

  /// RemoteConfig.parse + toJson: an object with a boolean enabled flag; a
  /// threshold outside (0, 1) is dropped on its own. Nil when not a config.
  static func normalize(_ json: String) -> Data? {
    guard let data = json.data(using: .utf8),
          let o = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
          let enabled = o[kEnabled] as? NSNumber, CFGetTypeID(enabled) == CFBooleanGetTypeID() else { return nil }
    func threshold(_ v: Any?) -> String {
      guard let n = v as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else { return "null" }
      let d = n.doubleValue
      return d.isFinite && d > 0 && d < 1 ? "\(d)" : "null"
    }
    let out = "{\"\(kEnabled)\":\(enabled.boolValue),\"\(kCaution)\":\(threshold(o[kCaution])),\"\(kDanger)\":\(threshold(o[kDanger]))}"
    return out.data(using: .utf8)
  }
}
