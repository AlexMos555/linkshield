import ExpoModulesCore
import Foundation

// The app's side of the iPhone scam-text filter (docs/IOS.md §4). The filter
// is the CleanwaySmsFilter extension; the app can only:
//   - leave the server's switches for it in the app group (the Android twin is
//     RemoteConfigStore in SharedPreferences): remote_config.json, the same
//     snake_case keys as the server and RemoteConfig.kt;
//   - say whether this build carries the extension at all.
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
