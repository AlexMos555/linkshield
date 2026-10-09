import Foundation

/// What the Messages filter does with one SMS. Mirrors the two
/// ILMessageFilterAction values the extension uses (IdentityLookup is not
/// imported here, so the engine and its tests also build for macOS).
public enum FilterDecision: Equatable {
    /// Shown as usual.
    case none
    /// Moved to "Junk": no notification, links not tappable.
    case junk
}

/// The engine as the scam-text filter extension runs it: the shipped
/// vocabulary, root zone and text model, loaded once per extension process
/// and lazily (nothing is read until the first message), and the server's
/// switches read from the app group for every message.
///
/// Offline by construction: nothing here opens a connection, and the
/// extension's Info.plist declares no network URL, so iOS never sends the
/// message anywhere either. The text is analysed in memory and dropped.
public final class SmsFilterEngine {
    public struct Assets {
        public let rules: URL
        public let rootZone: URL
        public let modelJSON: URL
        public let modelWeights: URL

        public init(rules: URL, rootZone: URL, modelJSON: URL, modelWeights: URL) {
            self.rules = rules
            self.rootZone = rootZone
            self.modelJSON = modelJSON
            self.modelWeights = modelWeights
        }

        /// The four files as the Expo plugin copies them into a bundle.
        public static func inBundle(_ bundle: Bundle) -> Assets? {
            guard let rules = bundle.url(forResource: "message_rules", withExtension: "json"),
                  let root = bundle.url(forResource: "root_zone_tlds", withExtension: "txt"),
                  let json = bundle.url(forResource: "message_model", withExtension: "json"),
                  let bin = bundle.url(forResource: "message_model", withExtension: "bin") else { return nil }
            return Assets(rules: rules, rootZone: root, modelJSON: json, modelWeights: bin)
        }
    }

    /// The file in the app group where the app keeps the server's switches.
    public static let remoteConfigFile = "remote_config.json"

    private let assets: Assets
    private let lock = NSLock()
    private var rules: MessageRules?
    private var modelLoaded = false
    private var model: MessageModel?

    public init(assets: Assets) { self.assets = assets }

    /// Dangerous → Junk. Caution and no signals → shown as usual (docs/IOS.md §5:
    /// a caution is a partial combination, and Junk hides a message with no
    /// way to see why — a real bank or delivery text there costs more than a
    /// borderline scam left in the inbox).
    public static func decision(for verdict: MessageVerdict) -> FilterDecision {
        verdict == .dangerous ? .junk : .none
    }

    /// The analysis of one incoming message. Never throws: without its assets
    /// the engine knows no words and lets everything through.
    public func analyze(_ text: String, sender: String?, remote: RemoteConfig) -> MessageAnalysis {
        let (rules, model) = load(withModel: remote.smsTextModelEnabled)
        return MessageAnalyzer(rules: rules, model: model, remote: remote).analyze(text, sender: sender)
    }

    public func decide(_ text: String, sender: String?, remote: RemoteConfig) -> FilterDecision {
        Self.decision(for: analyze(text, sender: sender, remote: remote).verdict)
    }

    /// The switches the app stored in the app group container, or `.default`.
    public static func remoteConfig(in container: URL?) -> RemoteConfig {
        guard let url = container?.appendingPathComponent(remoteConfigFile),
              let data = try? Data(contentsOf: url) else { return .default }
        return RemoteConfig.parse(data) ?? .default
    }

    private func load(withModel: Bool) -> (MessageRules, MessageModel?) {
        lock.lock()
        defer { lock.unlock() }
        if rules == nil {
            if let json = try? Data(contentsOf: assets.rules),
               let parsed = try? MessageRules.parse(json, rootZoneText: try? Data(contentsOf: assets.rootZone)) {
                rules = parsed
            } else {
                rules = MessageRules.empty()
            }
        }
        // With the model off it is not even read — as on Android.
        if withModel && !modelLoaded {
            modelLoaded = true
            if let json = try? Data(contentsOf: assets.modelJSON),
               let bin = try? Data(contentsOf: assets.modelWeights, options: .alwaysMapped) {
                model = try? MessageModel(json: json, weights: bin)
            }
        }
        return (rules!, withModel ? model : nil)
    }
}
