import Foundation

/// The server's switches for the on-phone checks — the Swift twin of
/// RemoteConfig.kt: the SMS text model off, or quieter thresholds. The app
/// stores the last answer of the update check in the app group
/// (`remote_config.json`, written by modules/cleanway-sms-filter); the filter
/// extension reads it for every message. A missing or malformed file means
/// `.default` — an outage cannot flip a switch. Overrides only RAISE the
/// shipped thresholds: the server can make the model quieter, never louder.
public struct RemoteConfig: Equatable {
    public var smsTextModelEnabled: Bool
    public var smsTextModelCautionThresholdOverride: Double?
    public var smsTextModelDangerThresholdOverride: Double?

    public init(smsTextModelEnabled: Bool = true, cautionOverride: Double? = nil, dangerOverride: Double? = nil) {
        self.smsTextModelEnabled = smsTextModelEnabled
        smsTextModelCautionThresholdOverride = cautionOverride
        smsTextModelDangerThresholdOverride = dangerOverride
    }

    public static let `default` = RemoteConfig()

    public static let kEnabled = "sms_text_model_enabled"
    public static let kCaution = "sms_text_model_caution_threshold_override"
    public static let kDanger = "sms_text_model_danger_threshold_override"

    public func cautionThreshold(_ shipped: Double) -> Double { Self.raiseOnly(shipped, smsTextModelCautionThresholdOverride) }
    public func dangerThreshold(_ shipped: Double) -> Double { Self.raiseOnly(shipped, smsTextModelDangerThresholdOverride) }

    /// The switches in `raw`, or nil when it is not a config at all (not JSON,
    /// not an object, no boolean enabled flag). A threshold that is not a
    /// number in (0, 1) is dropped on its own.
    public static func parse(_ raw: Data?) -> RemoteConfig? {
        guard let raw = raw, !raw.isEmpty,
              let o = (try? JSONSerialization.jsonObject(with: raw)) as? [String: Any],
              let enabled = strictBool(o[kEnabled]) else { return nil }
        return RemoteConfig(
            smsTextModelEnabled: enabled,
            cautionOverride: threshold(o[kCaution]),
            dangerOverride: threshold(o[kDanger])
        )
    }

    /// The stored form — the same snake_case keys the server sends.
    public func json() -> Data {
        func num(_ d: Double?) -> String { d.map { "\($0)" } ?? "null" }
        let s = "{\"\(Self.kEnabled)\":\(smsTextModelEnabled),\"\(Self.kCaution)\":\(num(smsTextModelCautionThresholdOverride)),\"\(Self.kDanger)\":\(num(smsTextModelDangerThresholdOverride))}"
        return Data(s.utf8)
    }

    static func threshold(_ v: Any?) -> Double? {
        guard let n = v as? NSNumber, strictBool(n) == nil else { return nil }
        let d = n.doubleValue
        return d.isFinite && d > 0 && d < 1 ? d : nil
    }

    /// JSON true/false, not 0/1: org.json's `as? Boolean` is as strict.
    private static func strictBool(_ v: Any?) -> Bool? {
        #if canImport(ObjectiveC)
        guard let n = v as? NSNumber, CFGetTypeID(n) == CFBooleanGetTypeID() else { return nil }
        return n.boolValue
        #else
        return v as? Bool
        #endif
    }

    private static func raiseOnly(_ shipped: Double, _ override: Double?) -> Double {
        if let o = override, o > shipped { return o }
        return shipped
    }
}
