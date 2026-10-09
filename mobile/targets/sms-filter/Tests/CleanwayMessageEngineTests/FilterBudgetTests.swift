import Foundation
import XCTest
import CleanwayMessageEngine
#if canImport(Darwin)
import Darwin
#endif

/// What the filter extension costs: memory after loading everything and
/// checking every corpus message, and the time per message. A message filter
/// extension runs under a small, undocumented memory limit (single-digit MB of
/// its own on some iOS versions), so the engine loads lazily and keeps the
/// model's weights memory-mapped. Prints the numbers; fails only well above
/// what the engine needs, so a regression (a Float copy of the weights, a
/// cache that grows per message) is caught.
final class FilterBudgetTests: XCTestCase {

    /// phys_footprint — what iOS counts against an extension's memory limit.
    static func footprint() -> Int {
        #if canImport(Darwin)
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count) }
        }
        return kr == KERN_SUCCESS ? Int(info.phys_footprint) : 0
        #else
        return 0
        #endif
    }

    func testMemoryAndSpeed() throws {
        let fixture = try KotlinParityTests.load(KotlinParityTests.root.appendingPathComponent("Fixtures/kotlin_parity.json"))
        let texts = (fixture["cases"] as! [[String: Any]]).map { ($0["text"] as! String, $0["sender"] as? String) }
        let before = Self.footprint()
        let engine = SmsFilterEngine(assets: KotlinParityTests.assets)
        let t0 = Date()
        _ = engine.decide("Привет! Как дела?", sender: nil, remote: .default)
        let firstMs = Date().timeIntervalSince(t0) * 1000
        let afterLoad = Self.footprint()
        var junk = 0
        var worstMs = 0.0
        let t1 = Date()
        for (text, sender) in texts {
            let s = Date()
            if engine.decide(text, sender: sender, remote: .default) == .junk { junk += 1 }
            worstMs = max(worstMs, Date().timeIntervalSince(s) * 1000)
        }
        let perMessageMs = Date().timeIntervalSince(t1) * 1000 / Double(texts.count)
        let afterAll = Self.footprint()
        let mb = { (b: Int) in String(format: "%.1f MB", Double(b) / 1_048_576) }
        print("BUDGET first message (load + check): \(String(format: "%.0f", firstMs)) ms; " +
              "per message: \(String(format: "%.2f", perMessageMs)) ms avg, \(String(format: "%.0f", worstMs)) ms worst over \(texts.count); " +
              "footprint: \(mb(before)) before, +\(mb(afterLoad - before)) loaded, +\(mb(afterAll - before)) after all; junk \(junk)")
        if before > 0 {
            XCTAssertLessThan(afterAll - before, 24 * 1_048_576, "the engine's own footprint grew past 24 MB")
        }
    }

    func testVerdictMapping() {
        XCTAssertEqual(SmsFilterEngine.decision(for: .dangerous), .junk)
        XCTAssertEqual(SmsFilterEngine.decision(for: .caution), .none)
        XCTAssertEqual(SmsFilterEngine.decision(for: .noSignals), .none)
    }

    func testRemoteConfigFromTheAppGroup() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("cw-remote-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        // Nothing stored, or no container at all: the shipped defaults.
        XCTAssertEqual(SmsFilterEngine.remoteConfig(in: dir), .default)
        XCTAssertEqual(SmsFilterEngine.remoteConfig(in: nil), .default)
        let file = dir.appendingPathComponent(SmsFilterEngine.remoteConfigFile)
        // What the app writes (RemoteConfig.kt's toJson shape).
        try Data(#"{"sms_text_model_enabled":false,"sms_text_model_caution_threshold_override":null,"sms_text_model_danger_threshold_override":0.95}"#.utf8).write(to: file)
        XCTAssertEqual(SmsFilterEngine.remoteConfig(in: dir), RemoteConfig(smsTextModelEnabled: false, dangerOverride: 0.95))
        // Malformed, or not a config: the defaults, never "off".
        for bad in ["", "nope", "[]", #"{"sms_text_model_enabled":"false"}"#, #"{"sms_text_model_enabled":0}"#] {
            try Data(bad.utf8).write(to: file)
            XCTAssertEqual(SmsFilterEngine.remoteConfig(in: dir), .default, bad)
        }
        // Thresholds outside (0, 1) are dropped on their own; overrides only raise.
        try Data(#"{"sms_text_model_enabled":true,"sms_text_model_caution_threshold_override":1.5,"sms_text_model_danger_threshold_override":0.5}"#.utf8).write(to: file)
        let c = SmsFilterEngine.remoteConfig(in: dir)
        XCTAssertNil(c.smsTextModelCautionThresholdOverride)
        XCTAssertEqual(c.dangerThreshold(0.8), 0.8)
        XCTAssertEqual(RemoteConfig(dangerOverride: 0.95).dangerThreshold(0.8), 0.95)
        // The round trip the app's writer relies on.
        let rc = RemoteConfig(smsTextModelEnabled: false, cautionOverride: 0.97, dangerOverride: nil)
        XCTAssertEqual(RemoteConfig.parse(rc.json()), rc)
    }

    func testKillSwitchRunsTheRulesAlone() {
        let engine = SmsFilterEngine(assets: KotlinParityTests.assets)
        // Scores high on the model and no rule fires on it alone.
        let text = "vash akkaunt vzloman, srochno pozvonite +79161234567 dlya otmeny"
        XCTAssertEqual(engine.analyze(text, sender: nil, remote: .default).verdict, .dangerous)
        XCTAssertEqual(engine.analyze(text, sender: nil, remote: RemoteConfig(smsTextModelEnabled: false)).verdict, .caution)
        XCTAssertEqual(engine.decide(text, sender: nil, remote: RemoteConfig(smsTextModelEnabled: false)), .none)
    }

    func testMissingAssetsLetEverythingThrough() {
        let nowhere = URL(fileURLWithPath: "/nonexistent")
        let engine = SmsFilterEngine(assets: .init(rules: nowhere, rootZone: nowhere, modelJSON: nowhere, modelWeights: nowhere))
        XCTAssertEqual(engine.decide("Госуслуги: аккаунт взломан, срочно позвоните +7 916 482-15-37", sender: nil, remote: .default), .none)
    }
}
