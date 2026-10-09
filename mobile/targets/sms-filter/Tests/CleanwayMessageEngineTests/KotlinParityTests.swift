import Foundation
import XCTest
import CleanwayMessageEngine

/// The iPhone filter must say what Android says. Fixtures/kotlin_parity.json is
/// written by the Kotlin engine itself (MessageIosParityTest.kt) for every
/// corpus message — developer corpora, held-out and blind sets, the model's
/// parity texts, sender variants and Unicode edge cases — under three server
/// configs: the text model on, switched off, and with raised thresholds.
/// Every one of them must give the same verdict AND the same reasons here, in
/// the same order, plus the same links, phones, organisations and shape.
final class KotlinParityTests: XCTestCase {

    static let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    static let assetsDir = root.appendingPathComponent("../../../../modules/cleanway-vpn/android/src/main/assets").standardized

    static let assets = SmsFilterEngine.Assets(
        rules: assetsDir.appendingPathComponent("message_rules.json"),
        rootZone: assetsDir.appendingPathComponent("root_zone_tlds.txt"),
        modelJSON: assetsDir.appendingPathComponent("message_model.json"),
        modelWeights: assetsDir.appendingPathComponent("message_model.bin")
    )

    static let engine = SmsFilterEngine(assets: assets)

    struct Expected: Equatable, CustomStringConvertible {
        let verdict: String
        let reasons: [String]
        let shape: String?
        let organisations: [String]
        let phones: [String]
        let links: [[String]]
        let truncated: Bool

        init(_ a: [Any]) {
            verdict = a[0] as! String
            reasons = a[1] as! [String]
            shape = a[2] as? String
            organisations = a[3] as! [String]
            phones = a[4] as! [String]
            links = (a[5] as! [[Any]]).map { l in [l[0] as! String, l[1] as! String, "\(l[2] as! Bool)", "\(l[3] as! Bool)"] }
            truncated = a[6] as! Bool
        }

        init(_ r: MessageAnalysis) {
            verdict = r.verdict.rawValue
            reasons = r.reasons
            shape = r.legitShape
            organisations = r.organisations
            phones = r.phones
            links = r.links.map { [$0.host, $0.text, "\($0.shortener)", "\($0.messenger)"] }
            truncated = r.truncated
        }

        var description: String { "\(verdict) \(reasons) shape=\(shape ?? "-") orgs=\(organisations) phones=\(phones) links=\(links)" }
    }

    static func load(_ url: URL) throws -> [String: Any] {
        let data = try Data(contentsOf: url)
        return try JSONSerialization.jsonObject(with: data) as! [String: Any]
    }

    /// Replays one fixture; returns the number of (message, config) pairs compared.
    @discardableResult
    func replay(_ fixture: [String: Any], file: StaticString = #filePath, line: UInt = #line) -> Int {
        let raised = fixture["raised"] as! [String: Double]
        let configs: [(String, RemoteConfig)] = [
            ("on", .default),
            ("off", RemoteConfig(smsTextModelEnabled: false)),
            ("raised", RemoteConfig(smsTextModelEnabled: true, cautionOverride: raised["caution"], dangerOverride: raised["danger"])),
        ]
        let cases = fixture["cases"] as! [[String: Any]]
        var compared = 0
        var mismatches: [String] = []
        var worstP = 0.0
        var verdicts: [String: Int] = [:]
        let model = try! MessageModel(json: Data(contentsOf: Self.assets.modelJSON), weights: Data(contentsOf: Self.assets.modelWeights))
        for c in cases {
            let id = c["id"] as! String
            let text = c["text"] as! String
            let sender = c["sender"] as? String
            if let p = c["p"] as? Double {
                let mine = model.probability(text)
                worstP = max(worstP, abs(mine - p))
                if abs(mine - p) > 1e-9 { mismatches.append("\(id): p \(mine) vs Kotlin \(p)") }
            }
            let on = Expected(c["on"] as! [Any])
            for (key, remote) in configs {
                let expected = (c[key] as? [Any]).map(Expected.init) ?? on
                let got = Expected(Self.engine.analyze(text, sender: sender, remote: remote))
                compared += 1
                if key == "on" { verdicts[got.verdict, default: 0] += 1 }
                if got != expected {
                    mismatches.append("\(id) [\(key)]\n  kotlin: \(expected)\n  swift:  \(got)\n  text: \(text.prefix(200))")
                }
            }
        }
        print("PARITY \(cases.count) messages × 3 configs = \(compared) analyses; mismatches \(mismatches.count); max |p diff| \(worstP); verdicts (model on) \(verdicts.sorted { $0.key < $1.key })")
        for m in mismatches.prefix(40) { print("MISMATCH " + m) }
        XCTAssertEqual(mismatches.count, 0, "Swift and Kotlin disagree on \(mismatches.count) analyses (see MISMATCH lines)", file: file, line: line)
        return compared
    }

    func testEveryCorpusMessageMatchesKotlin() throws {
        let fixture = try Self.load(Self.root.appendingPathComponent("Fixtures/kotlin_parity.json"))
        let cases = fixture["cases"] as! [[String: Any]]
        XCTAssertGreaterThan(cases.count, 2000, "the fixture lost its corpora")
        replay(fixture)
    }

    /// An uncommitted fixture made with CLEANWAY_IOS_PARITY_EXTRA (e.g. ml/sms/data/train_*.tsv), when given.
    func testExtraFixtureMatchesKotlin() throws {
        guard let path = ProcessInfo.processInfo.environment["CLEANWAY_IOS_PARITY_EXTRA_FIXTURE"] ??
            ProcessInfo.processInfo.environment["SIMCTL_CHILD_CLEANWAY_IOS_PARITY_EXTRA_FIXTURE"] else {
            throw XCTSkip("no extra fixture")
        }
        replay(try Self.load(URL(fileURLWithPath: path)))
    }
}
