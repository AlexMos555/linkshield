import Foundation
import IdentityLookup

/// The iPhone's scam-text filter: iOS hands it each SMS/MMS from an unknown
/// sender (never iMessage, never a contact), it answers Junk or nothing.
///
/// OFFLINE ONLY. The verdict comes from the on-device engine (the Swift twin
/// of the Android message check, same vocabulary and model). This class never
/// calls `context.deferQueryRequestToNetwork`, and the Info.plist names no
/// ILMessageFilterExtensionNetworkURL, so iOS has nowhere to send a message:
/// its text never leaves the phone. Nothing is logged or stored — Apple does
/// not even let a filter extension write to the shared container.
///
/// Mapping (docs/IOS.md §5): dangerous → .junk; caution and no signals → .none.
/// Junk has no sub-actions (iOS 16+ sub-actions belong to .transaction and
/// .promotion, which would mislabel a scam as a bill or an offer).
final class MessageFilterExtension: ILMessageFilterExtension {
    /// One engine per extension process: the vocabulary and model load on the first message only.
    static let engine: SmsFilterEngine? = SmsFilterEngine.Assets.inBundle(Bundle(for: MessageFilterExtension.self))
        .map { SmsFilterEngine(assets: $0) }

    /// The app group the app writes the server's switches to (set by the Expo plugin).
    static let container: URL? = (Bundle(for: MessageFilterExtension.self).object(forInfoDictionaryKey: "CleanwayAppGroup") as? String)
        .flatMap { FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: $0) }
}

extension MessageFilterExtension: ILMessageFilterQueryHandling {
    func handle(
        _ queryRequest: ILMessageFilterQueryRequest,
        context: ILMessageFilterExtensionContext,
        completion: @escaping (ILMessageFilterQueryResponse) -> Void
    ) {
        let response = ILMessageFilterQueryResponse()
        response.action = Self.action(body: queryRequest.messageBody, sender: queryRequest.sender)
        completion(response)
    }

    static func action(body: String?, sender: String?) -> ILMessageFilterAction {
        guard let body = body, !body.isEmpty, let engine = engine else { return .none }
        // Read for every message: a switch the server flipped applies to the next one.
        let remote = SmsFilterEngine.remoteConfig(in: container)
        switch engine.decide(body, sender: sender, remote: remote) {
        case .junk: return .junk
        case .none: return .none
        }
    }
}
