import Foundation

/// The vocabulary of the message check, parsed from message_rules.json — the
/// SAME asset the Android build ships (the Expo plugin copies it from
/// mobile/modules/cleanway-vpn/android/src/main/assets). Data only: which
/// combinations raise a warning is decided in MessageAnalyzer.
public final class MessageRules {
    /// Kind of body a message claims to come from; decides which rules apply.
    enum Kind: String { case gov = "GOV", security = "SECURITY", bank = "BANK", `operator` = "OPERATOR", delivery = "DELIVERY", messenger = "MESSENGER", company = "COMPANY", service = "SERVICE" }

    struct Organisation {
        let id: U16
        let kind: Kind
        let names: [Phrase]
        let domains: Set<U16>
        let domainTokens: Set<U16>
        let phones: Set<U16>
        let senders: Set<U16>
        let catchAll: Bool
    }

    let groups: [String: [Phrase]]
    let organisations: [Organisation]
    let negators: Set<U16>
    let intermediates: Set<U16>
    let shorteners: Set<U16>
    let messengers: Set<U16>
    let trustedDomains: Set<U16>
    let bareTlds: Set<U16>
    let userContentHosts: Set<U16>
    let appStores: Set<U16>
    let translitMarkers: Set<U16>

    /// Every official number of every organisation.
    let officialPhones: Set<U16>
    /// Every official domain, plus the trusted ones.
    let officialDomains: Set<U16>

    init(groups: [String: [Phrase]], organisations: [Organisation], negators: Set<U16>, intermediates: Set<U16>,
         shorteners: Set<U16>, messengers: Set<U16>, trustedDomains: Set<U16>, bareTlds: Set<U16>,
         userContentHosts: Set<U16>, appStores: Set<U16>, translitMarkers: Set<U16>) {
        self.groups = groups
        self.organisations = organisations
        self.negators = negators
        self.intermediates = intermediates
        self.shorteners = shorteners
        self.messengers = messengers
        self.trustedDomains = trustedDomains
        self.bareTlds = bareTlds
        self.userContentHosts = userContentHosts
        self.appStores = appStores
        self.translitMarkers = translitMarkers
        officialPhones = Set(organisations.flatMap { $0.phones })
        officialDomains = Set(organisations.flatMap { $0.domains }).union(trustedDomains)
    }

    func group(_ name: String) -> [Phrase] { groups[name] ?? [] }

    /// Belongs to a known organisation or a trusted body, and is not an upload host (NOT a safety verdict).
    func isOfficial(_ host: U16) -> Bool {
        HostNames.under(host, officialDomains) && !HostNames.under(host, userContentHosts)
    }

    /// No vocabulary at all: links are still found.
    public static func empty() -> MessageRules {
        MessageRules(groups: [:], organisations: [], negators: [], intermediates: [], shorteners: [], messengers: [],
                     trustedDomains: [], bareTlds: [], userContentHosts: [], appStores: [], translitMarkers: [])
    }

    public struct ParseError: Error {}

    /// Parse the asset; throws on malformed JSON. `rootZone` is RootZone.parse of root_zone_tlds.txt.
    public static func parse(_ json: Data, rootZoneText: Data?) throws -> MessageRules {
        let rootZone = rootZoneText.map { RootZone.parse(u(String(decoding: $0, as: UTF8.self))) } ?? []
        return try parse(json, rootZone: rootZone)
    }

    static func parse(_ json: Data, rootZone: Set<U16>) throws -> MessageRules {
        guard let root = try JSONSerialization.jsonObject(with: json) as? [String: Any] else { throw ParseError() }
        var groups: [String: [Phrase]] = [:]
        for (key, value) in (root["groups"] as? [String: Any]) ?? [:] {
            groups[key] = phrases(value as? [Any])
        }
        let orgs = (root["organisations"] as? [Any]) ?? []
        return MessageRules(
            groups: groups,
            organisations: orgs.compactMap { organisation($0 as? [String: Any]) },
            negators: words(root["negators"]),
            intermediates: words(root["intermediates"]),
            shorteners: hosts(root["shorteners"]),
            messengers: hosts(root["messengers"]),
            trustedDomains: hosts(root["trusted_domains"]),
            bareTlds: words(root["bare_tlds"]).union(words(root["country_tlds"])).union(rootZone),
            userContentHosts: hosts(root["user_content_hosts"]),
            appStores: hosts(root["app_stores"]),
            translitMarkers: words(root["translit_markers"])
        )
    }

    private static func organisation(_ o: [String: Any]?) -> Organisation? {
        guard let o = o else { return nil }
        guard let id = o["id"] as? String, !id.isEmpty else { return nil }
        guard let kind = Kind(rawValue: ((o["kind"] as? String) ?? "").uppercased()) else { return nil }
        return Organisation(
            id: u(id),
            kind: kind,
            names: phrases(o["names"] as? [Any]),
            domains: hosts(o["domains"]),
            domainTokens: Set(strings(o["domain_tokens"]).map(MessageText.normalizeWord)),
            phones: Set(strings(o["phones"]).compactMap(PhoneExtractor.normalize)),
            senders: Set(strings(o["senders"]).map(jLowercase)),
            catchAll: (o["catch_all"] as? Bool) ?? false
        )
    }

    /// org.json's optString over an array, blanks dropped.
    private static func strings(_ arr: Any?) -> [U16] {
        guard let arr = arr as? [Any] else { return [] }
        return arr.map { v -> U16 in
            if let s = v as? String { return u(s) }
            if v is NSNull { return u("null") }
            return u("\(v)")
        }.filter { s in s.contains { !JChar.isWhitespace($0) } }
    }

    private static func phrases(_ arr: [Any]?) -> [Phrase] { strings(arr).compactMap(Phrase.parse) }

    private static func words(_ arr: Any?) -> Set<U16> { Set(strings(arr).map { MessageText.normalizeWord(jTrim($0)) }) }

    private static func hosts(_ arr: Any?) -> Set<U16> { Set(strings(arr).compactMap { HostNames.normalize($0) }) }

    // Group names the analyzer reads. A missing group degrades to "never matches".
    static let THREAT = "threat"
    static let URGENCY = "urgency"
    static let CONFIRM_DATA = "confirm_data"
    static let BAIT = "bait"
    static let CALL = "call"
    static let CODE_VERB = "code_verb"
    static let CODE_DICTATE = "code_dictate"
    static let CODE_WORD = "code_word"
    static let CODE_TARGET = "code_target"
    static let CALL_CONTEXT = "call_context"
    static let PICKUP_CONTEXT = "pickup_context"
    static let FLASH_CALL = "flash_call"
    static let MONEY_VERB = "money_verb"
    static let MONEY_INFINITIVE = "money_infinitive"
    static let DIRECTIVE = "directive"
    static let MONEY_REQUEST = "money_request"
    static let SAFE_ACCOUNT = "safe_account"
    static let PAY_VERB = "pay_verb"
    static let FEE_WORD = "fee_word"
    static let INSTALL = "install"
    static let MALWARE_LURE = "malware_lure"
    static let KIN = "kin"
    static let NEW_NUMBER = "new_number"
    static let EMERGENCY = "emergency"
    static let SECRECY = "secrecy"
    static let AWARENESS = "awareness"
    static let CODE_LABEL = "code_label"
    static let CODE_DISCLAIMER = "code_disclaimer"
    static let PAYMENT_OP = "payment_op"
    static let BALANCE_WORD = "balance_word"
    static let CURRENCY = "currency"
    static let PICKUP = "pickup"
    static let PUBLIC_ALERT = "public_alert"
    static let SMS_COMMAND = "sms_command"
    static let PAYOUT = "payout"
    static let CODE_INCOMING = "code_incoming"
    static let CODE_PRONOUN = "code_pronoun"
    static let CODE_EXCEPT = "code_except"
    static let CODE_HOUSEHOLD = "code_household"
    static let SCAM_LABEL = "scam_label"
    static let OBEY = "obey"
    static let CALL_COMING = "call_coming"
    static let CODE_INFINITIVE = "code_infinitive"
    static let CODE_REQUEST = "code_request"
    static let MONEY_PLEA = "money_plea"
    static let BOSS = "boss"
    static let VOTE = "vote"
    static let FEE_UNPAID = "fee_unpaid"
    static let JOB_OFFER = "job_offer"
    static let LEAK_THREAT = "leak_threat"
    static let INTIMATE = "intimate"
    static let DATING = "dating"
    static let TICKET_BUY = "ticket_buy"
    static let MULE_OFFER = "mule_offer"
    static let MULE_REWARD = "mule_reward"
    static let LEGAL_WARNING = "legal_warning"
    static let CASH_JOB = "cash_job"
    static let HIRE = "hire"
    static let LISTING = "listing"
    static let RECEIVE_MONEY = "receive_money"
    static let SAFE_DEAL = "safe_deal"
    static let CHAT_MOVE = "chat_move"
    static let REMOTE_APP = "remote_app"
    static let INSTALL_VERB = "install_verb"
    static let NFC_TAP = "nfc_tap"
    static let REFUND = "refund"
    static let APK_WORD = "apk_word"
    static let MONEY_CONTEXT = "money_context"
    static let CASH_HANDOVER = "cash_handover"
    static let WRONG_NUMBER = "wrong_number"
    static let LAW_PRETEXT = "law_pretext"
    static let PASSPORT = "passport"
    static let SUMMONS = "summons"
    static let ORGANS = "organs"
    static let ORGANS_VAGUE = "organs_vague"
    static let PROBE = "probe"

    static let GEN_MONEY_ASK = "generic_money_ask"
    static let GEN_MONEY_INFINITIVE = "generic_money_infinitive"
    static let GEN_FEE = "generic_fee"
    static let GEN_MONEY_NOUN = "generic_money_noun"
    static let GEN_MODAL = "generic_modal"
    static let GEN_DATA_VERB = "generic_data_verb"
    static let GEN_CARD_DATA = "generic_card_data"
    static let GEN_TELL_VERB = "generic_tell_verb"
    static let GEN_SECRET = "generic_secret"
    static let GEN_IDENTITY = "generic_identity"
    static let GEN_PROMISE = "generic_promise"
    static let GEN_CLAIM = "generic_claim"
    static let GEN_PROMO = "generic_promo"
    static let GEN_THREAT = "generic_threat"
    static let GEN_ABSENT = "generic_absent"
    static let GEN_URGENCY = "generic_urgency"
    static let GEN_SECRECY = "generic_secrecy"
    static let GEN_AUTHORITY = "generic_authority"
}
