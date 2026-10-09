import Foundation

/// Overall result. There is deliberately no "safe": a message can only show no signals.
public enum MessageVerdict: String {
    case dangerous
    case caution
    case noSignals = "no_signals"
}

/// A link found in the message.
public struct MessageLink: Equatable {
    public let text: String
    public let host: String
    public let status: LinkStatus
    public let shortener: Bool
    public let messenger: Bool
}

public struct MessageAnalysis {
    public let verdict: MessageVerdict
    /// Stable snake_case codes, most important first. Empty for no_signals.
    public let reasons: [String]
    public let links: [MessageLink]
    /// Full phone numbers found, normalised to +<digits>.
    public let phones: [String]
    public let legitShape: String?
    public let organisations: [String]
    public let truncated: Bool
}

/// The on-device message check — the Swift twin of MessageAnalyzer.kt, which
/// documents every rule. KotlinParityTests replays what the Kotlin engine says
/// about every corpus message and requires the same verdict and reasons here.
///
/// The text is read in memory and dropped: never logged, stored or sent.
public final class MessageAnalyzer {
    private let rules: MessageRules
    private let model: MessageModel?
    private let remote: RemoteConfig
    private let linkStatus: (U16) -> LinkStatus

    public init(rules: MessageRules, model: MessageModel? = nil, remote: RemoteConfig = .default) {
        self.rules = rules
        self.model = model
        self.remote = remote
        // The filter extension holds no blocklist: every host is "not on the list".
        linkStatus = { _ in .unknown }
    }

    public func analyze(_ input: String, sender: String? = nil) -> MessageAnalysis {
        analyze(u(input), sender: sender.map(u))
    }

    func analyze(_ text: U16, sender: U16?) -> MessageAnalysis {
        let truncated = text.count > Self.maxChars
        let cut = truncated ? text.sub(0, Self.maxChars) : text
        let signals = read(cut, sender)
        let shape = legitShape(signals)
        let (ruleVerdict, ruleReasons) = decide(signals, excluded: shape != nil)
        let active = remote.smsTextModelEnabled ? model : nil
        let verdict: MessageVerdict
        let reasons: [String]
        if active == nil || shape != nil || ruleVerdict == .dangerous {
            (verdict, reasons) = (ruleVerdict, ruleReasons)
        } else {
            (verdict, reasons) = withModel(active!, cut, signals, ruleVerdict, ruleReasons)
        }
        return MessageAnalysis(
            verdict: verdict,
            reasons: reasons,
            links: shown(signals.links).map {
                MessageLink(text: $0.found.text.string, host: $0.found.host.string, status: $0.status, shortener: $0.shortener, messenger: $0.messenger)
            },
            phones: signals.phones.map { $0.number.string },
            legitShape: verdict != .dangerous ? shape : nil,
            organisations: signals.organisations.map { $0.id.string },
            truncated: truncated
        )
    }

    private func withModel(_ model: MessageModel, _ text: U16, _ s: MessageSignals, _ verdict: MessageVerdict, _ reasons: [String]) -> (MessageVerdict, [String]) {
        let g = GenericSignals(s)
        if Self.officialChannelsOnly(s, g) { return (verdict, reasons) }
        guard let p = model.score(text) else { return (verdict, reasons) }
        let danger = remote.dangerThreshold(model.dangerThreshold)
        let caution = remote.cautionThreshold(model.cautionThreshold)
        if p < danger && p < caution { return (verdict, reasons) }
        if p >= danger && !Self.modelIngredients(s, g).isEmpty {
            return (.dangerous, distinctKeepingOrder([Self.R_TEXT_RESEMBLES_SCAM] + reasons + GenericLayer.reasons(s, g)))
        }
        if p < caution { return (verdict, reasons) }
        if verdict == .caution { return (verdict, distinctKeepingOrder(reasons + [Self.R_TEXT_RESEMBLES_SCAM])) }
        return (.caution, distinctKeepingOrder([Self.R_TEXT_RESEMBLES_SCAM] + GenericLayer.reasons(s, g)))
    }

    func read(_ text: U16, _ sender: U16?) -> MessageSignals {
        let cleaned = MessageText.clean(text)
        let found = LinkExtractor.extract(cleaned.text, bareTlds: rules.bareTlds)
        let links = found.map(facts)
        let phones = PhoneExtractor.extract(blank(cleaned.text, found.map { $0.span }))
        return MessageSignals(
            rules: rules,
            index: MessageText.index(cleaned.text, masked: found.map { $0.span }, translitMarkers: rules.translitMarkers),
            text: MessageText.normalizeWord(cleaned.text),
            hiddenInWord: cleaned.hiddenInWord,
            links: links,
            phones: phones,
            sender: sender
        )
    }

    /// At most maxLinks links for the screen, in message order — listed ones first to keep.
    private func shown(_ links: [LinkFacts]) -> [LinkFacts] {
        if links.count <= Self.maxLinks { return links }
        let listed = Array(links.filter { $0.status == .blocked }.prefix(Self.maxLinks))
        let keep = listed + links.filter { $0.status != .blocked }.prefix(Self.maxLinks - listed.count)
        return links.filter { l in keep.contains(l) }
    }

    private func facts(_ link: FoundLink) -> LinkFacts {
        let official = rules.isOfficial(link.host)
        let imitated = official ? [] : self.imitated(link.host)
        return LinkFacts(
            found: link,
            status: linkStatus(link.host),
            shortener: HostNames.under(link.host, rules.shorteners),
            messenger: HostNames.under(link.host, rules.messengers),
            official: official,
            imitatesBrand: !imitated.isEmpty,
            imitatesState: imitated.contains { $0.kind == .gov || $0.kind == .security }
        )
    }

    private func imitated(_ host: U16) -> [MessageRules.Organisation] {
        let tokens = distinctKeepingOrder(hostTokens(host) + hostTokens(unicode(host)))
        return rules.organisations.filter { org in
            org.domainTokens.contains { brand in
                tokens.contains { t in
                    t == brand || (brand.count >= 6 && (t.hasPrefixU(brand) || t.hasSuffixU(brand))) ||
                        (brand.count == 5 && brand.allSatisfy { ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) } && t.hasPrefixU(brand)) ||
                        (brand.count >= 8 && t.containsU(brand))
                }
            }
        }
    }

    private func hostTokens(_ host: U16) -> [U16] {
        let n = MessageText.normalizeWord(host)
        let beforeLast = n.lastIndex(of: 0x2E).map { n.sub(0, $0) } ?? n
        return splitChars(beforeLast, [0x2E, 0x2D]).filter { !$0.isEmpty }
    }

    private func unicode(_ host: U16) -> U16 {
        host.containsU(u("xn--")) ? IDN.toUnicode(host) : host
    }

    func legitShape(_ s: MessageSignals) -> String? {
        let clean = !s.links.contains { $0.unofficial } && s.apkLinks.isEmpty && !s.callbackStrong && !s.codeAsked &&
            !s.safeAccount && !s.malwareLure && !s.smsTransferCommand
        if !clean { return nil }
        if s.pickupCode { return Self.SHAPE_PICKUP_CODE }
        if s.loginCode { return Self.SHAPE_LOGIN_CODE }
        if s.paymentAlert { return Self.SHAPE_PAYMENT_ALERT }
        if s.publicAlert { return Self.SHAPE_PUBLIC_ALERT }
        if s.safetyNotice && !s.moneyMove && !s.install && !s.callbackWeak && !s.pressure { return Self.SHAPE_SAFETY_NOTICE }
        return nil
    }

    private func decide(_ s: MessageSignals, excluded: Bool) -> (MessageVerdict, [String]) {
        var danger = OrderedSet()
        var caution = OrderedSet()
        if s.links.contains(where: { $0.status == .blocked }) { danger.add(Self.R_LINK_BLOCKLISTED) }
        if !excluded {
            dangerous(s, &danger)
            cautious(s, &caution)
            GenericLayer.judge(s, &danger, &caution)
        }
        if !danger.isEmpty {
            var all = danger
            all.add(caution.items)
            return (.dangerous, all.items)
        }
        if !caution.isEmpty { return (.caution, caution.items) }
        return (.noSignals, [])
    }

    private func dangerous(_ s: MessageSignals, _ out: inout OrderedSet) {
        let foreign = s.links.filter { $0.unofficial }
        let pressureReasons = self.pressureReasons(s)
        if s.namesKnownBody && s.pressure && s.callbackStrong {
            out.add([Self.R_ORGANISATION] + pressureReasons + [Self.R_CALL_UNKNOWN])
        }
        let linkPressure = s.namesOnlyCatchAll ? s.pressureBeyondDate : s.pressure
        if s.namesKnownBody && linkPressure && !foreign.isEmpty {
            out.add([Self.R_ORGANISATION] + pressureReasons + Self.linkReasons(foreign))
        }
        if s.namesKnownBody && s.fee && !foreign.isEmpty {
            out.add([Self.R_ORGANISATION, Self.R_PAYMENT] + Self.linkReasons(foreign))
        }
        if (s.namesState && s.bait || s.namesBankByName && s.payout) && !foreign.isEmpty {
            out.add([Self.R_ORGANISATION, Self.R_BAIT] + Self.linkReasons(foreign))
        }
        let stateLookalike = foreign.filter { $0.imitatesState }
        if s.threat && s.payAsked && !stateLookalike.isEmpty {
            out.add([Self.R_THREAT, Self.R_PAYMENT] + Self.linkReasons(stateLookalike))
        }
        let chats = foreign.filter { $0.messenger }
        if s.namesMarketplace && s.jobOffer && !chats.isEmpty {
            out.add([Self.R_ORGANISATION, Self.R_BAIT] + Self.linkReasons(chats))
        }
        if s.codeAsked { out.add(s.namesAnyBody ? [Self.R_CODE, Self.R_ORGANISATION] : [Self.R_CODE]) }
        if s.safeAccount && (s.moneyMove || s.namesAuthority || s.callbackStrong) { out.add(Self.R_SAFE_ACCOUNT) }
        if s.kin && s.moneyMove && (s.newNumber || s.emergency) { out.add(Self.R_RELATIVE) }
        if s.boss && s.namesSecurity && s.callComing && s.secrecy { out.add([Self.R_ORGANISATION, Self.R_THREAT]) }
        if s.namesSecurity && s.threatWords && s.callComing && s.obey { out.add([Self.R_ORGANISATION, Self.R_THREAT]) }
        if s.malwareLure && !foreign.isEmpty { out.add([Self.R_MALWARE_LURE] + Self.linkReasons(foreign)) }
        if s.install && foreign.contains(where: { $0.suspicious || s.namesKnownBody }) { out.add([Self.R_INSTALL] + Self.linkReasons(foreign)) }
        if !s.apkLinks.isEmpty { out.add([Self.R_INSTALL] + Self.linkReasons(s.apkLinks)) }
        if s.bait && s.fee { out.add([Self.R_BAIT, Self.R_PAYMENT]) }
        if s.smsTransferCommand { out.add(Self.R_SMS_COMMAND) }
        newSchemes(s, foreign, &out)
    }

    private func newSchemes(_ s: MessageSignals, _ foreign: [LinkFacts], _ out: inout OrderedSet) {
        let named = s.namesAnyBody ? [Self.R_ORGANISATION] : []
        if s.leakThreat && s.intimate && (s.moneyDemand || !foreign.isEmpty) {
            out.add([Self.R_THREAT, Self.R_PAYMENT] + Self.linkReasons(foreign))
        }
        if s.muleOffer || s.cashJob { out.add([Self.R_BAIT] + Self.linkReasons(foreign)) }
        let sites = foreign.filter { !$0.messenger }
        let chats = foreign.filter { $0.messenger }
        if s.listing && !sites.isEmpty && (s.receiveMoney || s.safeDeal || s.confirmData) {
            out.add([Self.R_PAYMENT] + Self.linkReasons(sites))
        }
        if s.listing && !chats.isEmpty && (s.receiveMoney || s.safeDeal) { out.add([Self.R_PAYMENT] + Self.linkReasons(chats)) }
        if s.nfcTap && (s.apkNamed || !s.apkLinks.isEmpty || !foreign.isEmpty || s.refund || s.payout) {
            out.add(named + [Self.R_INSTALL] + Self.linkReasons(foreign))
        }
        if s.remoteAsked && (s.namesKnownBody || s.moneyContext) { out.add(named + [Self.R_INSTALL] + Self.linkReasons(foreign)) }
        if s.install && !foreign.isEmpty && (s.refund || s.payout || s.safeAccount) { out.add([Self.R_INSTALL] + Self.linkReasons(foreign)) }
        if s.apkNamed && (s.install || s.installVerb) && (s.namesKnownBody || s.moneyContext || s.pressure) {
            out.add(named + [Self.R_INSTALL])
        }
        if s.cashHandover && (s.namesAuthority || s.safeAccount || s.callComing || s.secrecy || s.obey) {
            out.add(named + [Self.R_SAFE_ACCOUNT])
        }
        if s.lawPretext && (s.threat || s.urgency) && (!foreign.isEmpty || s.callbackStrong || s.passportAsked || s.codeAsked) {
            out.add(pressureReasons(s) + (s.callbackStrong ? [Self.R_CALL_UNKNOWN] : []) + Self.linkReasons(foreign))
        }
        if s.lawPretext && s.passportAsked { out.add([Self.R_CONFIRM_DATA] + pressureReasons(s)) }
        if s.summons && s.caseCited && (s.callbackPersonal || !foreign.isEmpty) {
            out.add(named + [Self.R_THREAT] + (s.callbackPersonal ? [Self.R_CALL_UNKNOWN] : []) + Self.linkReasons(foreign))
        }
        if s.boss && s.callComing && (s.secrecy || s.obey) && (s.organs || s.organsVague) { out.add([Self.R_ORGANISATION, Self.R_THREAT]) }
    }

    private func cautious(_ s: MessageSignals, _ out: inout OrderedSet) {
        let foreign = s.links.filter { $0.unofficial }
        let hidden = foreign.filter { $0.suspicious }
        let hiddenBeyondShortener = hidden.filter { !$0.shortener || $0.found.isApk || $0.imitatesBrand }
        let chatInvite = s.namesOnlyMessenger && foreign.allSatisfy { $0.messenger }
        if s.namesKnownBody && !foreign.isEmpty && !chatInvite {
            out.add([Self.R_ORGANISATION] + (s.bait ? [Self.R_BAIT] : []) + Self.linkReasons(foreign))
        }
        if s.namesAuthority && s.callbackStrong && (s.pressure || s.bait || s.callbackPersonal) {
            out.add([Self.R_ORGANISATION, Self.R_CALL_UNKNOWN])
        }
        if s.namesKnownBody && s.pressure && s.callbackWeak {
            out.add([Self.R_ORGANISATION] + pressureReasons(s) + [Self.R_CALL_UNKNOWN])
        }
        if s.pressure && s.callbackStrong && !s.namesServiceOnly { out.add(pressureReasons(s) + [Self.R_CALL_UNKNOWN]) }
        if s.threat && s.callbackWeak { out.add([Self.R_THREAT, Self.R_CALL_UNKNOWN]) }
        if s.bait && s.callbackStrong { out.add([Self.R_BAIT, Self.R_CALL_UNKNOWN]) }
        if (s.threat || s.confirmData) && !hidden.isEmpty {
            out.add(pressureReasons(s) + (s.bait ? [Self.R_BAIT] : []) + Self.linkReasons(hidden))
        } else if (s.urgency || s.bait) && !hiddenBeyondShortener.isEmpty {
            out.add(pressureReasons(s) + (s.bait ? [Self.R_BAIT] : []) + Self.linkReasons(hiddenBeyondShortener))
        }
        let disguisedLinks = foreign.filter { $0.found.isIp || $0.found.mixedScript || $0.imitatesBrand }
        if !disguisedLinks.isEmpty { out.add(Self.linkReasons(disguisedLinks)) }
        if s.safeAccount && (s.namesAnyBody || s.pressure || s.callAsked || !foreign.isEmpty) { out.add(Self.R_SAFE_ACCOUNT) }
        if s.disguised && (s.namesAnyBody || s.pressure || !foreign.isEmpty) { out.add(Self.R_DISGUISED) }
        if s.kin && s.moneyMove && (s.secrecy || s.urgency) { out.add(Self.R_RELATIVE) }
        if s.newNumber && s.moneyMove && (s.secrecy || s.urgency) { out.add(Self.R_RELATIVE) }
        if s.namesSecurity && s.callComing && (s.obey || s.secrecy) { out.add([Self.R_ORGANISATION, Self.R_THREAT]) }
        if s.vote && s.codeMentioned && !foreign.isEmpty { out.add([Self.R_CODE] + Self.linkReasons(foreign)) }
        nobodyNamed(s, foreign, &out)
        if s.leakThreat && s.intimate { out.add(Self.R_THREAT) }
        if s.dating && s.ticketBuy && !foreign.isEmpty { out.add([Self.R_PAYMENT] + Self.linkReasons(foreign)) }
        if s.listing && s.chatMove && (s.receiveMoney || s.safeDeal) { out.add([Self.R_PAYMENT] + Self.linkReasons(foreign)) }
        if s.summons && s.caseCited && (s.callComing || s.callbackWeak) {
            out.add((s.namesAnyBody ? [Self.R_ORGANISATION] : []) + [Self.R_THREAT])
        }
        if s.lawPretext && (s.threat || s.urgency) && s.callComing { out.add(pressureReasons(s)) }
        if s.install && !foreign.isEmpty && s.pressure { out.add([Self.R_INSTALL] + Self.linkReasons(foreign)) }
        if s.namesKnownBody && s.senderPersonal { out.add([Self.R_ORGANISATION, Self.R_SENDER_PERSONAL]) }
        if s.senderMismatch { out.add([Self.R_ORGANISATION, Self.R_SENDER_MISMATCH]) }
    }

    private func nobodyNamed(_ s: MessageSignals, _ foreign: [LinkFacts], _ out: inout OrderedSet) {
        if s.namesAnyBody || foreign.isEmpty { return }
        if s.threat && s.payAsked { out.add([Self.R_THREAT, Self.R_PAYMENT] + Self.linkReasons(foreign)) }
        if s.threat && s.confirmData { out.add(pressureReasons(s) + Self.linkReasons(foreign)) }
        if s.fee { out.add([Self.R_PAYMENT] + Self.linkReasons(foreign)) }
        if s.payout && (s.urgency || s.confirmData) { out.add(pressureReasons(s) + [Self.R_BAIT] + Self.linkReasons(foreign)) }
    }

    private func pressureReasons(_ s: MessageSignals) -> [String] {
        var out: [String] = []
        if s.threat || s.urgency { out.append(Self.R_THREAT) }
        if s.confirmData { out.append(Self.R_CONFIRM_DATA) }
        return out
    }

    /// Spaces over `spans` so a number inside a URL is not read as a phone.
    private func blank(_ text: U16, _ spans: [ClosedRange<Int>]) -> U16 {
        if spans.isEmpty { return text }
        var chars = text
        for r in spans { for i in r where i >= 0 && i < chars.count { chars[i] = 0x20 } }
        return chars
    }

    public static let maxChars = 10_000
    static let maxLinks = 20

    static let SHAPE_LOGIN_CODE = "login_code"
    static let SHAPE_PAYMENT_ALERT = "payment_alert"
    static let SHAPE_PICKUP_CODE = "pickup_code"
    static let SHAPE_PUBLIC_ALERT = "public_alert"
    static let SHAPE_SAFETY_NOTICE = "safety_notice"

    static let R_LINK_BLOCKLISTED = "link_blocklisted"
    static let R_ORGANISATION = "claims_organisation"
    static let R_THREAT = "threat_or_urgency"
    static let R_CONFIRM_DATA = "asks_to_confirm_data"
    static let R_BAIT = "reward_bait"
    static let R_CALL_UNKNOWN = "call_unknown_number"
    static let R_LINK_NOT_OFFICIAL = "link_not_official"
    static let R_LINK_SHORTENER = "link_shortener"
    static let R_LINK_MESSENGER = "link_messenger"
    static let R_LINK_IP = "link_ip_address"
    static let R_LINK_LOOKALIKE = "link_lookalike"
    static let R_LINK_IMITATES_BRAND = "link_imitates_brand"
    static let R_LINK_APK = "link_apk"
    static let R_CODE = "asks_for_code"
    static let R_SAFE_ACCOUNT = "safe_account"
    static let R_PAYMENT = "asks_for_payment"
    static let R_RELATIVE = "relative_in_trouble"
    static let R_INSTALL = "install_app"
    static let R_MALWARE_LURE = "malware_lure"
    static let R_SMS_COMMAND = "sms_transfer_command"
    static let R_DISGUISED = "disguised_letters"
    static let R_SENDER_PERSONAL = "sender_personal_number"
    static let R_SENDER_MISMATCH = "sender_mismatch"
    static let R_SECRECY = "asks_for_secrecy"
    static let R_TEXT_RESEMBLES_SCAM = "text_resembles_scam"

    /// Every link and number the message gives is the organisation's own.
    static func officialChannelsOnly(_ s: MessageSignals, _ g: GenericSignals) -> Bool {
        (!s.links.isEmpty || !s.phones.isEmpty) && g.foreign.isEmpty && s.phones.allSatisfy { s.rules.officialPhones.contains($0.number) }
    }

    /// The rules' ingredients that let a high model score make a message dangerous.
    static func modelIngredients(_ s: MessageSignals, _ g: GenericSignals) -> [String] {
        var out: [String] = []
        if !g.foreign.isEmpty { out.append("foreign") }
        if g.moneyAsked { out.append("moneyAsked") }
        if s.moneyMove { out.append("moneyMove") }
        if g.code || s.codeAsked { out.append("code") }
        if g.promise { out.append("promise") }
        if g.threat { out.append("threat") }
        if s.callbackPersonal { out.append("callbackPersonal") }
        if s.install || !s.apkLinks.isEmpty || s.remoteAsked { out.append("install") }
        if g.secrecy { out.append("secrecy") }
        return out
    }

    /// Why a set of links is a problem, most specific first after "not the brand's".
    static func linkReasons(_ links: [LinkFacts]) -> [String] {
        var out: [String] = []
        if links.contains(where: { !$0.official }) { out.append(R_LINK_NOT_OFFICIAL) }
        if links.contains(where: { $0.shortener }) { out.append(R_LINK_SHORTENER) }
        if links.contains(where: { $0.messenger }) { out.append(R_LINK_MESSENGER) }
        if links.contains(where: { $0.found.isIp }) { out.append(R_LINK_IP) }
        if links.contains(where: { $0.found.mixedScript }) { out.append(R_LINK_LOOKALIKE) }
        if links.contains(where: { $0.imitatesBrand }) { out.append(R_LINK_IMITATES_BRAND) }
        if links.contains(where: { $0.found.isApk }) { out.append(R_LINK_APK) }
        return out
    }
}
