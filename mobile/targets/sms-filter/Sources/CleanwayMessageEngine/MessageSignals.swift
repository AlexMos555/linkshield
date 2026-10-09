import Foundation

// Swift twin of MessageSignals.kt. Each signal is a fact about the text, never
// a verdict; the comments on each one live in the Kotlin file.

private typealias G = MessageRules

/// What the on-device list says about one link's host (LinkPolicy.kt's LinkStatus).
public enum LinkStatus: String {
    case blocked, system, allowedByUser = "allowed_by_user", unknown
}

/// One link with everything the rules need to know about it.
struct LinkFacts: Equatable {
    let found: FoundLink
    let status: LinkStatus
    let shortener: Bool
    let messenger: Bool
    let official: Bool
    let imitatesBrand: Bool
    var imitatesState: Bool = false

    var suspicious: Bool {
        !official && (shortener || messenger || found.isIp || found.mixedScript || found.isApk || imitatesBrand)
    }
    var vouched: Bool { status == .allowedByUser }
    var unofficial: Bool { !official && !vouched }
}

final class MessageSignals {
    let rules: MessageRules
    let index: WordIndex
    let text: U16
    private let hiddenInWord: Bool
    let links: [LinkFacts]
    let phones: [PhoneExtractor.Phone]
    let sender: U16?

    init(rules: MessageRules, index: WordIndex, text: U16, hiddenInWord: Bool, links: [LinkFacts], phones: [PhoneExtractor.Phone], sender: U16?) {
        self.rules = rules
        self.index = index
        self.text = text
        self.hiddenInWord = hiddenInWord
        self.links = links
        self.phones = phones
        self.sender = sender
    }

    private var cache: [String: [Hit]] = [:]
    func hits(_ group: String) -> [Hit] {
        if let h = cache[group] { return h }
        let h = index.hits(rules.group(group))
        cache[group] = h
        return h
    }
    func has(_ group: String) -> Bool { !hits(group).isEmpty }

    // ── who the message claims to be ───────────────────────────────────

    lazy var organisations: [MessageRules.Organisation] = rules.organisations.filter { org in
        org.names.contains { !index.hits($0).isEmpty }
    }
    var namesKnownBody: Bool { organisations.contains { $0.kind != .service } }
    var namesAuthority: Bool { organisations.contains { $0.kind == .gov || $0.kind == .security || $0.kind == .bank } }
    var namesAnyBody: Bool { !organisations.isEmpty }
    var namesState: Bool { organisations.contains { $0.kind == .gov || $0.kind == .security } }
    var namesServiceOnly: Bool { !organisations.isEmpty && organisations.allSatisfy { $0.kind == .service } }
    var namesSecurity: Bool { organisations.contains { $0.kind == .security } }
    var namesBankByName: Bool { organisations.contains { $0.kind == .bank && !$0.catchAll } }
    var namesMarketplace: Bool { organisations.contains { $0.kind == .delivery } }
    var namesOnlyCatchAll: Bool { !organisations.isEmpty && organisations.allSatisfy { $0.catchAll } }
    var namesOnlyMessenger: Bool { !organisations.isEmpty && organisations.allSatisfy { $0.kind == .messenger } }

    // ── pressure and bait ─────────────────────────────────────────────

    lazy var obey: Bool = has(G.OBEY)
    lazy var threatWords: Bool = has(G.THREAT)
    lazy var threat: Bool = threatWords || obey
    lazy var urgency: Bool = has(G.URGENCY) || within() || dateDeadline()
    lazy var confirmData: Bool = hits(G.CONFIRM_DATA).contains { active($0) }
    var pressure: Bool { threat || urgency || confirmData }
    var pressureBeyondDate: Bool { threat || has(G.URGENCY) || within() || confirmData }
    lazy var bait: Bool = has(G.BAIT)
    lazy var payout: Bool = has(G.PAYOUT)
    lazy var jobOffer: Bool = has(G.JOB_OFFER)

    // ── what it asks the reader to do ─────────────────────────────────

    lazy var callAsked: Bool = hits(G.CALL).contains { active($0) }
    private lazy var unofficialPhones: [PhoneExtractor.Phone] = phones.filter { !rules.officialPhones.contains($0.number) }
    lazy var callbackStrong: Bool = callAsked && unofficialPhones.contains { $0.kind != .tollFree }
    lazy var callbackPersonal: Bool = callAsked && unofficialPhones.contains { $0.kind == .mobile || $0.kind == .foreign }
    lazy var callbackWeak: Bool = callAsked && !callbackStrong && !unofficialPhones.isEmpty
    lazy var callComing: Bool = hits(G.CALL_COMING).contains { h in
        active(h) && !conditional(h.start) && !(h.start...h.end).contains { index.isWord($0, rules.negators) }
    }

    lazy var codeAsked: Bool = codeToPerson() || flashCallDigits()
    private lazy var liveMoneyVerbs: [Hit] =
        hits(G.MONEY_VERB).filter { active($0) } + hits(G.MONEY_REQUEST).filter { active($0) } +
        hits(G.MONEY_INFINITIVE).filter { active($0) && directiveBefore($0) }
    private lazy var moneyPlea: Bool = (cardNumber || amount()) && hits(G.MONEY_PLEA).contains { active($0) }
    var moneyMove: Bool { !liveMoneyVerbs.isEmpty || moneyPlea }
    lazy var cardNumber: Bool = Self.cardNumberRe.containsMatch(in: text)
    lazy var safeAccount: Bool = hits(G.SAFE_ACCOUNT).contains { safeAccountActive($0) }
    lazy var payAsked: Bool = hits(G.PAY_VERB).contains { active($0) }
    lazy var fee: Bool = {
        let feeWords = hits(G.FEE_WORD)
        if hits(G.PAY_VERB).contains(where: { p in
            active(p) && feeWords.contains { f in follows(p, f, 4) && !index.isWord(f.start - 1, Self.without) }
        }) { return true }
        return payAsked && hits(G.FEE_UNPAID).contains { un in feeWords.contains { f in follows(un, f, 2) || follows(f, un, 2) } }
    }()
    lazy var install: Bool = hits(G.INSTALL).contains { active($0) }
    lazy var malwareLure: Bool = has(G.MALWARE_LURE)
    lazy var smsTransferCommand: Bool =
        has(G.SMS_COMMAND) && (!phones.isEmpty || index.words.contains { $0.isNumber && $0.forms[0].count >= 10 })

    // ── relative in trouble ───────────────────────────────────────────

    lazy var kin: Bool = has(G.KIN)
    lazy var newNumber: Bool = has(G.NEW_NUMBER)
    lazy var emergency: Bool = has(G.EMERGENCY)
    lazy var secrecy: Bool = has(G.SECRECY)

    var disguised: Bool { index.disguised || hiddenInWord }

    // ── the boss and the vote ─────────────────────────────────────────

    lazy var boss: Bool = has(G.BOSS)
    lazy var vote: Bool = hits(G.VOTE).contains { active($0) }
    lazy var codeMentioned: Bool = hits(G.CODE_WORD).contains { c in !hits(G.CODE_HOUSEHOLD).contains { follows(c, $0, 2) } }

    // ── the 2026-10 schemes ───────────────────────────────────────────

    lazy var leakThreat: Bool = has(G.LEAK_THREAT)
    lazy var intimate: Bool = has(G.INTIMATE)
    lazy var moneyDemand: Bool =
        amount() || cardNumber || has(G.PAY_VERB) || has(G.MONEY_VERB) || has(G.MONEY_INFINITIVE)
    lazy var dating: Bool = has(G.DATING)
    lazy var ticketBuy: Bool = hits(G.TICKET_BUY).contains { active($0) }
    lazy var muleOffer: Bool =
        hits(G.MULE_OFFER).contains { active($0) } && (has(G.MULE_REWARD) || Self.percentCut.containsMatch(in: text)) &&
        !has(G.LEGAL_WARNING) && !safetyNotice
    lazy var cashJob: Bool =
        hits(G.CASH_JOB).contains { active($0) } && (has(G.HIRE) || jobOffer) && !has(G.LEGAL_WARNING) && !safetyNotice
    lazy var listing: Bool = has(G.LISTING)
    lazy var receiveMoney: Bool = hits(G.RECEIVE_MONEY).contains { active($0) }
    lazy var safeDeal: Bool = has(G.SAFE_DEAL)
    lazy var chatMove: Bool = has(G.CHAT_MOVE)
    lazy var installVerb: Bool = hits(G.INSTALL_VERB).contains { active($0) }
    lazy var remoteAsked: Bool = has(G.REMOTE_APP) && installVerb
    lazy var nfcTap: Bool = hits(G.NFC_TAP).contains { active($0) }
    lazy var refund: Bool = has(G.REFUND)
    lazy var apkNamed: Bool = has(G.APK_WORD)
    lazy var moneyContext: Bool = has(G.MONEY_CONTEXT) || refund
    lazy var cashHandover: Bool = hits(G.CASH_HANDOVER).contains { active($0) && !conditional($0.start) }
    lazy var wrongNumber: Bool = has(G.WRONG_NUMBER)
    lazy var lawPretext: Bool = has(G.LAW_PRETEXT)
    lazy var passportAsked: Bool = hits(G.CODE_VERB).contains { v in active(v) && hits(G.PASSPORT).contains { follows(v, $0, 4) } }
    lazy var summons: Bool = hits(G.SUMMONS).contains { active($0) }
    lazy var caseCited: Bool = Self.caseNumber.containsMatch(in: text) || Self.article.containsMatch(in: text)
    lazy var organs: Bool = has(G.ORGANS)
    lazy var organsVague: Bool = has(G.ORGANS_VAGUE) && has(G.PROBE)

    lazy var apkLinks: [LinkFacts] = {
        let own = Set(organisations.flatMap { $0.domains })
        return links.filter { l in
            l.found.isApk && !l.vouched && !HostNames.under(l.found.host, rules.appStores) &&
                !(l.official && HostNames.under(l.found.host, own))
        }
    }()

    // ── legitimate shapes ─────────────────────────────────────────────

    lazy var loginCode: Bool = hits(G.CODE_LABEL).contains { numberNear($0.start, window: 4, digits: 4...8) }
    lazy var paymentAlert: Bool = amount() && has(G.PAYMENT_OP) && (Self.cardMask.containsMatch(in: text) || has(G.BALANCE_WORD))
    lazy var pickupCode: Bool = has(G.PICKUP) && index.words.contains { $0.isNumber && (3...8).contains($0.forms[0].count) }
    lazy var publicAlert: Bool = has(G.PUBLIC_ALERT)
    lazy var safetyNotice: Bool = has(G.AWARENESS)
    lazy var codeInMessage: Bool = hits(G.CODE_WORD).contains { numberNear($0.start, window: 3, digits: 3...8) }

    // ── sender (optional; only ever adds suspicion) ───────────────────

    lazy var senderPersonal: Bool = {
        guard let s = sender, s.contains(where: { !JChar.isWhitespace($0) }) else { return false }
        return PhoneExtractor.extract(s).contains { $0.kind != .tollFree && !rules.officialPhones.contains($0.number) }
    }()
    lazy var senderMismatch: Bool = {
        guard let raw = sender else { return false }
        let s = jLowercase(jTrim(raw))
        if s.isEmpty { return false }
        guard organisations.count == 1, let only = organisations.first else { return false }
        return !only.senders.isEmpty && only.kind == .gov && !senderPersonal && !only.senders.contains(s)
    }()

    // ── helpers ───────────────────────────────────────────────────────

    func active(_ hit: Hit) -> Bool { !negated(hit.start) && !aware(hit.start) }

    func negated(_ i: Int) -> Bool {
        if index.isWord(i - 1, rules.negators) && index.sameClause(i - 1, i) { return true }
        return index.isWord(i - 2, rules.negators) && index.isWord(i - 1, rules.intermediates) && index.sameClause(i - 2, i)
    }

    func aware(_ i: Int) -> Bool {
        hits(G.AWARENESS).contains { $0.end < i && i - $0.end <= Self.awareWindow && index.sameSentence($0.end, i) }
    }

    private func codeRequested(_ h: Hit) -> Bool {
        (hits(G.DIRECTIVE) + hits(G.CODE_REQUEST)).contains { d in
            d.end < h.start && h.start - d.end <= 2 && index.sameClause(d.end, h.start) && active(d) && !conditional(d.start)
        }
    }

    func conditional(_ i: Int) -> Bool {
        var j = i - 1
        while j >= 0 && index.sameClause(j, i) {
            if index.isWord(j, Self.ifWords) { return true }
            j -= 1
        }
        return false
    }

    private func directiveBefore(_ h: Hit) -> Bool {
        hits(G.DIRECTIVE).contains { d in d.end < h.start && h.start - d.end <= 2 && index.sameClause(d.end, h.start) }
    }

    /// Does `g` start within `after` words after `h`, in the same sentence?
    func follows(_ h: Hit, _ g: Hit, _ after: Int) -> Bool {
        g.start > h.end && g.start - h.end <= after && index.sameSentence(h.end, g.start)
    }

    private func codeToPerson() -> Bool {
        if pickupHandover() { return false }
        if hits(G.CODE_DICTATE).contains(where: { active($0) && takesCode($0) }) { return true }
        let infinitive = hits(G.CODE_INFINITIVE).contains { v in active(v) && (codeRequested(v) || wrongNumber) && takesCode(v) }
        let asked = infinitive || hits(G.CODE_VERB).contains { active($0) && takesCode($0) }
        if asked && (has(G.CODE_TARGET) || has(G.CALL_CONTEXT) || has(G.CODE_INCOMING) || wrongNumber) { return true }
        return hits(G.CODE_VERB).contains { negated($0.start) && takesCode($0) && exceptListener($0) }
    }

    private func takesCode(_ v: Hit) -> Bool {
        let direct = hits(G.CODE_WORD).contains { c in
            follows(v, c, 6) && !hits(G.CODE_HOUSEHOLD).contains { follows(c, $0, 2) }
        }
        return direct || (hits(G.CODE_PRONOUN).contains { follows(v, $0, 2) } && hits(G.CODE_LABEL).contains { $0.start < v.start })
    }

    private func exceptListener(_ v: Hit) -> Bool {
        hits(G.CODE_EXCEPT).contains { x in
            follows(v, x, 8) && (hits(G.CODE_TARGET) + hits(G.CALL_CONTEXT)).contains { follows(x, $0, 3) }
        }
    }

    func pickupHandover() -> Bool {
        has(G.PICKUP_CONTEXT) && organisations.allSatisfy { $0.kind == .delivery } && (!organisations.isEmpty || codeInMessage)
    }

    private func flashCallDigits() -> Bool {
        hits(G.FLASH_CALL).contains { f in hits(G.CODE_VERB).contains { v in active(v) && index.sameSentence(v.start, f.start) } }
    }

    private func safeAccountActive(_ h: Hit) -> Bool {
        if aware(h.start) { return false }
        let verbs = (hits(G.MONEY_VERB) + hits(G.MONEY_INFINITIVE) + hits(G.MONEY_REQUEST))
            .filter { $0.start < h.start && index.sameSentence($0.start, h.start) }
        if !verbs.isEmpty { return verbs.contains { liveMoneyVerbs.contains($0) } }
        if hits(G.SCAM_LABEL).contains(where: { follows(h, $0, Self.labelWindow) }) { return false }
        var j = h.start - 1
        while j >= 0 && index.sameClause(j, h.start) {
            if index.isWord(j, rules.negators) { return false }
            j -= 1
        }
        return true
    }

    private func numberNear(_ i: Int, window: Int, digits: ClosedRange<Int>) -> Bool {
        let lo = max(0, i - window), hi = min(index.words.count - 1, i + window)
        if lo > hi { return false }
        return (lo...hi).contains { j in
            let w = index.words[j]
            return w.isNumber && digits.contains(w.forms[0].count)
        }
    }

    /// "356р", "1 500 руб", "RUB 1299" — a sum of money.
    func amount() -> Bool {
        let words = index.words
        let currency = rules.group(G.CURRENCY)
        func isCurrency(_ j: Int) -> Bool {
            j >= 0 && j < words.count && currency.contains { $0.stems.count == 1 && $0.stems[0].matches(words[j]) }
        }
        return words.indices.contains { j in
            let w = words[j]
            return Self.gluedAmount.matchesEntire(w.forms[0]) || (w.isNumber && (isCurrency(j + 1) || isCurrency(j - 1)))
        }
    }

    private func within() -> Bool { Self.withinRe.containsMatch(in: text) }

    private lazy var translit: Bool = index.words.contains { $0.translit }

    private func dateDeadline() -> Bool {
        (translit ? Self.deadlineLatin : Self.deadline).ranges(in: text).contains { m in
            let before = text.sub(max(0, m.location - 16), m.location)
            return !Self.rangeStart.containsMatch(in: before)
        }
    }

    // java.util.regex patterns with \d → [0-9] and \s → the ASCII class (Java's defaults).
    // IGNORE_CASE is dropped: `text` is already lowercase, and Java's (ASCII-only) folding then changes nothing.
    private static let awareWindow = 5
    private static let labelWindow = 4
    private static let without: Set<U16> = Set(["без", "no", "without"].map(u))
    static let ifWords: Set<U16> = Set(["если", "if"].map(u))
    private static let S = "[ \\t\\n\\x0B\\f\\r]"
    private static let cardNumberRe = JRegex("(?<![\\p{N}])[2-6][0-9]{3}(?:[ -]?[0-9]{4}){3}(?![\\p{N}])")
    private static let cardMask = JRegex(
        "(?:[*•]{1,4}|[xх]{2,4})\(S)?[0-9]{4}(?![0-9])|(?<!\\p{L})(?:mir|visa|ecmc|mc|maestro|мир|сч[её]т|сч|карт\\p{L}{0,2}|card)\(S)?[-*•.]{0,4}\(S)?[0-9]{4}(?![0-9])"
    )
    private static let gluedAmount = JRegex("^[0-9]+(?:р|руб\\p{L}*|rub|rur)$")
    private static let deadline = JRegex("(?<![\\p{L}\\p{N}])до\(S)+[0-9]{1,2}[.:][0-9]{2}(?![0-9])")
    private static let deadlineLatin = JRegex("(?<![\\p{L}\\p{N}])do\(S)+[0-9]{1,2}[.:][0-9]{2}(?![0-9])")
    private static let rangeStart = JRegex("(?<!\\p{L})[сcs]\(S)*[0-9]{1,2}[.:][0-9]{2}\(S)*[-–—]?\(S)*$")
    private static let percentCut = JRegex("[0-9]{1,2}\(S)?%\(S)*(?:от|с|тебе|твои|твоих|себе|вам|ваши|за)(?!\\p{L})")
    private static let caseNumber = JRegex("(?<!\\p{L})дел[оауе]?\(S)*(?:№|n|номер)\(S)*[0-9]")
    private static let article = JRegex(
        "(?<!\\p{L})(?:ст\\.?|стать\\p{L}*)\(S)*[0-9]{1,3}(?:\\.[0-9]{1,2})?(?:\(S)*ч\\.?\(S)*[0-9])?\(S)*(?:ук|гк|коап|упк|гпк|апк)(?!\\p{L})"
    )
    private static let withinRe = JRegex(
        "(?<![\\p{L}\\p{N}])(?:(?:в\(S)+течение|within)\(S)+[0-9]{1,3}\(S)*(?:час|мин|сут|дн|день|дня|hour|minute|day)|(?:через|in)\(S)+[0-9]{1,3}\(S)*(?:час|сут|дн|день|дня|hour|day))"
    )
}
