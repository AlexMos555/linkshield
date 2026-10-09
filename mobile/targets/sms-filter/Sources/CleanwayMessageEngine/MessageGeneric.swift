import Foundation

// Swift twin of MessageGeneric.kt: the scheme-independent ingredients of one
// message and the generic layer that combines them. Rationale in the Kotlin file.

private typealias G = MessageRules

final class GenericSignals {
    private let s: MessageSignals

    init(_ s: MessageSignals) { self.s = s }

    lazy var foreign: [LinkFacts] = s.links.filter { $0.unofficial && !(ownSite($0) && !$0.suspicious) }

    lazy var payable: [LinkFacts] = foreign.filter { !HostNames.under($0.found.host, s.rules.userContentHosts) }

    // ── money asked ───────────────────────────────────────────────────

    lazy var moneyAsked: Bool = moneyDemanded || s.hits(G.GEN_MONEY_INFINITIVE).contains { live($0) && !optional($0) }

    lazy var moneyDemanded: Bool =
        s.hits(G.GEN_MONEY_ASK).contains { live($0) && !optional($0) } ||
        s.hits(G.GEN_MONEY_INFINITIVE).contains { live($0) && !optional($0) && directed($0) } ||
        cardData

    lazy var cardData: Bool = asked(G.GEN_CARD_DATA)

    lazy var feeDemanded: Bool = {
        let fees = s.hits(G.FEE_WORD) + s.hits(G.GEN_FEE)
        return (s.hits(G.GEN_MONEY_ASK) + s.hits(G.GEN_MONEY_INFINITIVE)).contains { h in
            live(h) && !optional(h) && fees.contains { f in
                s.index.sameSentence(h.start, f.start) &&
                    ((f.start >= h.end + 1 && f.start <= h.end + Self.feeWindow) || (f.end >= h.start - Self.feeWindow && f.end < h.start))
            }
        }
    }()

    private func live(_ h: Hit) -> Bool { !s.aware(h.start) && (!s.negated(h.start) || s.conditional(h.start)) }

    private func optional(_ h: Hit) -> Bool {
        s.hits(G.GEN_MODAL).contains { m in
            s.index.sameClause(m.start, h.start) &&
                ((m.start >= h.start - 2 && m.start < h.start) || (m.start >= h.end + 1 && m.start <= h.end + 2))
        }
    }

    private func directed(_ h: Hit) -> Bool {
        (s.hits(G.DIRECTIVE) + s.hits(G.CODE_REQUEST)).contains { d in
            d.end < h.start && h.start - d.end <= 2 && s.index.sameClause(d.end, h.start) && s.active(d) && !s.conditional(d.start)
        }
    }

    private func asked(_ group: String) -> Bool {
        s.hits(G.GEN_DATA_VERB).contains { v in s.active(v) && s.hits(group).contains { s.follows(v, $0, 5) } }
    }

    // ── a code or personal data asked ─────────────────────────────────

    lazy var codeToPerson: Bool =
        !s.pickupHandover() &&
        (s.has(G.CODE_TARGET) || s.has(G.CALL_CONTEXT) || s.has(G.CODE_INCOMING) || s.callComing) &&
        (s.hits(G.GEN_TELL_VERB).contains { s.active($0) && secretAfter($0) } ||
            s.hits(G.CODE_INFINITIVE).contains { v in s.active(v) && (directed(v) || ifBefore(v)) && secretAfter(v) })

    private func ifBefore(_ v: Hit) -> Bool {
        s.index.isWord(v.start - 1, MessageSignals.ifWords) && s.index.sameClause(v.start - 1, v.start)
    }

    lazy var codeOnSite: Bool =
        !s.loginCode && !s.codeInMessage && s.hits(G.GEN_DATA_VERB).contains { s.active($0) && secretAfter($0) }

    lazy var identityAsked: Bool = s.confirmData || asked(G.GEN_IDENTITY)

    var code: Bool { codeToPerson || codeOnSite || identityAsked }

    private func secretAfter(_ v: Hit) -> Bool {
        s.hits(G.GEN_SECRET).contains { c in s.follows(v, c, 6) && !s.hits(G.CODE_HOUSEHOLD).contains { s.follows(c, $0, 2) } }
    }

    // ── a promise of money ────────────────────────────────────────────

    private lazy var amount: Bool = s.amount()
    lazy var promo: Bool = s.has(G.GEN_PROMO)
    lazy var claim: Bool = s.hits(G.GEN_CLAIM).contains { s.active($0) }
    lazy var promise: Bool = s.payout || s.has(G.GEN_PROMISE) || s.receiveMoney || (claim && amount && !promo)
    lazy var promiseOfMoney: Bool = promise && (amount || s.has(G.MONEY_CONTEXT) || s.has(G.GEN_MONEY_NOUN))

    // ── pressure, secrecy, a role ─────────────────────────────────────

    lazy var threat: Bool = s.obey || (s.hits(G.THREAT) + s.hits(G.GEN_THREAT)).contains { h in
        !s.hits(G.GEN_ABSENT).contains { $0.start >= h.end + 1 && $0.start <= h.end + 3 && s.index.sameClause(h.end, $0.start) }
    }
    lazy var urgency: Bool = s.urgency || s.has(G.GEN_URGENCY)

    lazy var secrecy: Bool = (s.hits(G.SECRECY) + s.hits(G.GEN_SECRECY)).contains { !guardsCode($0) }

    private lazy var codeWords: [Hit] = s.hits(G.CODE_WORD) + s.hits(G.CODE_PRONOUN) + s.hits(G.GEN_SECRET)

    private func guardsCode(_ h: Hit) -> Bool {
        codeWords.contains { $0.start >= h.start && $0.start <= h.end + 3 && s.index.sameSentence(h.start, $0.start) }
    }

    lazy var authority: Bool = s.namesKnownBody || s.has(G.GEN_AUTHORITY)

    lazy var chat: Bool = s.chatMove || foreign.contains { $0.messenger }

    // ── the sender's own site ─────────────────────────────────────────

    private lazy var signatures: [U16] = {
        var list: [U16] = []
        if let groups = Self.signatureRe.firstGroups(in: s.text), groups.count > 1, let label = groups[1],
           splitAsciiSpaces(jTrim(label)).count <= 3 {
            list.append(label)
        }
        if let sender = s.sender, sender.contains(where: JChar.isLetter) { list.append(sender) }
        return list.map { MessageText.normalizeWord($0).filter(JChar.isLetterOrDigit) }.filter { $0.count >= 3 }
    }()

    private func ownSite(_ link: LinkFacts) -> Bool {
        if signatures.isEmpty { return false }
        let parts = splitChars(link.found.host, [0x2E]).map { $0.filter { $0 != 0x2D } }
        var labels = Array(parts.dropLast())
        if parts.count >= 2 { labels.append(parts[parts.count - 2] + parts[parts.count - 1]) }
        return labels.filter { $0.count >= 3 }.contains { l in signatures.contains { Self.spells($0, l) } }
    }

    private static let feeWindow = 6
    private static let signatureRe = JRegex("^[ \\t\\n\\x0B\\f\\r]*([^:\\n]{2,30}):")

    /// Latin spellings of each Cyrillic letter, as Russian brands write their domains.
    private static let latin: [UInt16: [U16]] = {
        let table: [(Character, [String])] = [
            ("а", ["a"]), ("б", ["b"]), ("в", ["v", "w"]), ("г", ["g"]), ("д", ["d"]),
            ("е", ["e", "ye"]), ("ж", ["zh", "j"]), ("з", ["z"]), ("и", ["i"]),
            ("й", ["y", "i", "j", ""]), ("к", ["k", "c"]), ("л", ["l"]), ("м", ["m"]),
            ("н", ["n"]), ("о", ["o"]), ("п", ["p"]), ("р", ["r"]), ("с", ["s"]),
            ("т", ["t"]), ("у", ["u"]), ("ф", ["f"]), ("х", ["h", "kh", "x"]),
            ("ц", ["c", "ts", "tz"]), ("ч", ["ch"]), ("ш", ["sh"]), ("щ", ["sch", "sh", "shch"]),
            ("ъ", [""]), ("ы", ["y", "i"]), ("ь", [""]), ("э", ["e"]),
            ("ю", ["yu", "ju", "u"]), ("я", ["ya", "ja", "a"]),
        ]
        var m: [UInt16: [U16]] = [:]
        for (c, opts) in table { m[c.utf16.first!] = opts.map(u) }
        return m
    }()

    /// Does the Latin host label `latin` spell the signature `name`?
    static func spells(_ name: U16, _ latinLabel: U16) -> Bool {
        func go(_ i: Int, _ j: Int) -> Bool {
            if i == name.count { return j == latinLabel.count }
            let options = latin[name[i]] ?? [[name[i]]]
            return options.contains { o in latinLabel.hasPrefixU(o, at: j) && go(i + 1, j + o.count) }
        }
        return go(0, 0)
    }
}

/// The generic layer: warnings from ingredients, whatever the scheme (MessageGeneric.kt's GenericLayer).
enum GenericLayer {
    static func judge(_ s: MessageSignals, _ danger: inout OrderedSet, _ caution: inout OrderedSet) {
        if !danger.isEmpty { return }
        let g = GenericSignals(s)
        let linked = !g.foreign.isEmpty
        let core = [g.moneyAsked, g.code, g.promise, g.threat].filter { $0 }.count
        let moneyMoved = g.moneyAsked || s.moneyMove

        let dangerous = (linked && core >= 2) ||
            (g.codeToPerson && (g.authority || g.secrecy || g.threat || g.urgency || s.callComing)) ||
            (g.authority && g.secrecy && (s.callComing || s.callbackPersonal || moneyMoved || g.code)) ||
            (g.secrecy && moneyMoved && (g.threat || g.authority)) ||
            (g.threat && g.authority && s.callbackPersonal) ||
            (linked && g.authority && (g.threat || g.code))
        if dangerous {
            danger.add(reasons(s, g))
            return
        }
        let cautious = (linked && (g.threat || g.code)) ||
            (g.moneyDemanded && !g.payable.isEmpty && (g.feeDemanded || g.cardData || g.payable.contains { $0.suspicious })) ||
            (linked && g.promiseOfMoney && !g.promo && (g.claim || g.chat)) ||
            ((g.promise || g.threat) && s.callbackPersonal && !s.namesServiceOnly) ||
            (g.authority && s.callComing && (g.secrecy || s.obey)) ||
            (s.moneyMove && s.cardNumber && (g.threat || g.secrecy))
        if cautious { caution.add(reasons(s, g)) }
    }

    static func reasons(_ s: MessageSignals, _ g: GenericSignals) -> [String] {
        var out: [String] = []
        if g.authority { out.append(MessageAnalyzer.R_ORGANISATION) }
        if g.threat || g.urgency { out.append(MessageAnalyzer.R_THREAT) }
        if g.codeToPerson || g.codeOnSite { out.append(MessageAnalyzer.R_CODE) }
        if g.identityAsked { out.append(MessageAnalyzer.R_CONFIRM_DATA) }
        if g.moneyAsked { out.append(MessageAnalyzer.R_PAYMENT) }
        if g.promise { out.append(MessageAnalyzer.R_BAIT) }
        if g.secrecy { out.append(MessageAnalyzer.R_SECRECY) }
        if s.callbackPersonal { out.append(MessageAnalyzer.R_CALL_UNKNOWN) }
        out += MessageAnalyzer.linkReasons(g.foreign)
        return out
    }
}

/// Kotlin's LinkedHashSet<String> as the analyzer uses it: insertion order, no duplicates.
struct OrderedSet {
    private(set) var items: [String] = []
    private var seen = Set<String>()

    var isEmpty: Bool { items.isEmpty }

    mutating func add(_ s: String) { if seen.insert(s).inserted { items.append(s) } }
    mutating func add(_ list: [String]) { for s in list { add(s) } }
}
