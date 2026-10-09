import Foundation

// Swift twin of MessageLinks.kt: host names, the root zone, links and phone
// numbers in a message. Every rule and its reason is documented there.

/// Host names as the blocklist hashes them: lowercase ASCII, IDN → punycode.
enum HostNames {
    private static let fullwidthDots: Set<UInt16> = [0x3002, 0xFF0E, 0xFF61]

    /// The checkable form of `raw`, or nil when it is not a plausible host.
    static func normalize(_ raw: U16?) -> U16? {
        guard let raw = raw else { return nil }
        var s = jTrim(raw).map { fullwidthDots.contains($0) ? 0x2E : $0 }
        s = jLowercase(s)
        while s.last == 0x2E { s.removeLast() }
        if s.isEmpty || s.count > 253 || s.containsU(u("..")) || !s.contains(0x2E) { return nil }
        guard let idn = try? IDN.toASCII(s) else { return nil }
        let ascii = jLowercase(idn)
        if ascii.count > 253 { return nil }
        let ok = splitChars(ascii, [0x2E]).allSatisfy { label in
            !label.isEmpty && label.count <= 63 && label.first != 0x2D && label.last != 0x2D &&
                label.allSatisfy { ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2D || $0 == 0x5F }
        }
        return ok ? ascii : nil
    }

    /// Is `host` equal to, or a subdomain of, one of `suffixes`?
    static func under(_ host: U16, _ suffixes: Set<U16>) -> Bool {
        if suffixes.isEmpty { return false }
        if suffixes.contains(host) { return true }
        var i = 0
        while i < host.count {
            if host[i] == 0x2E && suffixes.contains(Array(host[(i + 1)...])) { return true }
            i += 1
        }
        return false
    }
}

/// Every TLD of the IANA root zone (root_zone_tlds.txt).
enum RootZone {
    static let asset = "root_zone_tlds.txt"

    /// One TLD per line; '#' lines are comments.
    static func parse(_ text: U16) -> Set<U16> {
        var out = Set<U16>()
        var line = U16()
        var i = 0
        func take() {
            let t = jTrim(line)
            if !t.isEmpty && t.first != 0x23 { out.insert(MessageText.normalizeWord(t)) }
            line.removeAll(keepingCapacity: true)
        }
        while i < text.count {
            let c = text[i]
            if c == 0x0A || c == 0x0D {
                take()
                if c == 0x0D && text.at(i + 1) == 0x0A { i += 1 }
            } else {
                line.append(c)
            }
            i += 1
        }
        if !line.isEmpty { take() }
        return out
    }
}

/// A link as written in a message, before any verdict.
struct FoundLink: Equatable {
    /// Exactly as it appears in the message (path included).
    let text: U16
    /// Normalised host.
    let host: U16
    let isIp: Bool
    /// The path names an Android package file.
    var isApk: Bool
    /// A host label mixes Latin and Cyrillic letters.
    let mixedScript: Bool
    /// Where it sits in the message (first...last).
    let span: ClosedRange<Int>
}

/// Finds every link in a message: http(s):// URLs and bare domains (MessageLinks.kt's LinkExtractor).
enum LinkExtractor {
    private static let webSchemes: [U16] = [u("https"), u("http")]
    private static let hardStops: Set<UInt16> = Set(u("<>\"«»“”„|\\^{}`'‘’"))
    private static let trailing: Set<UInt16> = Set(u(".,;:!?…)]}'\"»”"))
    private static let dots: Set<UInt16> = [0x2E, 0x3002, 0xFF0E, 0xFF61]
    private static let notBeforeBare: Set<UInt16> = Set(u("@/\\=?&#%"))
    private static let dashes: Set<UInt16> = [0x2D, 0x2010, 0x2011, 0x2013, 0x2014]
    private static let pathStart: Set<UInt16> = Set(u("/?#"))
    private static let maxTld = 24
    private static let sentenceWords: Set<U16> = Set([
        "no", "me", "to", "so", "in", "it", "is", "at", "be", "by", "do", "my", "am", "an", "as", "us", "go", "ok", "hi",
    ].map(u))

    static func extract(_ text: U16, bareTlds: Set<U16>) -> [FoundLink] {
        var found: [FoundLink] = []
        var consumed: [ClosedRange<Int>] = []
        schemeLinks(text, &found, &consumed)
        bareLinks(text, bareTlds, &found, stableSorted(consumed) { $0.lowerBound })
        return dedupe(stableSorted(found) { $0.span.lowerBound })
    }

    // ── http(s):// ────────────────────────────────────────────────────

    private static func schemeLinks(_ text: U16, _ out: inout [FoundLink], _ consumed: inout [ClosedRange<Int>]) {
        var from = 0
        let sepToken = u("://")
        while true {
            guard let sep = text.indexOfU(sepToken, from: from) else { return }
            let web = webSchemeStart(text, sep)
            var start = web ?? sep
            if web == nil {
                while start > 0 {
                    let p = text[start - 1]
                    if JChar.isLetterOrDigit(p) || p == 0x2B || p == 0x2E || p == 0x2D { start -= 1 } else { break }
                }
            }
            let end = trimTrailing(text, start, runEnd(text, sep + 3))
            from = max(end, sep + 3)
            if end <= sep + 3 { continue }
            if web == nil {
                consumed.append(start...(end - 1))
                continue
            }
            let rest = text.sub(sep + 3, end)
            let authLen = rest.firstIndex { $0 == 0x2F || $0 == 0x3F || $0 == 0x23 } ?? rest.count
            let authority = rest.sub(0, authLen)
            let hostPart = authority.lastIndex(of: 0x40).map { authority.sub($0 + 1, authority.count) } ?? authority
            if hostPart.first == 0x5B { // IPv6 literal
                consumed.append(start...(end - 1))
                continue
            }
            let rawHost = hostPart.firstIndex(of: 0x3A).map { hostPart.sub(0, $0) } ?? hostPart
            guard let host = HostNames.normalize(rawHost) else { continue }
            consumed.append(start...(end - 1))
            out.append(FoundLink(
                text: text.sub(start, end),
                host: host,
                isIp: isIpv4(host),
                isApk: pathIsApk(rest.sub(authority.count, rest.count)),
                mixedScript: mixesScripts(rawHost),
                span: start...(end - 1)
            ))
        }
    }

    // ── bare domains ──────────────────────────────────────────────────

    private static func bareLinks(_ text: U16, _ bareTlds: Set<U16>, _ out: inout [FoundLink], _ consumed: [ClosedRange<Int>]) {
        var i = 0
        let n = text.count
        var skipIdx = 0
        while i < n {
            while skipIdx < consumed.count && consumed[skipIdx].upperBound < i { skipIdx += 1 }
            if skipIdx < consumed.count && consumed[skipIdx].contains(i) {
                i = consumed[skipIdx].upperBound + 1
                continue
            }
            if !isHostChar(text[i]) { i += 1; continue }
            var e = i
            while e < n && (isHostChar(text[e]) || dots.contains(text[e])) { e += 1 }
            if let link = bareCandidate(text, i, e, bareTlds) {
                out.append(link)
                i = link.span.upperBound + 1
            } else {
                i = e
            }
        }
    }

    private static func bareCandidate(_ text: U16, _ runStart: Int, _ runStop: Int, _ bareTlds: Set<U16>) -> FoundLink? {
        if runStart > 0 && notBeforeBare.contains(text[runStart - 1]) { return nil }
        if runStop < text.count && text[runStop] == 0x40 { return nil }
        var s = runStart
        var e = runStop
        while s < e && (dots.contains(text[s]) || text[s] == 0x2D) { s += 1 }
        while e > s && (dots.contains(text[e - 1]) || text[e - 1] == 0x2D || text[e - 1] == 0x5F) { e -= 1 }
        if e <= s { return nil }
        let all = splitChars(text.sub(s, e), dots)
        if all.count < 2 || all.contains(where: { $0.isEmpty || $0.count > 63 }) { return nil }

        let ip = all.count == 4 && all.allSatisfy { l in
            l.allSatisfy(JChar.isDigit) && l.count <= 3 && (javaParseInt(l) ?? Int.max) <= 255
        }
        if ip {
            let next = text.at(e)
            if next != 0x2F && next != 0x3A { return nil }
        } else {
            var keep: Int?
            var k = all.count
            while k >= 2 {
                let after: UInt16? = k == all.count ? text.at(e) : 0x2E
                if plausibleTld(Array(all[0..<k]), bareTlds, after) { keep = k; break }
                k -= 1
            }
            guard let kept = keep else { return nil }
            e = s + all[0..<kept].reduce(0) { $0 + $1.count } + kept - 1
        }
        let raw = text.sub(s, e)
        let next = text.at(e)
        guard let host = HostNames.normalize(raw) else { return nil }

        var end = e
        if next == 0x3A, let d = text.at(e + 1), JChar.isDigit(d) {
            end = e + 1
            while end < text.count && JChar.isDigit(text[end]) { end += 1 }
        }
        let pathStartAt = end
        if end < text.count && pathStart.contains(text[end]) { end = trimTrailing(text, end, runEnd(text, end)) }
        return FoundLink(
            text: text.sub(s, end),
            host: host,
            isIp: ip,
            isApk: pathIsApk(text.sub(pathStartAt, end)),
            mixedScript: mixesScripts(raw),
            span: s...(end - 1)
        )
    }

    /// Is the last of `labels` a TLD, and the whole a name rather than words around a dot?
    private static func plausibleTld(_ labels: [U16], _ tlds: Set<U16>, _ after: UInt16?) -> Bool {
        if !endsLink(after) { return false }
        let written = labels[labels.count - 1]
        let name = labels[labels.count - 2]
        let pathFollows = after == 0x2F
        if name.contains(0x5F) { return false }
        let tld = MessageText.normalizeWord(written)
        if tld.hasPrefixU(u("xn--")) { return true }
        if tld.contains(where: { !JChar.isLetter($0) }) { return false }
        let cyrillic = tld.allSatisfy(MessageText.isCyrillic)
        let latin = tld.allSatisfy { $0 >= 0x61 && $0 <= 0x7A }
        if !cyrillic && !latin { return false }
        let nameLatin = name.contains { ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x41 && $0 <= 0x5A) }
        let nameCyrillic = name.contains(where: MessageText.isCyrillic)
        let titleCase = written.count > 1 && JChar.isUpperCase(written[0]) && written.dropFirst().allSatisfy(JChar.isLowerCase)
        if cyrillic {
            if !nameCyrillic || name.count < 2 || !tlds.contains(tld) { return false }
            if pathFollows { return true }
            if titleCase && tld.count > 2 { return false }
            return tld.count < 4 || written == tld
        }
        if nameCyrillic && !nameLatin { return pathFollows && tlds.contains(tld) }
        if pathFollows && tld.count >= 2 && tld.count <= maxTld { return true }
        if !tlds.contains(tld) { return false }
        if name.allSatisfy(JChar.isDigit) { return false }
        if titleCase && (tld.count > 2 || sentenceWords.contains(tld) || name.count < 2) { return false }
        return !(written == u("ID") && name.contains(where: JChar.isLowerCase))
    }

    /// May a link end right before `c`?
    private static func endsLink(_ c: UInt16?) -> Bool {
        guard let c = c else { return true }
        return JChar.isWhitespace(c) || c == 0x2F || c == 0x3A || c == 0x3F || c == 0x23 ||
            trailing.contains(c) || hardStops.contains(c) || dashes.contains(c)
    }

    private static func isHostChar(_ c: UInt16) -> Bool { JChar.isLetterOrDigit(c) || c == 0x2D || c == 0x5F }

    private static func runEnd(_ text: U16, _ from: Int) -> Int {
        var e = from
        while e < text.count && !JChar.isWhitespace(text[e]) && !hardStops.contains(text[e]) { e += 1 }
        return e
    }

    private static func trimTrailing(_ text: U16, _ start: Int, _ end: Int) -> Int {
        var e = end
        while e > start && trailing.contains(text[e - 1]) {
            if text[e - 1] == 0x29 && text[start..<(e - 1)].contains(0x28) { break }
            e -= 1
        }
        return e
    }

    private static func pathIsApk(_ path: U16) -> Bool {
        var p = path
        if let q = p.firstIndex(of: 0x3F) { p = p.sub(0, q) }
        if let h = p.firstIndex(of: 0x23) { p = p.sub(0, h) }
        return jLowercase(p).hasSuffixU(u(".apk"))
    }

    private static func isIpv4(_ host: U16) -> Bool {
        let parts = splitChars(host, [0x2E])
        return parts.count == 4 && parts.allSatisfy { p in
            !p.isEmpty && p.count <= 3 && p.allSatisfy(JChar.isDigit) && (javaParseInt(p) ?? Int.max) <= 255
        }
    }

    private static func mixesScripts(_ host: U16) -> Bool {
        splitChars(host, [0x2E, 0x2D]).contains { label in
            label.contains { ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x41 && $0 <= 0x5A) } && label.contains(where: MessageText.isCyrillic)
        }
    }

    /// One entry per host; a later mention can only add the .apk flag.
    private static func dedupe(_ links: [FoundLink]) -> [FoundLink] {
        var order: [U16] = []
        var byHost: [U16: FoundLink] = [:]
        for l in links {
            if var prev = byHost[l.host] {
                prev.isApk = prev.isApk || l.isApk
                byHost[l.host] = prev
            } else {
                order.append(l.host)
                byHost[l.host] = l
            }
        }
        return order.map { byHost[$0]! }
    }

    /// Where "http(s)" starts before "://" (case-insensitive as String.regionMatches), or nil.
    private static func webSchemeStart(_ text: U16, _ sep: Int) -> Int? {
        for scheme in webSchemes {
            let start = sep - scheme.count
            if start >= 0 && (0..<scheme.count).allSatisfy({ k in charsEqualIgnoreCase(text[start + k], scheme[k]) }) {
                return start
            }
        }
        return nil
    }

    /// java.lang.String.regionMatches(ignoreCase = true) on one pair of chars.
    private static func charsEqualIgnoreCase(_ a: UInt16, _ b: UInt16) -> Bool {
        if a == b { return true }
        let ua = JChar.simpleUpper(a), ub = JChar.simpleUpper(b)
        if ua == ub { return true }
        return JChar.simpleLower(ua) == JChar.simpleLower(ub)
    }
}

/// Integer.parseInt over decimal digits of any script (Kotlin's String.toInt()).
func javaParseInt(_ s: U16) -> Int? {
    if s.isEmpty { return nil }
    var v = 0
    for c in s {
        guard let d = JChar.digitValue(c) else { return nil }
        v = v * 10 + d
        if v > Int(Int32.max) { return nil }
    }
    return v
}

/// Phone numbers in a message, normalised to +<digits> (MessageLinks.kt's PhoneExtractor).
enum PhoneExtractor {
    private static let maxSpan = 24
    private static let separators: Set<UInt16> = [0x20, 0x2D, 0x28, 0x29, 0xA0, 0x2011, 0x2012, 0x2013]

    enum Kind { case mobile, tollFree, city, foreign }

    struct Phone: Equatable {
        let number: U16
        let kind: Kind
    }

    static func extract(_ text: U16) -> [Phone] {
        var order: [U16] = []
        var out: [U16: Phone] = [:]
        var i = 0
        while i < text.count {
            let c = text[i]
            let startsHere = (c == 0x2B && (text.at(i + 1).map(JChar.isDigit) ?? false)) || JChar.isDigit(c)
            if !startsHere || gluedToPrevious(text, i) {
                i += 1
                continue
            }
            let (phone, end) = readAt(text, i)
            if let p = phone, out[p.number] == nil {
                out[p.number] = p
                order.append(p.number)
            }
            i = max(end, i + 1)
        }
        return order.map { out[$0]! }
    }

    private static func gluedToPrevious(_ text: U16, _ i: Int) -> Bool {
        guard let prev = text.at(i - 1) else { return false }
        if JChar.isLetterOrDigit(prev) || prev == 0x2A { return true }
        return (prev == 0x2E || prev == 0x2C) && (text.at(i - 2).map(JChar.isDigit) ?? false)
    }

    /// Normalise a number written anywhere (rules file, sender id). Nil when it is not one.
    static func normalize(_ raw: U16) -> U16? {
        let digits = raw.filter(JChar.isDigit)
        if digits.count >= 3 && digits.count <= 6 && !raw.contains(0x2B) { return digits }
        return classify(digits, plus: jTrim(raw).first == 0x2B, separated: true)?.number
    }

    private static func readAt(_ text: U16, _ start: Int) -> (Phone?, Int) {
        let plus = text[start] == 0x2B
        var digits = U16()
        var j = plus ? start + 1 : start
        var lastDigit = j
        var separated = false
        while j < text.count && j - start <= maxSpan {
            let c = text[j]
            if JChar.isDigit(c) {
                digits.append(c)
                lastDigit = j + 1
                if digits.count == 11 && (digits[0] == 0x37 || digits[0] == 0x38) && !(text.at(j + 1).map(JChar.isDigit) ?? false) {
                    break
                }
            } else if separators.contains(c), let nx = text.at(j + 1), JChar.isDigit(nx) || separators.contains(nx) {
                separated = true
            } else {
                break
            }
            j += 1
        }
        if let after = text.at(lastDigit),
           JChar.isLetter(after) || (after == 0x2E && (text.at(lastDigit + 1).map(JChar.isDigit) ?? false)) {
            return (nil, lastDigit)
        }
        return (classify(digits, plus: plus, separated: separated), lastDigit)
    }

    private static func classify(_ digits: U16, plus: Bool, separated: Bool) -> Phone? {
        var ru: U16?
        if digits.count == 11 && (digits[0] == 0x37 || (digits[0] == 0x38 && !plus)) {
            ru = digits.sub(1, digits.count)
        } else if digits.count == 10 && digits[0] == 0x39 && !plus && separated {
            ru = digits
        }
        if let ru = ru {
            let kind: Kind = ru.first == 0x39 ? .mobile : (ru.hasPrefixU(u("800")) ? .tollFree : .city)
            return Phone(number: u("+7") + ru, kind: kind)
        }
        if plus && digits.count >= 10 && digits.count <= 15 { return Phone(number: [0x2B] + digits, kind: .foreign) }
        return nil
    }
}
