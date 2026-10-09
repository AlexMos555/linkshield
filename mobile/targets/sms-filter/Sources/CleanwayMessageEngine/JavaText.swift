import Foundation

// The Kotlin engine (mobile/modules/cleanway-vpn/android/.../Message*.kt) works
// on JVM strings: UTF-16 code units, java.lang.Character classes, Java's
// lowercase and java.util.regex. Swift's String compares by grapheme and
// canonical equivalence ("é" == "e\u{301}"), so a port on String would part
// from Kotlin on exactly the inputs a scammer controls. Every text here is
// therefore a [UInt16] of UTF-16 code units, and every character class below
// is the JVM's, written out. KotlinParityTests pins the result.

typealias U16 = [UInt16]

@inline(__always) func u(_ s: String) -> U16 { Array(s.utf16) }

extension Array where Element == UInt16 {
    var string: String { String(decoding: self, as: UTF16.self) }
}

/// java.lang.Character / kotlin.Char predicates, on one UTF-16 code unit.
enum JChar {
    @inline(__always) static func scalar(_ c: UInt16) -> Unicode.Scalar? {
        (0xD800...0xDFFF).contains(c) ? nil : Unicode.Scalar(UInt32(c))
    }

    /// Character.isLetter(char): Lu, Ll, Lt, Lm, Lo. A surrogate is none of them.
    static func isLetter(_ c: UInt16) -> Bool {
        if c < 0x80 { return (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) }
        guard let s = scalar(c) else { return false }
        switch s.properties.generalCategory {
        case .uppercaseLetter, .lowercaseLetter, .titlecaseLetter, .modifierLetter, .otherLetter: return true
        default: return false
        }
    }

    /// Character.isDigit(char): Nd.
    static func isDigit(_ c: UInt16) -> Bool {
        if c < 0x80 { return c >= 0x30 && c <= 0x39 }
        guard let s = scalar(c) else { return false }
        return s.properties.generalCategory == .decimalNumber
    }

    static func isLetterOrDigit(_ c: UInt16) -> Bool { isLetter(c) || isDigit(c) }

    /// kotlin.Char.isWhitespace on the JVM: Character.isWhitespace || Character.isSpaceChar.
    static func isWhitespace(_ c: UInt16) -> Bool {
        if c == 0x20 || (c >= 0x09 && c <= 0x0D) || (c >= 0x1C && c <= 0x1F) { return true }
        if c < 0x80 { return false }
        guard let s = scalar(c) else { return false }
        switch s.properties.generalCategory {
        case .spaceSeparator, .lineSeparator, .paragraphSeparator: return true
        default: return false
        }
    }

    /// Character.isUpperCase(char): Lu or Other_Uppercase.
    static func isUpperCase(_ c: UInt16) -> Bool {
        guard let s = scalar(c) else { return false }
        return s.properties.isUppercase
    }

    /// Character.isLowerCase(char): Ll or Other_Lowercase.
    static func isLowerCase(_ c: UInt16) -> Bool {
        guard let s = scalar(c) else { return false }
        return s.properties.isLowercase
    }

    /// Character.digit(ch, 10) for a decimal digit of any script, else nil.
    static func digitValue(_ c: UInt16) -> Int? {
        if c >= 0x30 && c <= 0x39 { return Int(c - 0x30) }
        guard isDigit(c), let s = scalar(c), let v = s.properties.numericValue else { return nil }
        return Int(v)
    }

    /// Character.toUpperCase(char) — the simple mapping (one char to one char).
    static func simpleUpper(_ c: UInt16) -> UInt16 {
        guard let s = scalar(c) else { return c }
        let m = Array(s.properties.uppercaseMapping.utf16)
        return m.count == 1 ? m[0] : c
    }

    /// Character.toLowerCase(char) — the simple mapping.
    static func simpleLower(_ c: UInt16) -> UInt16 {
        guard let s = scalar(c) else { return c }
        if c == 0x130 { return 0x69 } // İ: its full mapping is two chars, its simple one is "i"
        let m = Array(s.properties.lowercaseMapping.utf16)
        return m.count == 1 ? m[0] : c
    }
}

/// Code points of UTF-16 units, with a lone surrogate kept as itself (as Java does).
func codePoints(_ s: U16) -> [UInt32] {
    var out: [UInt32] = []
    out.reserveCapacity(s.count)
    var i = 0
    while i < s.count {
        let c = s[i]
        if c >= 0xD800 && c <= 0xDBFF && i + 1 < s.count && s[i + 1] >= 0xDC00 && s[i + 1] <= 0xDFFF {
            out.append(0x10000 + ((UInt32(c) - 0xD800) << 10) + (UInt32(s[i + 1]) - 0xDC00))
            i += 2
        } else {
            out.append(UInt32(c))
            i += 1
        }
    }
    return out
}

func appendCodePoint(_ cp: UInt32, to out: inout U16) {
    if cp >= 0x10000 {
        let v = cp - 0x10000
        out.append(UInt16(0xD800 + (v >> 10)))
        out.append(UInt16(0xDC00 + (v & 0x3FF)))
    } else {
        out.append(UInt16(cp))
    }
}

/// String.toLowerCase(Locale.ROOT): per code point, the final sigma in context, İ → "i̇".
func jLowercase(_ s: U16) -> U16 {
    // Fast path: nothing to change.
    if !s.contains(where: { ($0 >= 0x41 && $0 <= 0x5A) || $0 >= 0x80 }) { return s }
    let cps = codePoints(s)
    var out = U16()
    out.reserveCapacity(s.count)
    for (i, cp) in cps.enumerated() {
        if cp < 0x80 {
            out.append(UInt16(cp >= 0x41 && cp <= 0x5A ? cp + 32 : cp))
            continue
        }
        guard let sc = Unicode.Scalar(cp) else { out.append(UInt16(cp)); continue }
        if cp == 0x3A3 {
            out.append(isFinalSigma(cps, i) ? 0x3C2 : 0x3C3)
            continue
        }
        for unit in sc.properties.lowercaseMapping.utf16 { out.append(unit) }
    }
    return out
}

/// Java's ConditionalSpecialCasing: Σ after a cased letter and not before one is final.
private func isFinalSigma(_ cps: [UInt32], _ i: Int) -> Bool {
    func props(_ cp: UInt32) -> Unicode.Scalar.Properties? { Unicode.Scalar(cp)?.properties }
    var j = i - 1
    var before = false
    while j >= 0 {
        guard let p = props(cps[j]) else { break }
        if p.isCaseIgnorable { j -= 1; continue }
        before = p.isCased
        break
    }
    if !before { return false }
    j = i + 1
    while j < cps.count {
        guard let p = props(cps[j]) else { return true }
        if p.isCaseIgnorable { j += 1; continue }
        return !p.isCased
    }
    return true
}

/// kotlin.text.trim(): drops Char.isWhitespace from both ends.
func jTrim(_ s: U16) -> U16 {
    var a = 0
    var b = s.count
    while a < b && JChar.isWhitespace(s[a]) { a += 1 }
    while b > a && JChar.isWhitespace(s[b - 1]) { b -= 1 }
    return Array(s[a..<b])
}

/// java.util.regex's \s without UNICODE_CHARACTER_CLASS.
@inline(__always) func isAsciiSpace(_ c: UInt16) -> Bool {
    c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0B || c == 0x0C || c == 0x0D
}

/// Kotlin's split(Regex("\\s+")) — keeps empty leading and trailing parts.
func splitAsciiSpaces(_ s: U16) -> [U16] {
    var out: [U16] = []
    var cur = U16()
    var i = 0
    var any = false
    while i < s.count {
        if isAsciiSpace(s[i]) {
            any = true
            out.append(cur)
            cur = []
            while i < s.count && isAsciiSpace(s[i]) { i += 1 }
            continue
        }
        cur.append(s[i])
        i += 1
    }
    if !any { return [s] }
    out.append(cur)
    return out
}

/// Kotlin's split(vararg delimiters: Char) — keeps every empty part.
func splitChars(_ s: U16, _ delims: Set<UInt16>) -> [U16] {
    var out: [U16] = []
    var cur = U16()
    for c in s {
        if delims.contains(c) { out.append(cur); cur = [] } else { cur.append(c) }
    }
    out.append(cur)
    return out
}

extension Array where Element == UInt16 {
    func hasPrefixU(_ p: U16, at i: Int = 0) -> Bool {
        if i < 0 || i + p.count > count { return false }
        for k in 0..<p.count where self[i + k] != p[k] { return false }
        return true
    }

    func hasSuffixU(_ p: U16) -> Bool { p.count <= count && hasPrefixU(p, at: count - p.count) }

    func indexOfU(_ p: U16, from: Int = 0) -> Int? {
        if p.isEmpty { return from <= count ? from : nil }
        var i = Swift.max(0, from)
        while i + p.count <= count {
            if self[i] == p[0] && hasPrefixU(p, at: i) { return i }
            i += 1
        }
        return nil
    }

    func containsU(_ p: U16) -> Bool { indexOfU(p) != nil }

    func lastIndexOfU(_ c: UInt16) -> Int? { lastIndex(of: c) }

    func sub(_ a: Int, _ b: Int) -> U16 { Array(self[a..<b]) }

    func at(_ i: Int) -> UInt16? { i >= 0 && i < count ? self[i] : nil }
}

/// A java.util.regex pattern run through ICU (NSRegularExpression). Patterns
/// are written with [0-9] and an explicit ASCII-space class, because ICU's \d
/// and \s are Unicode-wide and Java's are not.
final class JRegex {
    private let re: NSRegularExpression

    init(_ pattern: String) {
        // Constant patterns: a failure here is a programming error caught by the tests.
        re = try! NSRegularExpression(pattern: pattern, options: [])
    }

    // String(decoding:) keeps the UTF-16 length (a lone surrogate becomes one U+FFFD),
    // so NSRange offsets are offsets into [s].
    func containsMatch(in s: U16) -> Bool {
        let str = s.string
        return re.firstMatch(in: str, options: [], range: NSRange(location: 0, length: s.count)) != nil
    }

    /// The whole of [s] matches (Regex.matches).
    func matchesEntire(_ s: U16) -> Bool {
        let str = s.string
        guard let m = re.firstMatch(in: str, options: [.anchored], range: NSRange(location: 0, length: s.count)) else { return false }
        return m.range.location == 0 && m.range.length == s.count
    }

    /// Every match's range, in UTF-16 units (Regex.findAll).
    func ranges(in s: U16) -> [NSRange] {
        let str = s.string
        return re.matches(in: str, options: [], range: NSRange(location: 0, length: s.count)).map { $0.range }
    }

    /// The first match's capture groups (Regex.find(...).groupValues).
    func firstGroups(in s: U16) -> [U16?]? {
        let str = s.string
        guard let m = re.firstMatch(in: str, options: [], range: NSRange(location: 0, length: s.count)) else { return nil }
        return (0..<m.numberOfRanges).map { k in
            let r = m.range(at: k)
            return r.location == NSNotFound ? nil : Array(s[r.location..<(r.location + r.length)])
        }
    }
}

/// Kotlin's sortedBy: a STABLE sort.
func stableSorted<T>(_ a: [T], by key: (T) -> Int) -> [T] {
    a.enumerated().sorted { l, r in
        let kl = key(l.element), kr = key(r.element)
        return kl != kr ? kl < kr : l.offset < r.offset
    }.map { $0.element }
}

/// Kotlin's distinct(): first occurrence kept, order kept.
func distinctKeepingOrder<T: Hashable>(_ a: [T]) -> [T] {
    var seen = Set<T>()
    return a.filter { seen.insert($0).inserted }
}
