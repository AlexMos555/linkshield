import Foundation

/// java.net.IDN (IDNA 2003, ALLOW_UNASSIGNED) as the Kotlin engine calls it:
/// toASCII for host names ("госуслуги.рф" → "xn--…xn--p1ai") and toUnicode
/// for reading a brand back out of a punycode name. Foundation has no public
/// IDNA API, so nameprep (RFC 3491) and punycode (RFC 3492) are written here.
enum IDN {
    struct Failure: Error {}

    private static let ace: U16 = u("xn--")
    private static let dots: Set<UInt16> = [0x2E, 0x3002, 0xFF0E, 0xFF61]

    /// IDN.toASCII(input, IDN.ALLOW_UNASSIGNED); throws where Java throws IllegalArgumentException.
    static func toASCII(_ input: U16) throws -> U16 {
        var out = U16()
        var p = 0
        while p < input.count {
            var q = p
            while q < input.count && !dots.contains(input[q]) { q += 1 }
            out += try labelToASCII(input.sub(p, q))
            if q != input.count { out.append(0x2E) }
            p = q + 1
        }
        return out
    }

    /// IDN.toUnicode(input, IDN.ALLOW_UNASSIGNED): a label that does not decode stays as written.
    static func toUnicode(_ input: U16) -> U16 {
        var out = U16()
        var p = 0
        while p < input.count {
            var q = p
            while q < input.count && !dots.contains(input[q]) { q += 1 }
            out += labelToUnicode(input.sub(p, q))
            if q != input.count { out.append(0x2E) }
            p = q + 1
        }
        return out
    }

    private static func isAllASCII(_ s: U16) -> Bool { !s.contains { $0 >= 0x80 } }

    private static func startsWithACE(_ s: U16) -> Bool {
        s.count >= 4 && jLowercaseASCII(s.sub(0, 4)) == ace
    }

    private static func jLowercaseASCII(_ s: U16) -> U16 { s.map { $0 >= 0x41 && $0 <= 0x5A ? $0 + 32 : $0 } }

    private static func labelToASCII(_ label: U16) throws -> U16 {
        var dest = isAllASCII(label) ? label : try nameprep(label)
        if dest.isEmpty { throw Failure() }
        if !isAllASCII(dest) {
            if startsWithACE(dest) { throw Failure() }
            dest = ace + jLowercaseASCII(try punycodeEncode(codePoints(dest)))
        }
        if dest.count > 63 { throw Failure() }
        return dest
    }

    private static func labelToUnicode(_ label: U16) -> U16 {
        let dest: U16
        if isAllASCII(label) {
            dest = label
        } else {
            guard let prepped = try? nameprep(label) else { return label }
            dest = prepped
        }
        guard startsWithACE(dest) else { return label }
        guard let decoded = try? punycodeDecode(dest.sub(4, dest.count)) else { return label }
        var units = U16()
        for cp in decoded { appendCodePoint(cp, to: &units) }
        guard let back = try? toASCII(units) else { return label }
        return jLowercaseASCII(back) == jLowercaseASCII(dest) ? units : label
    }

    // ── nameprep (RFC 3491 over RFC 3454) ─────────────────────────────

    /// Map (B.1 dropped, B.2 case folding), NFKC, then the prohibited and bidi checks.
    static func nameprep(_ label: U16) throws -> U16 {
        var mapped = U16()
        for cp in codePoints(label) where !mappedToNothing(cp) {
            appendCodePoint(cp, to: &mapped)
        }
        let folded = mapped.string.folding(options: [.caseInsensitive], locale: nil)
        let normalized = folded.precomposedStringWithCompatibilityMapping
        let cps = normalized.unicodeScalars.map { $0.value }
        if cps.contains(where: prohibited) { throw Failure() }
        // RFC 3454 §6: right-to-left letters may not mix with left-to-right
        // ones, and must start and end the label.
        if cps.contains(where: isRandAL) {
            if cps.contains(where: isL) { throw Failure() }
            if let f = cps.first, let l = cps.last, !(isRandAL(f) && isRandAL(l)) { throw Failure() }
        }
        return u(normalized)
    }

    /// RFC 3454 table B.1.
    private static func mappedToNothing(_ c: UInt32) -> Bool {
        switch c {
        case 0x00AD, 0x034F, 0x1806, 0x180B...0x180D, 0x200B...0x200D, 0x2060, 0xFE00...0xFE0F, 0xFEFF: return true
        default: return false
        }
    }

    /// RFC 3454 tables C.1.2, C.2.2, C.3–C.9 (nameprep's prohibited output).
    private static func prohibited(_ c: UInt32) -> Bool {
        switch c {
        // C.1.2 non-ASCII spaces
        case 0x00A0, 0x1680, 0x2000...0x200B, 0x202F, 0x205F, 0x3000: return true
        // C.2.2 non-ASCII controls
        case 0x0080...0x009F, 0x06DD, 0x070F, 0x180E, 0x200C, 0x200D, 0x2028, 0x2029, 0x2060...0x2063,
             0x206A...0x206F, 0xFEFF, 0xFFF9...0xFFFC, 0x1D173...0x1D17A: return true
        // C.3 private use, C.4 non-characters, C.5 surrogates, C.6 not for plain text, C.7 ideographic description
        case 0xE000...0xF8FF, 0xF0000...0xFFFFD, 0x100000...0x10FFFD: return true
        case 0xFDD0...0xFDEF, 0xFFFE, 0xFFFF: return true
        case 0xD800...0xDFFF: return true
        case 0xFFFD: return true
        case 0x2FF0...0x2FFB: return true
        // C.8 change display properties, C.9 tagging
        case 0x0340, 0x0341, 0x200E, 0x200F, 0x202A...0x202E: return true
        case 0xE0001, 0xE0020...0xE007F: return true
        default:
            return c & 0xFFFE == 0xFFFE // the last two code points of every plane
        }
    }

    /// RFC 3454 table D.1: characters with bidi property R or AL.
    private static func isRandAL(_ c: UInt32) -> Bool {
        switch c {
        case 0x05BE, 0x05C0, 0x05C3, 0x05D0...0x05EA, 0x05F0...0x05F4, 0x061B, 0x061F, 0x0621...0x063A,
             0x0640...0x064A, 0x066D...0x066F, 0x0671...0x06D5, 0x06DD, 0x06E5...0x06E6, 0x06FA...0x06FE,
             0x0700...0x070D, 0x0710, 0x0712...0x072C, 0x0780...0x07A5, 0x07B1, 0x200F, 0xFB1D,
             0xFB1F...0xFB28, 0xFB2A...0xFB36, 0xFB38...0xFB3C, 0xFB3E, 0xFB40...0xFB41, 0xFB43...0xFB44,
             0xFB46...0xFBB1, 0xFBD3...0xFD3D, 0xFD50...0xFD8F, 0xFD92...0xFDC7, 0xFDF0...0xFDFC,
             0xFE70...0xFE74, 0xFE76...0xFEFC:
            return true
        default:
            return false
        }
    }

    /// RFC 3454 table D.2 (bidi property L), approximated: a letter or a spacing mark of a left-to-right script.
    private static func isL(_ c: UInt32) -> Bool {
        guard !isRandAL(c), let s = Unicode.Scalar(c) else { return false }
        switch s.properties.generalCategory {
        case .uppercaseLetter, .lowercaseLetter, .titlecaseLetter, .modifierLetter, .otherLetter, .spacingMark: return true
        default: return false
        }
    }

    // ── punycode (RFC 3492) ───────────────────────────────────────────

    private static let base: UInt32 = 36, tMin: UInt32 = 1, tMax: UInt32 = 26
    private static let skew: UInt32 = 38, damp: UInt32 = 700, initialBias: UInt32 = 72, initialN: UInt32 = 128

    private static func adapt(_ delta0: UInt32, _ numPoints: UInt32, _ first: Bool) -> UInt32 {
        var delta = first ? delta0 / damp : delta0 / 2
        delta += delta / numPoints
        var k: UInt32 = 0
        while delta > ((base - tMin) * tMax) / 2 {
            delta /= base - tMin
            k += base
        }
        return k + (((base - tMin + 1) * delta) / (delta + skew))
    }

    private static func digit(_ d: UInt32) -> UInt16 {
        UInt16(d < 26 ? d + 0x61 : d - 26 + 0x30)
    }

    static func punycodeEncode(_ input: [UInt32]) throws -> U16 {
        var out = U16()
        for c in input where c < 0x80 { out.append(UInt16(c)) }
        let b = UInt32(out.count)
        var h = b
        if b > 0 { out.append(0x2D) }
        var n = initialN, delta: UInt32 = 0, bias = initialBias
        while h < UInt32(input.count) {
            var m = UInt32.max
            for c in input where c >= n && c < m { m = c }
            let (mul, o1) = (m - n).multipliedReportingOverflow(by: h + 1)
            let (sum, o2) = delta.addingReportingOverflow(mul)
            if o1 || o2 { throw Failure() }
            delta = sum
            n = m
            for c in input {
                if c < n {
                    delta += 1
                    if delta == 0 { throw Failure() }
                }
                if c == n {
                    var q = delta
                    var k = base
                    while true {
                        let t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias)
                        if q < t { break }
                        out.append(digit(t + (q - t) % (base - t)))
                        q = (q - t) / (base - t)
                        k += base
                    }
                    out.append(digit(q))
                    bias = adapt(delta, h + 1, h == b)
                    delta = 0
                    h += 1
                }
            }
            delta += 1
            n += 1
        }
        return out
    }

    static func punycodeDecode(_ input: U16) throws -> [UInt32] {
        var output: [UInt32] = []
        var n = initialN, i: UInt32 = 0, bias = initialBias
        var start = 0
        if let d = input.lastIndex(of: 0x2D) {
            for c in input[0..<d] {
                if c >= 0x80 { throw Failure() }
                output.append(UInt32(c))
            }
            start = d + 1
        }
        var j = start
        while j < input.count {
            let oldi = i
            var w: UInt32 = 1
            var k = base
            while true {
                if j >= input.count { throw Failure() }
                let c = input[j]
                j += 1
                let d: UInt32
                switch c {
                case 0x30...0x39: d = UInt32(c) - 0x30 + 26
                case 0x41...0x5A: d = UInt32(c) - 0x41
                case 0x61...0x7A: d = UInt32(c) - 0x61
                default: throw Failure()
                }
                let (dw, o1) = d.multipliedReportingOverflow(by: w)
                let (ni, o2) = i.addingReportingOverflow(dw)
                if o1 || o2 { throw Failure() }
                i = ni
                let t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias)
                if d < t { break }
                let (nw, o3) = w.multipliedReportingOverflow(by: base - t)
                if o3 { throw Failure() }
                w = nw
                k += base
            }
            let count = UInt32(output.count + 1)
            bias = adapt(i - oldi, count, oldi == 0)
            let (nn, o4) = n.addingReportingOverflow(i / count)
            if o4 { throw Failure() }
            n = nn
            i %= count
            if n > 0x10FFFF || (0xD800...0xDFFF).contains(n) { throw Failure() }
            output.insert(n, at: Int(i))
            i += 1
        }
        return output
    }
}
