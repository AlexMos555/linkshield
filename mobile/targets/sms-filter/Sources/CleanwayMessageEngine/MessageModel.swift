import Foundation

/// The on-device text model — the Swift twin of MessageModel.kt (logistic
/// regression over hashed char n-grams and word uni/bigrams, trained in
/// ml/sms). Same normalisation tables, same FNV-1a + fmix32 hashing over
/// UTF-16 code units, same float16 weights from message_model.bin.
///
/// Memory: the 512 KB weight table is kept as the file's own bytes (memory
/// mapped when it comes from disk) and each float16 is widened when read, so
/// a message filter extension does not pay for a 1 MB Float copy.
public final class MessageModel {
    private let weights: Data
    private let dim: Int
    private let bias: Double
    private let nMin: Int
    private let nMax: Int
    private let charWeight: Double
    private let wordWeight: Double
    private let charFloor: Int
    private let wordFloor: Int
    private let maxChars: Int
    public let minWords: Int
    public let cautionThreshold: Double
    public let dangerThreshold: Double
    private let official: Set<U16>
    private let shorteners: Set<U16>
    private let messengers: Set<U16>
    private let cyrillicTlds: Set<U16>
    private let translitMarkers: Set<U16>

    public struct ParseError: Error {
        public let what: String
    }

    /// The model from its two assets; throws on anything malformed (the caller then runs the rules alone).
    public init(json: Data, weights bytes: Data) throws {
        guard let meta = try JSONSerialization.jsonObject(with: json) as? [String: Any] else { throw ParseError(what: "json") }
        func num(_ o: [String: Any]?, _ k: String) throws -> Double {
            guard let v = o?[k] as? NSNumber else { throw ParseError(what: k) }
            return v.doubleValue
        }
        func strs(_ o: [String: Any]?, _ k: String) throws -> Set<U16> {
            guard let a = o?[k] as? [String] else { throw ParseError(what: k) }
            return Set(a.map(u))
        }
        guard try num(meta, "version") == 1 else { throw ParseError(what: "model version") }
        let hash = meta["hash"] as? [String: Any]
        let dim = Int(try num(hash, "dim"))
        guard dim > 0 && dim & (dim - 1) == 0 else { throw ParseError(what: "dim must be a power of two") }
        guard bytes.count == 12 + 2 * dim else { throw ParseError(what: "weights size") }
        let header = [UInt8](bytes.prefix(12))
        guard header[0] == 0x43, header[1] == 0x57, header[2] == 0x53, header[3] == 0x4D else { throw ParseError(what: "weights magic") }
        func u32(_ at: Int) -> Int { Int(header[at]) | Int(header[at + 1]) << 8 | Int(header[at + 2]) << 16 | Int(header[at + 3]) << 24 }
        guard u32(4) == 1 && u32(8) == dim else { throw ParseError(what: "weights header") }
        guard let ngrams = hash?["char_ngrams"] as? [NSNumber], ngrams.count >= 2 else { throw ParseError(what: "char_ngrams") }
        let thresholds = meta["thresholds"] as? [String: Any]
        let norm = meta["normaliser"] as? [String: Any]
        weights = bytes
        self.dim = dim
        bias = try num(meta, "bias")
        nMin = ngrams[0].intValue
        nMax = ngrams[1].intValue
        charWeight = try num(hash, "char_weight")
        wordWeight = try num(hash, "word_weight")
        charFloor = Int(try num(hash, "char_floor"))
        wordFloor = Int(try num(hash, "word_floor"))
        maxChars = Int(try num(meta, "max_chars"))
        minWords = Int(try num(meta, "min_words"))
        cautionThreshold = try num(thresholds, "caution")
        dangerThreshold = try num(thresholds, "dangerous_with_ingredient")
        official = try strs(norm, "official")
        shorteners = try strs(norm, "shorteners")
        messengers = try strs(norm, "messengers")
        cyrillicTlds = try strs(norm, "cyrillic_tlds")
        translitMarkers = try strs(norm, "translit_markers")
    }

    /// The probability that `text` is a scam, by its words alone; nil when it has fewer than minWords words.
    public func score(_ text: String) -> Double? { score(u(text)) }

    func score(_ text: U16) -> Double? {
        let f = featureHashes(text)
        return f.words < minWords ? nil : probability(f)
    }

    /// The probability whatever the length (the parity tests compare it with Kotlin's).
    public func probability(_ text: String) -> Double { probability(featureHashes(u(text))) }

    private func probability(_ f: Features) -> Double {
        var z = bias
        let mask = UInt32(dim - 1)
        weights.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            for (block, weight, floor) in [(f.chars, charWeight, charFloor), (f.grams, wordWeight, wordFloor)] {
                if block.isEmpty { continue }
                let v = weight / Double(max(block.count, floor)).squareRoot()
                var sum = 0.0
                block.forEach { k in
                    let at = 12 + 2 * Int(k & mask)
                    let bits = UInt16(raw[at]) | UInt16(raw[at + 1]) << 8
                    sum += Double(Self.halfToFloat(bits))
                }
                z += v * sum
            }
        }
        return 1.0 / (1.0 + exp(-z))
    }

    /// IEEE 754 binary16 → float, exactly as MessageModel.halfToFloat (Float16 is not on Intel Macs).
    static func halfToFloat(_ bits: UInt16) -> Float {
        let sign: Float = bits & 0x8000 != 0 ? -1 : 1
        let exponent = UInt32(bits >> 10) & 0x1F
        let mantissa = UInt32(bits) & 0x3FF
        switch exponent {
        case 0: return sign * Float(mantissa) * 5.9604645E-8
        case 0x1F: return mantissa == 0 ? sign * Float.infinity : Float.nan
        default: return Float(bitPattern: (UInt32(bits & 0x8000) << 16) | ((exponent + 112) << 23) | (mantissa << 13))
        }
    }

    // ── features ──────────────────────────────────────────────────────

    private struct Features {
        let chars: IntSet
        let grams: IntSet
        let words: Int
    }

    private func featureHashes(_ text: U16) -> Features {
        let (tokens, translit) = tokenize(text)
        let chars = IntSet()
        let words = IntSet()
        for stream in [tokens, translit].compactMap({ $0 }) {
            var prev: U16?
            for t in stream {
                words.add(Self.fmix(Self.feed(Self.hw, t)))
                if let p = prev { words.add(Self.fmix(Self.feed(Self.feed(Self.feed(Self.hb, p), 0x20), t))) }
                prev = t
                if t[0] == 0x5F { continue }
                let padded: U16 = [0x20] + t + [0x20]
                for a in padded.indices {
                    var h = Self.hc
                    let end = min(padded.count, a + nMax)
                    for b in a..<end {
                        h = Self.feed(h, padded[b])
                        if b - a + 1 >= nMin { chars.add(Self.fmix(h)) }
                    }
                }
            }
        }
        return Features(chars: chars, grams: words, words: tokens.filter { $0[0] != 0x5F }.count)
    }

    // ── normalisation (features.py, step by step) ─────────────────────

    /// Step 1: the first maxChars code points, invisible ones dropped, emoji → U+FFFD, currency spelled, lowercase.
    func prepare(_ text: U16) -> U16 {
        var sb = U16()
        sb.reserveCapacity(min(text.count, maxChars) + 16)
        var i = 0
        var points = 0
        while i < text.count && points < maxChars {
            let c = text[i]
            if c >= 0xD800 && c <= 0xDBFF && i + 1 < text.count && text[i + 1] >= 0xDC00 && text[i + 1] <= 0xDFFF {
                i += 2
                points += 1
                sb.append(0xFFFD)
                continue
            }
            i += 1
            points += 1
            if Self.invisible.contains(c) { continue }
            if let spelled = Self.currency[c] { sb += spelled } else { sb.append(Self.lowerChar(c)) }
        }
        return sb
    }

    private enum Item {
        case word(text: U16, raw: U16, start: Int, end: Int, number: Bool)
        case special(U16)
    }

    /// Steps 2-5: the tokens, and their Cyrillic reading when the message is Russian typed in Latin.
    func tokenize(_ text: U16) -> ([U16], [U16]?) {
        let s = prepare(text)
        let n = s.count
        var items: [Item] = []
        items.reserveCapacity(n / 5 + 4)
        var mixed = false
        var i = 0
        while i < n {
            if Self.whitespace.contains(s[i]) { i += 1; continue }
            var j = i
            while j < n && !Self.whitespace.contains(s[j]) { j += 1 }
            let chunk = Self.stripChunk(s.sub(i, j))
            var special: [U16]?
            if !chunk.isEmpty {
                special = urlTokens(chunk)
                if special == nil, let at = chunk.firstIndex(of: 0x40) {
                    if at == 0 && chunk.count > 2 { special = [u("_handle")] }
                    else if at > 0 && chunk[(at + 1)...].contains(0x2E) { special = [u("_email")] }
                }
            }
            if let sp = special {
                items += sp.map { .special($0) }
            } else {
                var k = i
                while k < j {
                    if !Self.isWordChar(s[k]) { k += 1; continue }
                    var m = k
                    var buf = U16()
                    while m < j {
                        let c = s[m]
                        if Self.isWordChar(c) { buf.append(c); m += 1 }
                        else if Self.apostrophes.contains(c) && !buf.isEmpty && m + 1 < j && Self.isLetter(s[m + 1]) { m += 1 }
                        else { break }
                    }
                    if Self.maskRun(buf) {
                        items.append(.word(text: U16(repeating: 0x30, count: buf.count), raw: buf, start: k, end: m, number: true))
                    } else {
                        for part in splitChars(buf, [0x2A]) where !part.isEmpty {
                            let (folded, wasMixed) = Self.foldWord(part)
                            mixed = mixed || wasMixed
                            let zeroed = folded.map { Self.isDigit($0) ? 0x30 : $0 }
                            items.append(.word(text: zeroed, raw: part, start: k, end: m, number: false))
                        }
                    }
                    k = m
                }
            }
            i = j
        }
        var tokens: [U16] = []
        tokens.reserveCapacity(items.count + 2)
        var k = 0
        while k < items.count {
            guard case let .word(wText, wRaw, wStart, _, wNumber) = items[k] else {
                if case let .special(t) = items[k] { tokens.append(t) }
                k += 1
                continue
            }
            if !wNumber { tokens.append(wText); k += 1; continue }
            var m = k
            var digits = wText.count
            while m + 1 < items.count {
                guard case let .word(nText, _, nStart, _, nNumber) = items[m + 1], nNumber else { break }
                guard case let .word(_, _, _, pEnd, _) = items[m] else { break }
                let gap = s.sub(pEnd, nStart)
                if gap.isEmpty || gap.count > 3 || gap.contains(where: { !Self.phoneGap.contains($0) }) { break }
                m += 1
                digits += nText.count
            }
            let plus = wStart > 0 && s[wStart - 1] == 0x2B
            let first = wRaw[0]
            if digits >= 10 && digits <= 12 && (plus || first == 0x37 || first == 0x38 || first == 0x39 || Self.mask.contains(first)) {
                tokens.append(u("_phone"))
            } else if digits >= 13 && digits <= 19 && m > k {
                tokens.append(u("_card"))
            } else {
                for q in k...m { if case let .word(t, _, _, _, _) = items[q] { tokens.append(t) } }
            }
            k = m + 1
        }
        if s.contains(0x21) { tokens.append(u("_excl")) }
        if mixed { tokens.append(u("_mixscript")) }
        var translit: [U16]?
        if !s.contains(where: Self.isCyrillic) {
            var markers = Set<U16>()
            for t in tokens where translitMarkers.contains(t) { markers.insert(t) }
            if markers.count >= Self.translitMinMarkers {
                translit = tokens.map { t in t[0] != 0x5F && t.allSatisfy(Self.isLatin) ? Self.reading(t) : t }
            }
        }
        return (tokens, translit)
    }

    /// A URL's tokens — its class and TLD, never its words — or nil when `chunk` is not a link.
    private func urlTokens(_ chunk: U16) -> [U16]? {
        var rest = chunk
        var scheme = false
        for prefix in Self.schemes where rest.hasPrefixU(prefix) {
            rest = rest.sub(prefix.count, rest.count)
            scheme = true
            break
        }
        if rest.hasPrefixU(u("www.")) { scheme = true }
        if !scheme && rest.contains(0x40) { return nil }
        let end = rest.firstIndex { $0 == 0x2F || $0 == 0x3F || $0 == 0x23 } ?? rest.count
        var host = rest.sub(0, end)
        let path = rest.sub(end, rest.count)
        if let colon = host.firstIndex(of: 0x3A) { host = host.sub(0, colon) }
        let labels = splitChars(host, [0x2E])
        if !scheme && path.isEmpty && labels.count >= 2 && Self.fileExtensions.contains(labels[labels.count - 1]) && !labels[labels.count - 2].isEmpty {
            return [labels[labels.count - 1] == u("apk") ? u("_apk") : u("_file")]
        }
        if labels.count < 2 || !labels.allSatisfy(Self.hostLabelOk) { return nil }
        let tld = labels[labels.count - 1]
        let ip = labels.count == 4 && labels.allSatisfy { l in l.allSatisfy(Self.isDigit) && l.count <= 3 }
        let nameLabels = labels.dropLast()
        let nameLatin = nameLabels.contains { $0.contains(where: Self.isLatin) }
        let nameCyrillic = nameLabels.contains { $0.contains(where: Self.isCyrillic) }
        if !ip {
            if !scheme {
                let name = labels[labels.count - 2]
                if tld.allSatisfy(Self.isCyrillic) {
                    if !cyrillicTlds.contains(tld) || !name.contains(where: Self.isCyrillic) { return nil }
                } else if tld.allSatisfy(Self.isLatin) {
                    if tld.count < 2 || name.allSatisfy(Self.isDigit) { return nil }
                    if !nameLatin && path.first != 0x2F { return nil }
                } else {
                    return nil
                }
            } else if !tld.contains(where: Self.isLetter) {
                return nil
            }
        } else if !scheme && path.first != 0x2F {
            return nil
        }
        var out = [u("_url")]
        if ip {
            out.append(u("_url_ip"))
        } else {
            if HostNames.under(host, official) { out.append(u("_url_off")) }
            else if HostNames.under(host, shorteners) { out.append(u("_url_short")) }
            else if HostNames.under(host, messengers) { out.append(u("_url_msgr")) }
            else { out.append(u("_url_unk")) }
            out.append(u("_tld_") + tld)
            if nameCyrillic && (nameLatin || tld.allSatisfy(Self.isLatin)) { out.append(u("_url_mixed")) }
        }
        let q = path.firstIndex { $0 == 0x3F || $0 == 0x23 } ?? path.count
        if path.sub(0, q).hasSuffixU(u(".apk")) { out.append(u("_apk")) }
        return out
    }

    // ── hashing ───────────────────────────────────────────────────────

    private static let fnvOffset: UInt32 = 0x811C_9DC5
    private static let fnvPrime: UInt32 = 0x0100_0193

    @inline(__always) static func feed(_ h0: UInt32, _ c: UInt16) -> UInt32 {
        let o = UInt32(c)
        var h = (h0 ^ (o & 0xFF)) &* fnvPrime
        h = (h ^ (o >> 8)) &* fnvPrime
        return h
    }

    static func feed(_ h0: UInt32, _ s: U16) -> UInt32 {
        var h = h0
        for c in s { h = feed(h, c) }
        return h
    }

    @inline(__always) static func fmix(_ h0: UInt32) -> UInt32 {
        var h = h0
        h ^= h >> 16
        h = h &* 0x85EB_CA6B
        h ^= h >> 13
        h = h &* 0xC2B2_AE35
        h ^= h >> 16
        return h
    }

    private static let hw = feed(fnvOffset, 0x77) // 'w'
    private static let hb = feed(fnvOffset, 0x62) // 'b'
    private static let hc = feed(fnvOffset, 0x63) // 'c'

    // ── character tables (features.py) ────────────────────────────────

    private static let invisible: Set<UInt16> = [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x180E, 0x200E, 0x200F]
    private static let whitespace: Set<UInt16> = Set([
        0x20, 0x09, 0x0A, 0x0D, 0x0B, 0x0C, 0xA0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006,
        0x2007, 0x2008, 0x2009, 0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
    ])
    private static let lead: Set<UInt16> = Set(u("([{<\"'«„“‘"))
    private static let trail: Set<UInt16> = Set(u(".,;:!?)]}>\"'»”’…"))
    private static let apostrophes: Set<UInt16> = [0x27, 0x2019, 0x2BC]
    private static let mask: Set<UInt16> = Set(u("xх*n"))
    private static let phoneGap: Set<UInt16> = Set(u(" -(). ")).union([0xA0])
    private static let schemes: [U16] = [u("https://"), u("http://")]
    private static let fileExtensions: Set<U16> = Set(
        ["apk", "pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "rtf", "rar", "mp3", "mp4"].map(u)
    )
    private static let currency: [UInt16: U16] = [0x20BD: u(" руб "), 0x24: u(" usd "), 0x20AC: u(" eur "), 0xA3: u(" gbp ")]
    private static let toCyrillic: [UInt16: UInt16] = {
        let pairs: [(Character, Character)] = [
            ("a", "а"), ("b", "в"), ("c", "с"), ("e", "е"), ("h", "н"), ("k", "к"), ("m", "м"), ("o", "о"),
            ("p", "р"), ("t", "т"), ("x", "х"), ("y", "у"),
        ]
        var m: [UInt16: UInt16] = [:]
        for (l, c) in pairs { m[l.utf16.first!] = c.utf16.first! }
        return m
    }()
    private static let toLatin: [UInt16: UInt16] = {
        var m: [UInt16: UInt16] = [:]
        for (l, c) in toCyrillic { m[c] = l }
        return m
    }()
    private static let vowels: Set<UInt16> = Set(u("аеиоуыэюя"))
    private static let translitMaxLength = 32
    private static let translitMinMarkers = 2

    /// MessageText's Translit table; the model takes its first reading only.
    private static let translitTable: [(U16, U16)] = [
        ("shch", "щ"), ("sch", "сч"), ("zh", "ж"), ("kh", "х"), ("ch", "ч"), ("sh", "ш"), ("ts", "ц"), ("tz", "ц"),
        ("yu", "ю"), ("ju", "ю"), ("ya", "я"), ("ja", "я"), ("yo", "е"), ("jo", "е"), ("ye", "е"), ("je", "е"),
        ("ck", "к"), ("ph", "ф"),
        ("a", "а"), ("b", "б"), ("c", "ц"), ("d", "д"), ("e", "е"), ("f", "ф"), ("g", "г"), ("h", "х"), ("i", "и"),
        ("j", "й"), ("k", "к"), ("l", "л"), ("m", "м"), ("n", "н"), ("o", "о"), ("p", "п"), ("q", "к"), ("r", "р"),
        ("s", "с"), ("t", "т"), ("u", "у"), ("v", "в"), ("w", "в"), ("x", "кс"), ("z", "з"),
    ].map { (u($0.0), u($0.1)) }

    @inline(__always) static func isLatin(_ c: UInt16) -> Bool { c >= 0x61 && c <= 0x7A }
    @inline(__always) static func isCyrillic(_ c: UInt16) -> Bool { (c >= 0x430 && c <= 0x44F) || (c >= 0x450 && c <= 0x45F) }
    @inline(__always) static func isDigit(_ c: UInt16) -> Bool { c >= 0x30 && c <= 0x39 }
    @inline(__always) static func isLetter(_ c: UInt16) -> Bool { isLatin(c) || isCyrillic(c) }
    @inline(__always) static func isWordChar(_ c: UInt16) -> Bool { isLetter(c) || isDigit(c) || c == 0x2A }

    static func lowerChar(_ c: UInt16) -> UInt16 {
        if (c >= 0x41 && c <= 0x5A) || (c >= 0x410 && c <= 0x42F) { return c + 32 }
        if c == 0x401 || c == 0x451 { return 0x435 }
        if c >= 0x400 && c <= 0x40F { return c + 0x50 }
        return c
    }

    private static func stripChunk(_ chunk: U16) -> U16 {
        var s = 0
        var e = chunk.count
        while s < e && lead.contains(chunk[s]) { s += 1 }
        while e > s && trail.contains(chunk[e - 1]) { e -= 1 }
        return chunk.sub(s, e)
    }

    private static func hostLabelOk(_ label: U16) -> Bool {
        !label.isEmpty && label.allSatisfy { isLatin($0) || isDigit($0) || $0 == 0x2D || isCyrillic($0) }
    }

    /// XXX, ***, 9**, NN, 2200: a number, possibly masked.
    private static func maskRun(_ run: U16) -> Bool {
        if !run.allSatisfy({ isDigit($0) || mask.contains($0) }) { return false }
        if run.contains(where: isDigit) { return true }
        return run.count >= 2
    }

    /// A word mixing Latin and Cyrillic letters, folded into the script it imitates.
    private static func foldWord(_ w: U16) -> (U16, Bool) {
        if !(w.contains(where: isLatin) && w.contains(where: isCyrillic)) { return (w, false) }
        let cyr = w.map { toCyrillic[$0] ?? $0 }
        if !cyr.contains(where: isLatin) { return (cyr, true) }
        let lat = w.map { toLatin[$0] ?? $0 }
        if !lat.contains(where: isCyrillic) { return (lat, true) }
        return (w, true)
    }

    /// The first Cyrillic reading of a Latin word.
    static func reading(_ word: U16) -> U16 {
        if word.isEmpty || word.count > translitMaxLength || word.contains(where: { !isLatin($0) }) { return word }
        var sb = U16()
        var i = 0
        while i < word.count {
            if let hit = translitTable.first(where: { word.hasPrefixU($0.0, at: i) }) {
                sb += hit.1
                i += hit.0.count
            } else {
                sb.append(sb.last.map { vowels.contains($0) } == true ? 0x439 : 0x44B)
                i += 1
            }
        }
        return sb
    }
}

/// MessageModel.kt's IntSet, bit for bit: the same open addressing, spread and
/// growth, so the weights are summed in the same order and the floating-point
/// sum — and so the probability — is identical to Kotlin's.
final class IntSet {
    private var keys = [UInt32](repeating: 0, count: 256)
    private var used = [Bool](repeating: false, count: 256)
    private(set) var count = 0

    var isEmpty: Bool { count == 0 }

    func add(_ k: UInt32) {
        if 2 * (count + 1) > keys.count { grow() }
        let m = UInt32(keys.count - 1)
        var i = Int(Self.spread(k) & m)
        while used[i] {
            if keys[i] == k { return }
            i = (i + 1) & Int(m)
        }
        used[i] = true
        keys[i] = k
        count += 1
    }

    func forEach(_ body: (UInt32) -> Void) {
        for j in 0..<keys.count where used[j] { body(keys[j]) }
    }

    @inline(__always) private static func spread(_ k: UInt32) -> UInt32 { k &* 0x9E37_79B9 } // k * -0x61c88647

    private func grow() {
        let oldKeys = keys
        let oldUsed = used
        keys = [UInt32](repeating: 0, count: oldKeys.count * 2)
        used = [Bool](repeating: false, count: oldKeys.count * 2)
        count = 0
        for j in oldKeys.indices where oldUsed[j] { add(oldKeys[j]) }
    }
}
