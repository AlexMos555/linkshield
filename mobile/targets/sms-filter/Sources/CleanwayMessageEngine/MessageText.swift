import Foundation

// Swift twin of MessageText.kt: words of a message, normalised. See the Kotlin
// file for why (no \b regexes, one tokenisation, Unicode-safe by construction).

struct Word {
    /// The normalised word, plus its folded spellings when scripts were mixed.
    var forms: [U16]
    let sentence: Int
    let clause: Int
    let isNumber: Bool
    /// Mixed Latin/Cyrillic that folds into one script — a disguised word.
    let disguised: Bool
    /// Russian typed in Latin letters: forms carry its Cyrillic readings.
    var translit: Bool = false
}

/// One stem of a phrase: a prefix ("госуслуг*") or an exact word ("тел").
struct Stem {
    let text: U16
    let prefix: Bool
    private let hard: U16

    init(text: U16, prefix: Bool) {
        self.text = text
        self.prefix = prefix
        hard = text.filter { $0 != 0x44C && $0 != 0x44A } // ь ъ
    }

    func matches(_ word: Word) -> Bool {
        word.forms.contains { matches($0, text) } || (word.translit && hard != text && word.forms.contains { matches($0, hard) })
    }

    private func matches(_ form: U16, _ stem: U16) -> Bool { prefix ? form.hasPrefixU(stem) : form == stem }
}

/// A vocabulary entry: stems that must appear in order, at most `maxGap` words apart.
struct Phrase {
    static let maxGap = 1
    let stems: [Stem]

    static func parse(_ entry: U16) -> Phrase? {
        let stems = splitAsciiSpaces(jTrim(entry))
            .filter { !$0.isEmpty }
            .map { raw -> Stem in
                let prefix = raw.last == 0x2A
                var t = raw
                while t.last == 0x2A { t.removeLast() }
                return Stem(text: MessageText.normalizeWord(t), prefix: prefix)
            }
            .filter { !$0.text.isEmpty }
        return stems.isEmpty ? nil : Phrase(stems: stems)
    }
}

/// Where a phrase matched: word indices of its first and last stem.
struct Hit: Equatable {
    let start: Int
    let end: Int
}

final class WordIndex {
    let words: [Word]

    init(_ words: [Word]) { self.words = words }

    /// Every place `phrase` matches, left to right.
    func hits(_ phrase: Phrase) -> [Hit] {
        var out: [Hit] = []
        for i in words.indices {
            if !phrase.stems[0].matches(words[i]) { continue }
            guard let end = extend(phrase, i) else { continue }
            out.append(Hit(start: i, end: end))
        }
        return out
    }

    func hits(_ group: [Phrase]) -> [Hit] { stableSorted(group.flatMap { hits($0) }) { $0.start } }

    private func extend(_ phrase: Phrase, _ first: Int) -> Int? {
        var at = first
        for k in 1..<max(1, phrase.stems.count) where phrase.stems.count > 1 {
            let stem = phrase.stems[k]
            let limit = min(words.count - 1, at + 1 + Phrase.maxGap)
            var found = -1
            if at + 1 <= limit {
                for m in (at + 1)...limit where stem.matches(words[m]) { found = m; break }
            }
            if found < 0 { return nil }
            at = found
        }
        return at
    }

    func isWord(_ index: Int, _ set: Set<U16>) -> Bool {
        guard index >= 0 && index < words.count else { return false }
        return words[index].forms.contains { set.contains($0) }
    }

    func sameClause(_ a: Int, _ b: Int) -> Bool {
        a >= 0 && a < words.count && b >= 0 && b < words.count && words[a].clause == words[b].clause
    }

    func sameSentence(_ a: Int, _ b: Int) -> Bool {
        a >= 0 && a < words.count && b >= 0 && b < words.count && words[a].sentence == words[b].sentence
    }

    var disguised: Bool { words.contains { $0.disguised } }
}

enum MessageText {
    static let invisible: Set<UInt16> = [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x180E, 0x200E, 0x200F]
    private static let sentenceBreaks: Set<UInt16> = [0x2E, 0x21, 0x3F, 0x2026, 0x0A, 0x0D]
    private static let clauseBreaks: Set<UInt16> = [0x2C, 0x3B, 0x3A, 0x2014, 0x2013, 0x28, 0x29]
    private static let apostrophes: Set<UInt16> = [0x27, 0x2019, 0x2BC]

    /// Latin letters that look like Cyrillic ones, both cases.
    static let toCyrillic: [UInt16: UInt16] = {
        let pairs: [(Character, Character)] = [
            ("A", "А"), ("a", "а"), ("B", "В"), ("E", "Е"), ("e", "е"), ("K", "К"), ("k", "к"), ("M", "М"),
            ("H", "Н"), ("O", "О"), ("o", "о"), ("P", "Р"), ("p", "р"), ("C", "С"), ("c", "с"), ("T", "Т"),
            ("X", "Х"), ("x", "х"), ("Y", "У"), ("y", "у"),
        ]
        var m: [UInt16: UInt16] = [:]
        for (l, c) in pairs { m[l.utf16.first!] = c.utf16.first! }
        return m
    }()
    static let toLatin: [UInt16: UInt16] = {
        var m: [UInt16: UInt16] = [:]
        for (l, c) in toCyrillic { m[c] = l }
        return m
    }()

    /// Currency signs are not letters; spell them so "500 ₽" tokenises as an amount.
    static let currency: [UInt16: U16] = [0x20BD: u(" руб "), 0x24: u(" usd "), 0x20AC: u(" eur "), 0xA3: u(" gbp ")]

    struct Cleaned {
        let text: U16
        let hiddenInWord: Bool
    }

    /// Drop zero-width and bidi-control characters; one between two letters is a disguise.
    static func clean(_ text: U16) -> Cleaned {
        var hidden = false
        var sb = U16()
        sb.reserveCapacity(text.count)
        for (i, c) in text.enumerated() {
            if !invisible.contains(c) { sb.append(c); continue }
            if let last = sb.last, JChar.isLetter(last), let next = text.at(i + 1), JChar.isLetter(next) { hidden = true }
        }
        return Cleaned(text: sb, hiddenInWord: hidden)
    }

    static func normalizeWord(_ word: U16) -> U16 {
        jLowercase(word).map { $0 == 0x451 ? 0x435 : $0 } // ё → е
    }

    /// Distinct Russian-in-Latin function words a message needs before it is read as Russian.
    static let translitMinMarkers = 2

    static func index(_ text: U16, masked: [ClosedRange<Int>] = [], translitMarkers: Set<U16> = []) -> WordIndex {
        let words = split(text, masked)
        if translitMarkers.isEmpty || text.contains(where: isCyrillic) { return WordIndex(words) }
        var markers = Set<U16>()
        for w in words where translitMarkers.contains(w.forms[0]) { markers.insert(w.forms[0]) }
        if markers.count < translitMinMarkers { return WordIndex(words) }
        return WordIndex(words.map { w in
            let latin = w.forms[0]
            if w.isNumber || latin.contains(where: { !($0 >= 0x61 && $0 <= 0x7A) }) { return w }
            var copy = w
            copy.forms = distinctKeepingOrder(w.forms + Translit.readings(latin))
            copy.translit = true
            return copy
        })
    }

    private static func split(_ text: U16, _ masked: [ClosedRange<Int>]) -> [Word] {
        var words: [Word] = []
        words.reserveCapacity(text.count / 5 + 1)
        var sentence = 0
        var clause = 0
        var current = U16()
        func flush() {
            if !current.isEmpty {
                words.append(makeWord(current, sentence, clause))
                current.removeAll(keepingCapacity: true)
            }
        }
        var maskIdx = 0
        let sortedMasks = stableSorted(masked) { $0.lowerBound }
        for i in text.indices {
            while maskIdx < sortedMasks.count && sortedMasks[maskIdx].upperBound < i { maskIdx += 1 }
            let inMask = maskIdx < sortedMasks.count && sortedMasks[maskIdx].contains(i)
            let c: UInt16 = inMask ? 0x20 : text[i]
            if let spelled = currency[c] {
                flush()
                words.append(makeWord(jTrim(spelled), sentence, clause))
            } else if JChar.isLetterOrDigit(c) {
                current.append(c)
            } else if apostrophes.contains(c) && !current.isEmpty && (text.at(i + 1).map(JChar.isLetter) ?? false) {
                // dropped inside a word
            } else {
                flush()
                if sentenceBreaks.contains(c) {
                    sentence += 1
                    clause += 1
                } else if clauseBreaks.contains(c) || isSpacedDash(text, i) {
                    clause += 1
                }
            }
        }
        flush()
        return words
    }

    private static func isSpacedDash(_ text: U16, _ i: Int) -> Bool {
        text[i] == 0x2D && (text.at(i - 1).map(JChar.isWhitespace) ?? false) && (text.at(i + 1).map(JChar.isWhitespace) ?? false)
    }

    private static func makeWord(_ raw: U16, _ sentence: Int, _ clause: Int) -> Word {
        let base = normalizeWord(raw)
        let isNumber = base.allSatisfy(JChar.isDigit)
        let hasLatin = raw.contains { ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x41 && $0 <= 0x5A) }
        let hasCyrillic = raw.contains(where: isCyrillic)
        if !(hasLatin && hasCyrillic) {
            return Word(forms: [base], sentence: sentence, clause: clause, isNumber: isNumber, disguised: false)
        }
        let cyr = normalizeWord(raw.map { toCyrillic[$0] ?? $0 })
        let lat = normalizeWord(raw.map { toLatin[$0] ?? $0 })
        let disguised = !cyr.contains { $0 >= 0x61 && $0 <= 0x7A } || !lat.contains(where: isCyrillic)
        return Word(forms: distinctKeepingOrder([base, cyr, lat]), sentence: sentence, clause: clause, isNumber: isNumber, disguised: disguised)
    }

    @inline(__always) static func isCyrillic(_ c: UInt16) -> Bool { c >= 0x400 && c <= 0x4FF }
}

/// Russian typed in Latin letters, read back into Cyrillic (MessageText.kt's Translit).
enum Translit {
    private static let maxLength = 32
    private static let vowels: Set<UInt16> = Set(u("аеиоуыэюя"))

    /// Longest first, so "shch" wins over "sh" and "sh" over "s".
    private static let table: [(U16, [U16])] = [
        ("shch", ["щ"]), ("sch", ["сч", "щ"]),
        ("zh", ["ж"]), ("kh", ["х"]), ("ch", ["ч"]), ("sh", ["ш", "щ"]),
        ("ts", ["ц", "тс"]), ("tz", ["ц"]),
        ("yu", ["ю"]), ("ju", ["ю"]), ("ya", ["я"]), ("ja", ["я"]),
        ("yo", ["е"]), ("jo", ["е"]), ("ye", ["е"]), ("je", ["е"]),
        ("ck", ["к"]), ("ph", ["ф"]),
        ("a", ["а"]), ("b", ["б"]), ("c", ["ц"]), ("d", ["д"]), ("e", ["е"]),
        ("f", ["ф"]), ("g", ["г"]), ("h", ["х"]), ("i", ["и"]), ("j", ["й"]),
        ("k", ["к"]), ("l", ["л"]), ("m", ["м"]), ("n", ["н"]), ("o", ["о"]),
        ("p", ["п"]), ("q", ["к"]), ("r", ["р"]), ("s", ["с"]), ("t", ["т"]),
        ("u", ["у"]), ("v", ["в"]), ("w", ["в"]), ("x", ["кс"]), ("z", ["з"]),
    ].map { (u($0.0), $0.1.map(u)) }

    private static func options(_ key: U16) -> [U16]? { table.first { $0.0 == key }?.1 }

    /// The Cyrillic readings of a lowercase Latin word; empty for anything else.
    static func readings(_ word: U16) -> [U16] {
        if word.isEmpty || word.count > maxLength || word.contains(where: { !($0 >= 0x61 && $0 <= 0x7A) }) { return [] }
        var keys: [U16] = []
        var i = 0
        while i < word.count {
            let key = table.first { word.hasPrefixU($0.0, at: i) }?.0 ?? [word[i]]
            keys.append(key)
            i += key.count
        }
        let ambiguous = distinctKeepingOrder(keys.filter { (options($0)?.count ?? 0) > 1 })
        let firstE = keys.first == u("e")
        var out: [U16] = []
        var seen = Set<U16>()
        let combos = 1 << (ambiguous.count + (firstE ? 1 : 0))
        for mask in 0..<combos {
            var sb = U16()
            for (n, k) in keys.enumerated() {
                if n == 0 && firstE {
                    sb.append(mask & 1 == 0 ? 0x435 : 0x44D) // е / э
                } else if k == u("y") {
                    sb.append(sb.last.map { vowels.contains($0) } == true ? 0x439 : 0x44B) // й / ы
                } else {
                    let opts = options(k)!
                    let bit = ambiguous.firstIndex(of: k).map { $0 + (firstE ? 1 : 0) }
                    sb += (bit == nil || mask & (1 << bit!) == 0) ? opts[0] : opts[1]
                }
            }
            if seen.insert(sb).inserted { out.append(sb) }
        }
        return out
    }
}
