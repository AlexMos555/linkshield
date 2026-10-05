package ai.cleanway.app

import java.util.Locale

/**
 * Words of a message, normalised for the on-device message check.
 *
 * Why not regexes with \b: a JVM word boundary without UNICODE_CHARACTER_CLASS
 * treats every Cyrillic letter as a non-word character, so a Russian stem
 * would match from the middle of a word (the same trap test-host-parser.mjs
 * caught in host.ts). Tokenising into letter/digit runs once, then comparing
 * stems word by word, is Unicode-safe by construction and linear in the
 * message length — no pattern can backtrack.
 *
 * Normalisation, once per word:
 *  - lowercase (Locale.ROOT) and ё → е, so the vocabulary is written once;
 *  - apostrophes inside a word are dropped ("don't" → "dont");
 *  - a word that mixes Latin and Cyrillic letters is folded both ways
 *    ("Гoсуслуги" with a Latin o reads as "госуслуги"). Scammers mix
 *    scripts to slip past operator filters; a real sender never does;
 *  - in a message written wholly in Latin letters that reads as Russian
 *    ("vash akkaunt vzloman, srochno pozvonite"), each Latin word also gets
 *    its Cyrillic readings ([Translit]), so the Russian vocabulary applies.
 *
 * Pure Kotlin: no Android types, JVM-testable.
 */
internal data class Word(
    /** The normalised word, plus its folded spellings when scripts were mixed. */
    val forms: List<String>,
    val sentence: Int,
    val clause: Int,
    val isNumber: Boolean,
    /** Mixed Latin/Cyrillic that folds into one script — a disguised word. */
    val disguised: Boolean,
    /** Russian typed in Latin letters: [forms] carry its Cyrillic readings, which have no soft or hard sign. */
    val translit: Boolean = false,
)

/** One stem of a phrase: a prefix ("госуслуг*") or an exact word ("тел"). */
internal data class Stem(val text: String, val prefix: Boolean) {
    /** The stem as a Latin-typed word reads back: "деньг" from "dengi" (the apostrophe of "den'gi" is dropped). */
    private val hard = text.filterNot { it == 'ь' || it == 'ъ' }

    fun matches(word: Word): Boolean =
        word.forms.any { matches(it, text) } || (word.translit && hard != text && word.forms.any { matches(it, hard) })

    private fun matches(form: String, stem: String): Boolean = if (prefix) form.startsWith(stem) else form == stem
}

/** A vocabulary entry: stems that must appear in order, at most [MAX_GAP] words apart. */
internal data class Phrase(val stems: List<Stem>) {
    companion object {
        const val MAX_GAP = 1

        fun parse(entry: String): Phrase? {
            val stems = entry.trim().split(Regex("\\s+"))
                .filter { it.isNotEmpty() }
                .map { raw ->
                    val prefix = raw.endsWith("*")
                    Stem(MessageText.normalizeWord(raw.trimEnd('*')), prefix)
                }
                .filter { it.text.isNotEmpty() }
            return if (stems.isEmpty()) null else Phrase(stems)
        }
    }
}

/** Where a phrase matched: word indices of its first and last stem. */
internal data class Hit(val start: Int, val end: Int)

internal class WordIndex(val words: List<Word>) {

    /** Every place [phrase] matches, left to right. */
    fun hits(phrase: Phrase): List<Hit> {
        val out = ArrayList<Hit>(2)
        for (i in words.indices) {
            if (!phrase.stems[0].matches(words[i])) continue
            val end = extend(phrase, i) ?: continue
            out += Hit(i, end)
        }
        return out
    }

    fun hits(group: List<Phrase>): List<Hit> = group.flatMap { hits(it) }.sortedBy { it.start }

    fun any(group: List<Phrase>): Boolean = group.any { hits(it).isNotEmpty() }

    private fun extend(phrase: Phrase, first: Int): Int? {
        var at = first
        for (k in 1 until phrase.stems.size) {
            val stem = phrase.stems[k]
            val limit = minOf(words.size - 1, at + 1 + Phrase.MAX_GAP)
            var found = -1
            for (m in at + 1..limit) {
                if (stem.matches(words[m])) { found = m; break }
            }
            if (found < 0) return null
            at = found
        }
        return at
    }

    fun isWord(index: Int, set: Set<String>): Boolean =
        words.getOrNull(index)?.forms?.any { it in set } == true

    fun sameClause(a: Int, b: Int): Boolean =
        a in words.indices && b in words.indices && words[a].clause == words[b].clause

    fun sameSentence(a: Int, b: Int): Boolean =
        a in words.indices && b in words.indices && words[a].sentence == words[b].sentence

    val disguised: Boolean get() = words.any { it.disguised }
}

internal object MessageText {
    private val INVISIBLE = setOf(
        '​', '‌', '‍', '⁠', '﻿', '­', '᠎', '‎', '‏',
    )
    private val SENTENCE_BREAKS = setOf('.', '!', '?', '…', '\n', '\r')
    // Quotes mark a name, not a new clause: in "не переводите на «безопасный
    // счёт»" the "не" still governs the quoted words.
    private val CLAUSE_BREAKS = setOf(',', ';', ':', '—', '–', '(', ')')
    private val APOSTROPHES = setOf('\'', '’', 'ʼ')

    /** Latin letters that look like Cyrillic ones, both cases. */
    private val TO_CYRILLIC = mapOf(
        'A' to 'А', 'a' to 'а', 'B' to 'В', 'E' to 'Е', 'e' to 'е', 'K' to 'К', 'k' to 'к', 'M' to 'М',
        'H' to 'Н', 'O' to 'О', 'o' to 'о', 'P' to 'Р', 'p' to 'р', 'C' to 'С', 'c' to 'с', 'T' to 'Т',
        'X' to 'Х', 'x' to 'х', 'Y' to 'У', 'y' to 'у',
    )
    private val TO_LATIN: Map<Char, Char> = TO_CYRILLIC.entries.associate { (lat, cyr) -> cyr to lat }

    /** Currency signs are not letters; spell them so "500 ₽" tokenises as an amount. */
    private val CURRENCY = mapOf('₽' to " руб ", '$' to " usd ", '€' to " eur ", '£' to " gbp ")

    /** [hiddenInWord]: an invisible character sat between two letters. */
    data class Cleaned(val text: String, val hiddenInWord: Boolean)

    /**
     * Drop zero-width and bidi-control characters. "Гос​услуги" renders
     * as "Госуслуги" on the phone, but would never match a stem, and a link
     * split the same way would never match the blocklist.
     *
     * Only one hidden INSIDE a word counts as disguise: text pasted from a
     * messenger routinely starts with a byte-order mark, and Arabic text
     * carries direction marks between words.
     */
    fun clean(text: String): Cleaned {
        var hidden = false
        val sb = StringBuilder(text.length)
        for ((i, c) in text.withIndex()) {
            if (c !in INVISIBLE) { sb.append(c); continue }
            if (sb.lastOrNull()?.isLetter() == true && text.getOrNull(i + 1)?.isLetter() == true) hidden = true
        }
        return Cleaned(sb.toString(), hidden)
    }

    fun normalizeWord(word: String): String =
        word.lowercase(Locale.ROOT).replace('ё', 'е')

    /**
     * Split [text] into words. Characters inside [masked] (the links, already
     * judged on their own) are read as spaces: "…/login-verify" must not
     * count as a message asking the reader to log in.
     *
     * A message with no Cyrillic letter and at least [TRANSLIT_MIN_MARKERS]
     * distinct words from [translitMarkers] ("vash", "srochno", "dlya"…) is
     * Russian typed in Latin letters: its Latin words also get their Cyrillic
     * readings. English never reaches that many of them, so an English
     * message is read exactly as before.
     */
    fun index(text: String, masked: List<IntRange> = emptyList(), translitMarkers: Set<String> = emptySet()): WordIndex {
        val words = split(text, masked)
        if (translitMarkers.isEmpty() || text.any { isCyrillic(it) }) return WordIndex(words)
        val markers = words.mapNotNullTo(HashSet()) { w -> w.forms[0].takeIf { it in translitMarkers } }
        if (markers.size < TRANSLIT_MIN_MARKERS) return WordIndex(words)
        return WordIndex(
            words.map { w ->
                val latin = w.forms[0]
                if (w.isNumber || latin.any { it !in 'a'..'z' }) w
                else w.copy(forms = (w.forms + Translit.readings(latin)).distinct(), translit = true)
            },
        )
    }

    /** Distinct Russian-in-Latin function words a message needs before it is read as Russian. */
    const val TRANSLIT_MIN_MARKERS = 2

    private fun split(text: String, masked: List<IntRange>): List<Word> {
        val words = ArrayList<Word>(text.length / 5 + 1)
        var sentence = 0
        var clause = 0
        val current = StringBuilder()
        fun flush() {
            if (current.isNotEmpty()) {
                words += makeWord(current.toString(), sentence, clause)
                current.setLength(0)
            }
        }
        var maskIdx = 0
        val sortedMasks = masked.sortedBy { it.first }
        for (i in text.indices) {
            while (maskIdx < sortedMasks.size && sortedMasks[maskIdx].last < i) maskIdx++
            val inMask = maskIdx < sortedMasks.size && i in sortedMasks[maskIdx]
            val c = if (inMask) ' ' else text[i]
            val spelled = CURRENCY[c]
            when {
                spelled != null -> {
                    flush()
                    words += makeWord(spelled.trim(), sentence, clause)
                }
                c.isLetterOrDigit() -> current.append(c)
                c in APOSTROPHES && current.isNotEmpty() && text.getOrNull(i + 1)?.isLetter() == true -> Unit
                else -> {
                    flush()
                    if (c in SENTENCE_BREAKS) { sentence++; clause++ }
                    else if (c in CLAUSE_BREAKS || isSpacedDash(text, i)) clause++
                }
            }
        }
        flush()
        return words
    }

    private fun isSpacedDash(text: String, i: Int): Boolean =
        text[i] == '-' && text.getOrNull(i - 1)?.isWhitespace() == true && text.getOrNull(i + 1)?.isWhitespace() == true

    private fun makeWord(raw: String, sentence: Int, clause: Int): Word {
        val base = normalizeWord(raw)
        val isNumber = base.all { it.isDigit() }
        val hasLatin = raw.any { it in 'a'..'z' || it in 'A'..'Z' }
        val hasCyrillic = raw.any { isCyrillic(it) }
        if (!(hasLatin && hasCyrillic)) {
            return Word(listOf(base), sentence, clause, isNumber, disguised = false)
        }
        val cyr = normalizeWord(raw.map { TO_CYRILLIC[it] ?: it }.joinToString(""))
        val lat = normalizeWord(raw.map { TO_LATIN[it] ?: it }.joinToString(""))
        val disguised = cyr.none { it in 'a'..'z' } || lat.none { isCyrillic(it) }
        return Word(listOf(base, cyr, lat).distinct(), sentence, clause, isNumber, disguised)
    }

    fun isCyrillic(c: Char): Boolean = c in 'Ѐ'..'ӿ'
}

/**
 * Russian typed in Latin letters, read back into Cyrillic: "vzloman" →
 * "взломан", "soobshchayte" → "сообщайте", "den'gi" → "денги".
 *
 * People type it by ear, so a few spellings are ambiguous and each gets
 * both readings: "sh" is ш or щ ("soobshite"), "sch" сч or щ ("schet",
 * "soobschite"), "ts" ц or тс ("otsenka", "svyazhetsya"), a first "e" е or э
 * ("eto"). A choice is made once per word, so a word has at most a handful
 * of readings. "y" is й after a vowel ("moy", "pozhaluysta") and ы elsewhere
 * ("vy", "nuzhny"); the soft sign is never typed, so a stem is compared
 * without it ([Stem]).
 */
internal object Translit {
    private const val MAX_LENGTH = 32
    private const val VOWELS = "аеиоуыэюя"

    /** Longest first, so "shch" wins over "sh" and "sh" over "s". */
    private val TABLE: List<Pair<String, List<String>>> = listOf(
        "shch" to listOf("щ"), "sch" to listOf("сч", "щ"),
        "zh" to listOf("ж"), "kh" to listOf("х"), "ch" to listOf("ч"), "sh" to listOf("ш", "щ"),
        "ts" to listOf("ц", "тс"), "tz" to listOf("ц"),
        "yu" to listOf("ю"), "ju" to listOf("ю"), "ya" to listOf("я"), "ja" to listOf("я"),
        "yo" to listOf("е"), "jo" to listOf("е"), "ye" to listOf("е"), "je" to listOf("е"),
        "ck" to listOf("к"), "ph" to listOf("ф"),
        "a" to listOf("а"), "b" to listOf("б"), "c" to listOf("ц"), "d" to listOf("д"), "e" to listOf("е"),
        "f" to listOf("ф"), "g" to listOf("г"), "h" to listOf("х"), "i" to listOf("и"), "j" to listOf("й"),
        "k" to listOf("к"), "l" to listOf("л"), "m" to listOf("м"), "n" to listOf("н"), "o" to listOf("о"),
        "p" to listOf("п"), "q" to listOf("к"), "r" to listOf("р"), "s" to listOf("с"), "t" to listOf("т"),
        "u" to listOf("у"), "v" to listOf("в"), "w" to listOf("в"), "x" to listOf("кс"), "z" to listOf("з"),
    )

    /** The Cyrillic readings of a lowercase Latin word; empty for anything else. */
    fun readings(word: String): List<String> {
        if (word.isEmpty() || word.length > MAX_LENGTH || word.any { it !in 'a'..'z' }) return emptyList()
        // Split into table keys; "y" is decided by what comes before it.
        val keys = ArrayList<String>(word.length)
        var i = 0
        while (i < word.length) {
            val key = TABLE.firstOrNull { word.startsWith(it.first, i) }?.first ?: word[i].toString()
            keys += key
            i += key.length
        }
        val ambiguous = keys.filter { k -> TABLE.firstOrNull { it.first == k }?.second.orEmpty().size > 1 }.distinct()
        val firstE = keys.first() == "e"
        val out = LinkedHashSet<String>()
        val combos = 1 shl (ambiguous.size + if (firstE) 1 else 0)
        for (mask in 0 until combos) {
            val sb = StringBuilder(word.length + 4)
            for ((n, k) in keys.withIndex()) {
                when {
                    n == 0 && firstE -> sb.append(if (mask and 1 == 0) 'е' else 'э')
                    k == "y" -> sb.append(if (sb.lastOrNull()?.let { it in VOWELS } == true) 'й' else 'ы')
                    else -> {
                        val options = TABLE.first { it.first == k }.second
                        val bit = ambiguous.indexOf(k).takeIf { it >= 0 }?.let { it + if (firstE) 1 else 0 }
                        sb.append(if (bit == null || mask and (1 shl bit) == 0) options[0] else options[1])
                    }
                }
            }
            out += sb.toString()
        }
        return out.toList()
    }
}
