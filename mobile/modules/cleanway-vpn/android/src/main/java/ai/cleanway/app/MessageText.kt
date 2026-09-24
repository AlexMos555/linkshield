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
 *    scripts to slip past operator filters; a real sender never does.
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
)

/** One stem of a phrase: a prefix ("госуслуг*") or an exact word ("тел"). */
internal data class Stem(val text: String, val prefix: Boolean) {
    fun matches(word: Word): Boolean =
        word.forms.any { if (prefix) it.startsWith(text) else it == text }
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
     */
    fun index(text: String, masked: List<IntRange> = emptyList()): WordIndex {
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
        return WordIndex(words)
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
