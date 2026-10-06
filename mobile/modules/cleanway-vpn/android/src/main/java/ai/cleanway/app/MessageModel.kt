package ai.cleanway.app

import org.json.JSONArray
import org.json.JSONObject
import kotlin.math.exp
import kotlin.math.sqrt

/**
 * The on-device text model: how much a message reads like the scams it was
 * trained on, as a probability. It generalises over paraphrases the
 * vocabulary rules have no words for; MessageAnalyzer decides what a score
 * may add to the rules' verdict (it never removes anything).
 *
 * Logistic regression over hashed binary features, trained in Python
 * (ml/sms/train.py; data, training and retraining in ml/sms/README.md):
 *  - char n-grams (2..5) of every word, and word unigrams and bigrams;
 *  - each block scaled to unit L2 norm, so length alone does not score;
 *  - FNV-1a 32 over UTF-16 code units, murmur3 fmix32, bucket = h & (dim-1);
 *  - weights: assets/message_model.bin (float16), the rest in
 *    assets/message_model.json (hash layout, bias, thresholds, the
 *    normaliser's lists, data hashes and metrics).
 *
 * The normaliser is the Kotlin twin of ml/sms/features.py and must stay
 * identical to it: MessageModelTest checks ~300 texts against the
 * probabilities Python computed (message_model_parity.tsv) to 1e-4. Every
 * character class is an explicit table, never Char.isLetter() or
 * lowercase(), which differ between the JVM and Python.
 *
 * Privacy: the text is read in memory and dropped, like the rules do.
 * Pure Kotlin, no Android types: JVM-testable.
 */
class MessageModel private constructor(
    private val weights: FloatArray,
    private val bias: Double,
    private val nMin: Int,
    private val nMax: Int,
    private val charWeight: Double,
    private val wordWeight: Double,
    private val charFloor: Int,
    private val wordFloor: Int,
    private val maxChars: Int,
    /** Fewer words than this and the model abstains ([score] is null): a few words are no evidence. */
    val minWords: Int,
    /** p at or above this, on a message the rules let through: a caution. */
    val cautionThreshold: Double,
    /** p at or above this, with one of the rules' ingredients: dangerous. */
    val dangerThreshold: Double,
    private val official: Set<String>,
    private val shorteners: Set<String>,
    private val messengers: Set<String>,
    private val cyrillicTlds: Set<String>,
    private val translitMarkers: Set<String>,
) {
    private val mask = weights.size - 1

    /** The probability that [text] is a scam, by its words alone; null when it has fewer than [minWords] words. */
    fun score(text: String): Double? {
        val f = featureHashes(text)
        return if (f.words < minWords) null else probability(f)
    }

    /** The probability whatever the length (the parity test compares this with Python). */
    fun probability(text: String): Double = probability(featureHashes(text))

    private fun probability(f: Features): Double {
        var z = bias
        for ((block, weight, floor) in listOf(Triple(f.chars, charWeight, charFloor), Triple(f.grams, wordWeight, wordFloor))) {
            if (block.isEmpty()) continue
            val v = weight / sqrt(maxOf(block.size, floor).toDouble())
            var sum = 0.0
            val it = block.iterator()
            while (it.hasNext()) sum += weights[it.next() and mask]
            z += v * sum
        }
        return 1.0 / (1.0 + exp(-z))
    }

    // ── features ──────────────────────────────────────────────────────────

    /** The hashed char n-grams and word uni/bigrams of a text, and how many words it has. */
    private class Features(val chars: IntSet, val grams: IntSet, val words: Int)

    private fun featureHashes(text: String): Features {
        val (tokens, translit) = tokenize(text)
        val chars = IntSet()
        val words = IntSet()
        for (stream in listOfNotNull(tokens, translit)) {
            var prev: String? = null
            for (t in stream) {
                words.add(fmix(feed(HW, t)))
                if (prev != null) words.add(fmix(feed(feed(feed(HB, prev), " "), t)))
                prev = t
                if (t[0] == '_') continue
                val padded = " $t "
                for (a in padded.indices) {
                    var h = HC
                    val end = minOf(padded.length, a + nMax)
                    for (b in a until end) {
                        h = feed(h, padded[b])
                        if (b - a + 1 >= nMin) chars.add(fmix(h))
                    }
                }
            }
        }
        return Features(chars, words, tokens.count { it[0] != '_' })
    }

    // ── normalisation (features.py, step by step) ─────────────────────────

    /** Step 1: the first [maxChars] code points, invisible ones dropped, emoji → U+FFFD, currency spelled, lowercase. */
    internal fun prepare(text: String): String {
        val sb = StringBuilder(minOf(text.length, maxChars) + 16)
        var i = 0
        var points = 0
        while (i < text.length && points < maxChars) {
            val cp = text.codePointAt(i)
            i += Character.charCount(cp)
            points++
            if (cp > 0xFFFF) { sb.append('�'); continue }
            val c = cp.toChar()
            if (c in INVISIBLE) continue
            val spelled = CURRENCY[c]
            if (spelled != null) sb.append(spelled) else sb.append(lowerChar(c))
        }
        return sb.toString()
    }

    private class Word(val text: String, val raw: String, val start: Int, val end: Int, val number: Boolean)

    /** Steps 2-5: the tokens, and their Cyrillic reading when the message is Russian typed in Latin. */
    internal fun tokenize(text: String): Pair<List<String>, List<String>?> {
        val s = prepare(text)
        val n = s.length
        val items = ArrayList<Any>(n / 5 + 4) // Word or a special token String
        var mixed = false
        var i = 0
        while (i < n) {
            if (s[i] in WHITESPACE) { i++; continue }
            var j = i
            while (j < n && s[j] !in WHITESPACE) j++
            val chunk = stripChunk(s.substring(i, j))
            var special: List<String>? = null
            if (chunk.isNotEmpty()) {
                special = urlTokens(chunk)
                if (special == null && '@' in chunk) {
                    val at = chunk.indexOf('@')
                    if (at == 0 && chunk.length > 2) special = listOf("_handle")
                    else if (at > 0 && '.' in chunk.substring(at + 1)) special = listOf("_email")
                }
            }
            if (special != null) {
                items.addAll(special)
            } else {
                var k = i
                while (k < j) {
                    if (!isWordChar(s[k])) { k++; continue }
                    var m = k
                    val buf = StringBuilder()
                    while (m < j) {
                        val c = s[m]
                        if (isWordChar(c)) { buf.append(c); m++ }
                        else if (c in APOSTROPHES && buf.isNotEmpty() && m + 1 < j && isLetter(s[m + 1])) m++
                        else break
                    }
                    val run = buf.toString()
                    if (maskRun(run)) {
                        items += Word("0".repeat(run.length), run, k, m, true)
                    } else {
                        for (part in run.split('*')) {
                            if (part.isEmpty()) continue
                            val (folded, wasMixed) = foldWord(part)
                            mixed = mixed || wasMixed
                            val zeroed = String(CharArray(folded.length) { q -> if (isDigit(folded[q])) '0' else folded[q] })
                            items += Word(zeroed, part, k, m, false)
                        }
                    }
                    k = m
                }
            }
            i = j
        }
        val tokens = ArrayList<String>(items.size + 2)
        var k = 0
        while (k < items.size) {
            val w = items[k]
            if (w !is Word) { tokens += w as String; k++; continue }
            if (!w.number) { tokens += w.text; k++; continue }
            // Phone and card numbers: number words joined only by spaces, dashes, brackets, dots.
            var m = k
            var digits = w.text.length
            while (m + 1 < items.size) {
                val next = items[m + 1] as? Word ?: break
                if (!next.number) break
                val gap = s.substring((items[m] as Word).end, next.start)
                if (gap.isEmpty() || gap.length > 3 || gap.any { it !in PHONE_GAP }) break
                m++
                digits += next.text.length
            }
            val plus = w.start > 0 && s[w.start - 1] == '+'
            val first = w.raw[0]
            if (digits in 10..12 && (plus || first in "789" || first in MASK)) {
                tokens += "_phone"
            } else if (digits in 13..19 && m > k) {
                tokens += "_card"
            } else {
                for (q in k..m) tokens += (items[q] as Word).text
            }
            k = m + 1
        }
        if ('!' in s) tokens += "_excl"
        if (mixed) tokens += "_mixscript"
        var translit: List<String>? = null
        if (s.none { isCyrillic(it) }) {
            val markers = tokens.filterTo(HashSet()) { it in translitMarkers }
            if (markers.size >= TRANSLIT_MIN_MARKERS) {
                translit = tokens.map { t -> if (t[0] != '_' && t.all { isLatin(it) }) reading(t) else t }
            }
        }
        return tokens to translit
    }

    /** A URL's tokens — its class and TLD, never its words — or null when [chunk] is not a link. */
    private fun urlTokens(chunk: String): List<String>? {
        var rest = chunk
        var scheme = false
        for (prefix in SCHEMES) {
            if (rest.startsWith(prefix)) {
                rest = rest.substring(prefix.length)
                scheme = true
                break
            }
        }
        if (rest.startsWith("www.")) scheme = true
        if (!scheme && '@' in rest) return null
        var end = rest.length
        for ((k, c) in rest.withIndex()) {
            if (c == '/' || c == '?' || c == '#') { end = k; break }
        }
        var host = rest.substring(0, end)
        val path = rest.substring(end)
        val colon = host.indexOf(':')
        if (colon >= 0) host = host.substring(0, colon)
        val labels = host.split('.')
        if (!scheme && path.isEmpty() && labels.size >= 2 && labels.last() in FILE_EXTENSIONS && labels[labels.size - 2].isNotEmpty()) {
            // "vozvrat.apk", "foto_party.apk", "scan.pdf": a file named in words, not a site.
            return listOf(if (labels.last() == "apk") "_apk" else "_file")
        }
        if (labels.size < 2 || !labels.all { hostLabelOk(it) }) return null
        val tld = labels.last()
        val ip = labels.size == 4 && labels.all { l -> l.all { isDigit(it) } && l.length <= 3 }
        val nameLabels = labels.subList(0, labels.size - 1)
        val nameLatin = nameLabels.any { l -> l.any { isLatin(it) } }
        val nameCyrillic = nameLabels.any { l -> l.any { isCyrillic(it) } }
        if (!ip) {
            if (!scheme) {
                val name = labels[labels.size - 2]
                if (tld.all { isCyrillic(it) }) {
                    // "госуслуги.рф": a Cyrillic TLD from the list, after a Cyrillic name.
                    if (tld !in cyrillicTlds || name.none { isCyrillic(it) }) return null
                } else if (tld.all { isLatin(it) }) {
                    // Any Latin TLD after a name with a Latin letter or a digit; a Cyrillic
                    // word before a Latin TLD ("отчет.pdf") only with a path.
                    if (tld.length < 2 || name.all { isDigit(it) }) return null
                    if (!nameLatin && !path.startsWith("/")) return null
                } else {
                    return null
                }
            } else if (tld.none { isLetter(it) }) {
                return null
            }
        } else if (!scheme && !path.startsWith("/")) {
            return null
        }
        val out = arrayListOf("_url")
        if (ip) {
            out += "_url_ip"
        } else {
            out += when {
                HostNames.under(host, official) -> "_url_off"
                HostNames.under(host, shorteners) -> "_url_short"
                HostNames.under(host, messengers) -> "_url_msgr"
                else -> "_url_unk"
            }
            out += "_tld_$tld"
            if (nameCyrillic && (nameLatin || tld.all { isLatin(it) })) out += "_url_mixed"
        }
        var q = path.length
        for ((k, c) in path.withIndex()) {
            if (c == '?' || c == '#') { q = k; break }
        }
        if (path.substring(0, q).endsWith(".apk")) out += "_apk"
        return out
    }

    companion object {
        const val ASSET_JSON = "message_model.json"
        const val ASSET_WEIGHTS = "message_model.bin"
        private const val VERSION = 1
        private val MAGIC = byteArrayOf('C'.code.toByte(), 'W'.code.toByte(), 'S'.code.toByte(), 'M'.code.toByte())

        /** The model from its two assets; throws on anything malformed (the caller falls back to rules only). */
        fun parse(json: String, weightBytes: ByteArray): MessageModel {
            val meta = JSONObject(json)
            require(meta.getInt("version") == VERSION) { "model version" }
            val hash = meta.getJSONObject("hash")
            val dim = hash.getInt("dim")
            require(dim > 0 && dim and (dim - 1) == 0) { "dim must be a power of two" }
            require(weightBytes.size == 12 + 2 * dim) { "weights size" }
            require((0 until 4).all { weightBytes[it] == MAGIC[it] }) { "weights magic" }
            require(u32(weightBytes, 4) == VERSION && u32(weightBytes, 8) == dim) { "weights header" }
            val weights = FloatArray(dim) { halfToFloat(((weightBytes[12 + 2 * it].toInt() and 0xFF) or ((weightBytes[13 + 2 * it].toInt() and 0xFF) shl 8))) }
            val ngrams = hash.getJSONArray("char_ngrams")
            val thresholds = meta.getJSONObject("thresholds")
            val norm = meta.getJSONObject("normaliser")
            return MessageModel(
                weights = weights,
                bias = meta.getDouble("bias"),
                nMin = ngrams.getInt(0),
                nMax = ngrams.getInt(1),
                charWeight = hash.getDouble("char_weight"),
                wordWeight = hash.getDouble("word_weight"),
                charFloor = hash.getInt("char_floor"),
                wordFloor = hash.getInt("word_floor"),
                maxChars = meta.getInt("max_chars"),
                minWords = meta.getInt("min_words"),
                cautionThreshold = thresholds.getDouble("caution"),
                dangerThreshold = thresholds.getDouble("dangerous_with_ingredient"),
                official = strings(norm.getJSONArray("official")),
                shorteners = strings(norm.getJSONArray("shorteners")),
                messengers = strings(norm.getJSONArray("messengers")),
                cyrillicTlds = strings(norm.getJSONArray("cyrillic_tlds")),
                translitMarkers = strings(norm.getJSONArray("translit_markers")),
            )
        }

        private fun strings(a: JSONArray): Set<String> = (0 until a.length()).mapTo(HashSet()) { a.getString(it) }

        private fun u32(b: ByteArray, at: Int): Int =
            (b[at].toInt() and 0xFF) or ((b[at + 1].toInt() and 0xFF) shl 8) or
                ((b[at + 2].toInt() and 0xFF) shl 16) or ((b[at + 3].toInt() and 0xFF) shl 24)

        /** IEEE 754 binary16 → float, exactly (android.util.Half is API 26+ and not on the JVM). */
        internal fun halfToFloat(bits: Int): Float {
            val sign = if (bits and 0x8000 != 0) -1f else 1f
            val exponent = (bits shr 10) and 0x1F
            val mantissa = bits and 0x3FF
            return when (exponent) {
                0 -> sign * mantissa * HALF_SUBNORMAL
                0x1F -> if (mantissa == 0) sign * Float.POSITIVE_INFINITY else Float.NaN
                else -> Float.fromBits(((bits and 0x8000) shl 16) or ((exponent + 112) shl 23) or (mantissa shl 13))
            }
        }

        private const val HALF_SUBNORMAL = 5.9604645E-8f // 2^-24

        // ── hashing ───────────────────────────────────────────────────────

        private const val FNV_OFFSET = 0x811C9DC5.toInt()
        private const val FNV_PRIME = 0x01000193

        private fun feed(h0: Int, c: Char): Int {
            val o = c.code
            var h = (h0 xor (o and 0xFF)) * FNV_PRIME
            h = (h xor (o ushr 8)) * FNV_PRIME
            return h
        }

        private fun feed(h0: Int, s: String): Int {
            var h = h0
            for (c in s) h = feed(h, c)
            return h
        }

        private fun fmix(h0: Int): Int {
            var h = h0
            h = h xor (h ushr 16)
            h *= 0x85EBCA6B.toInt()
            h = h xor (h ushr 13)
            h *= 0xC2B2AE35.toInt()
            h = h xor (h ushr 16)
            return h
        }

        private val HW = feed(FNV_OFFSET, 'w')
        private val HB = feed(FNV_OFFSET, 'b')
        private val HC = feed(FNV_OFFSET, 'c')

        // ── character tables (features.py) ────────────────────────────────

        private val INVISIBLE = setOf('​', '‌', '‍', '⁠', '﻿', '­', '᠎', '‎', '‏')
        private val WHITESPACE = (
            " \t\n\r\u000B\u000C             " +
                "    　"
            ).toSet()
        private val LEAD = "([{<\"'«„“‘".toSet()
        private val TRAIL = ".,;:!?)]}>\"'»”’…".toSet()
        private val APOSTROPHES = setOf('\'', '’', 'ʼ')
        private const val MASK = "xх*n"
        private val PHONE_GAP = " -(). ".toSet()
        private val SCHEMES = listOf("https://", "http://")
        private val FILE_EXTENSIONS = setOf("apk", "pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "rtf", "rar", "mp3", "mp4")
        private val CURRENCY = mapOf('₽' to " руб ", '$' to " usd ", '€' to " eur ", '£' to " gbp ")
        private val TO_CYRILLIC = mapOf(
            'a' to 'а', 'b' to 'в', 'c' to 'с', 'e' to 'е', 'h' to 'н', 'k' to 'к', 'm' to 'м', 'o' to 'о',
            'p' to 'р', 't' to 'т', 'x' to 'х', 'y' to 'у',
        )
        private val TO_LATIN: Map<Char, Char> = TO_CYRILLIC.entries.associate { (lat, cyr) -> cyr to lat }
        private const val VOWELS = "аеиоуыэюя"
        private const val TRANSLIT_MAX_LENGTH = 32
        private const val TRANSLIT_MIN_MARKERS = 2

        /** MessageText.kt's Translit table; the model takes its first reading only. */
        private val TRANSLIT: List<Pair<String, String>> = listOf(
            "shch" to "щ", "sch" to "сч", "zh" to "ж", "kh" to "х", "ch" to "ч", "sh" to "ш", "ts" to "ц", "tz" to "ц",
            "yu" to "ю", "ju" to "ю", "ya" to "я", "ja" to "я", "yo" to "е", "jo" to "е", "ye" to "е", "je" to "е",
            "ck" to "к", "ph" to "ф",
            "a" to "а", "b" to "б", "c" to "ц", "d" to "д", "e" to "е", "f" to "ф", "g" to "г", "h" to "х", "i" to "и",
            "j" to "й", "k" to "к", "l" to "л", "m" to "м", "n" to "н", "o" to "о", "p" to "п", "q" to "к", "r" to "р",
            "s" to "с", "t" to "т", "u" to "у", "v" to "в", "w" to "в", "x" to "кс", "z" to "з",
        )

        private fun isLatin(c: Char) = c in 'a'..'z'
        private fun isCyrillic(c: Char) = c in 'а'..'я' || c in 'ѐ'..'џ'
        private fun isDigit(c: Char) = c in '0'..'9'
        private fun isLetter(c: Char) = isLatin(c) || isCyrillic(c)
        private fun isWordChar(c: Char) = isLetter(c) || isDigit(c) || c == '*'

        private fun lowerChar(c: Char): Char = when (c) {
            in 'A'..'Z', in 'А'..'Я' -> c + 32
            'Ё', 'ё' -> 'е'
            in 'Ѐ'..'Џ' -> c + 0x50
            else -> c
        }

        private fun stripChunk(chunk: String): String {
            var s = 0
            var e = chunk.length
            while (s < e && chunk[s] in LEAD) s++
            while (e > s && chunk[e - 1] in TRAIL) e--
            return chunk.substring(s, e)
        }

        private fun hostLabelOk(label: String): Boolean =
            label.isNotEmpty() && label.all { isLatin(it) || isDigit(it) || it == '-' || isCyrillic(it) }

        /** XXX, ***, 9**, NN, 2200: a number, possibly masked. */
        private fun maskRun(run: String): Boolean {
            if (!run.all { isDigit(it) || it in MASK }) return false
            if (run.any { isDigit(it) }) return true
            return run.length >= 2
        }

        /** A word mixing Latin and Cyrillic letters, folded into the script it imitates. */
        private fun foldWord(w: String): Pair<String, Boolean> {
            if (!(w.any { isLatin(it) } && w.any { isCyrillic(it) })) return w to false
            val cyr = String(CharArray(w.length) { TO_CYRILLIC[w[it]] ?: w[it] })
            if (cyr.none { isLatin(it) }) return cyr to true
            val lat = String(CharArray(w.length) { TO_LATIN[w[it]] ?: w[it] })
            if (lat.none { isCyrillic(it) }) return lat to true
            return w to true
        }

        /** The first Cyrillic reading of a Latin word (Translit.readings()[0] in MessageText.kt). */
        internal fun reading(word: String): String {
            if (word.isEmpty() || word.length > TRANSLIT_MAX_LENGTH || word.any { !isLatin(it) }) return word
            val sb = StringBuilder(word.length + 4)
            var i = 0
            while (i < word.length) {
                val hit = TRANSLIT.firstOrNull { word.startsWith(it.first, i) }
                if (hit != null) {
                    sb.append(hit.second)
                    i += hit.first.length
                } else { // only "y" is not in the table: й after a vowel, ы elsewhere
                    sb.append(if (sb.isNotEmpty() && sb.last() in VOWELS) 'й' else 'ы')
                    i++
                }
            }
            return sb.toString()
        }
    }
}

/** A small open-addressing set of ints: the features of one message, without boxing. */
internal class IntSet {
    private var keys = IntArray(256)
    private var used = BooleanArray(256)
    var size = 0
        private set

    fun isEmpty() = size == 0

    fun add(k: Int) {
        if (2 * (size + 1) > keys.size) grow()
        var i = spread(k) and (keys.size - 1)
        while (used[i]) {
            if (keys[i] == k) return
            i = (i + 1) and (keys.size - 1)
        }
        used[i] = true
        keys[i] = k
        size++
    }

    fun iterator(): IntIterator = object : IntIterator() {
        private var i = advance(0)
        private fun advance(from: Int): Int {
            var j = from
            while (j < keys.size && !used[j]) j++
            return j
        }
        override fun hasNext() = i < keys.size
        override fun nextInt(): Int {
            val k = keys[i]
            i = advance(i + 1)
            return k
        }
    }

    private fun spread(k: Int) = k * -0x61c88647

    private fun grow() {
        val oldKeys = keys
        val oldUsed = used
        keys = IntArray(oldKeys.size * 2)
        used = BooleanArray(oldKeys.size * 2)
        size = 0
        for (j in oldKeys.indices) if (oldUsed[j]) add(oldKeys[j])
    }
}
