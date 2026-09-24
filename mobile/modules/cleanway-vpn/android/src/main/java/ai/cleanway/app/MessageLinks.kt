package ai.cleanway.app

import java.net.IDN
import java.util.Locale

/**
 * Host names as the blocklist hashes them: lowercase ASCII, IDN → punycode.
 *
 * The list stores DNS-form names, so a Cyrillic host passed raw would never
 * match — "госуслуги.рф" has to become "xn--…xn--p1ai" first. This is the
 * Kotlin twin of mobile/src/utils/host.ts::toCheckableHost's last step.
 */
object HostNames {
    private val FULLWIDTH_DOTS = charArrayOf('。', '．', '｡')

    /** The checkable form of [raw], or null when it is not a plausible host. */
    fun normalize(raw: String?): String? {
        var s = raw?.trim() ?: return null
        for (d in FULLWIDTH_DOTS) s = s.replace(d, '.')
        s = s.lowercase(Locale.ROOT).trimEnd('.')
        if (s.isEmpty() || s.length > 253 || s.contains("..") || !s.contains('.')) return null
        val ascii = try {
            IDN.toASCII(s, IDN.ALLOW_UNASSIGNED).lowercase(Locale.ROOT)
        } catch (_: IllegalArgumentException) {
            return null
        }
        if (ascii.length > 253) return null
        val ok = ascii.split('.').all { label ->
            label.isNotEmpty() && label.length <= 63 && !label.startsWith("-") && !label.endsWith("-") &&
                label.all { it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }
        }
        return if (ok) ascii else null
    }

    /** Is [host] equal to, or a subdomain of, one of [suffixes]? */
    fun under(host: String, suffixes: Set<String>): Boolean {
        if (suffixes.isEmpty()) return false
        if (host in suffixes) return true
        var dot = host.indexOf('.')
        while (dot >= 0) {
            if (host.substring(dot + 1) in suffixes) return true
            dot = host.indexOf('.', dot + 1)
        }
        return false
    }
}

/** A link as written in a message, before any verdict. */
data class FoundLink(
    /** Exactly as it appears in the message (path included) — shown on the phone, never sent. */
    val text: String,
    /** Normalised host — the only part that may ever leave the phone. */
    val host: String,
    val isIp: Boolean,
    /** The path names an Android package file. */
    val isApk: Boolean,
    /** A host label mixes Latin and Cyrillic letters: a look-alike of a real name. */
    val mixedScript: Boolean,
    /** Where it sits in the message, so the word rules can skip it. */
    val span: IntRange,
)

/**
 * Finds every link in a message: `http(s)://` URLs AND bare domains
 * ("sberbank-bonus.ru/login", "gosuslugi.help", "сайт.рф"), because an SMS
 * rarely carries a scheme.
 *
 * Built as a single left-to-right scan rather than one large regex: the
 * input is attacker-written, and a scan cannot backtrack.
 *
 * What is deliberately NOT a link: decimals, times and dates ("1.500 руб",
 * "10.30", "24.09.2026" — a numeric last label), abbreviations ("т.е.",
 * "г.Москва" — one-letter labels / unknown TLDs), e-mail addresses (the
 * part next to '@'), and a sentence glued on after a dot ("метро.Ok?",
 * "Call me.Today"). A bare name needs a TLD the rules know (the country codes
 * included) or a path after it; with a scheme any TLD is accepted.
 *
 * Every distinct host is returned — no cap while scanning. The input is
 * already cut to MessageAnalyzer.MAX_CHARS, and a cap here would let twenty
 * copies of a harmless link push a listed one out of sight.
 */
object LinkExtractor {
    private val WEB_SCHEMES = listOf("https", "http")

    private val HARD_STOPS = setOf('<', '>', '"', '«', '»', '“', '”', '„', '|', '\\', '^', '{', '}', '`', '\'', '‘', '’')
    private val TRAILING = setOf('.', ',', ';', ':', '!', '?', '…', ')', ']', '}', '\'', '"', '»', '”')
    private val DOTS = setOf('.', '。', '．', '｡')
    private val NOT_BEFORE_BARE = setOf('@', '/', '\\', '=', '?', '&', '#', '%')

    fun extract(text: String, bareTlds: Set<String>): List<FoundLink> {
        val found = ArrayList<FoundLink>()
        val consumed = ArrayList<IntRange>()
        schemeLinks(text, found, consumed)
        bareLinks(text, bareTlds, found, consumed.sortedBy { it.first })
        return dedupe(found.sortedBy { it.span.first })
    }

    // ── http(s):// ────────────────────────────────────────────────────────

    private fun schemeLinks(text: String, out: MutableList<FoundLink>, consumed: MutableList<IntRange>) {
        var from = 0
        while (true) {
            val sep = text.indexOf("://", from)
            if (sep < 0) return
            val web = webSchemeStart(text, sep)
            var start = web ?: sep
            if (web == null) {
                while (start > 0 && (text[start - 1].isLetterOrDigit() || text[start - 1] in "+.-")) start--
            }
            val end = trimTrailing(text, start, runEnd(text, sep + 3))
            from = maxOf(end, sep + 3)
            if (end <= sep + 3) continue
            // A non-web scheme (ftp://, intent://) answers a different question.
            if (web == null) {
                consumed += start until end
                continue
            }
            val rest = text.substring(sep + 3, end)
            val authority = rest.split('/', '?', '#', limit = 2)[0]
            val hostPart = authority.substringAfterLast('@')
            if (hostPart.startsWith("[")) { // IPv6 literal — not a name the list holds
                consumed += start until end
                continue
            }
            val rawHost = hostPart.substringBefore(':')
            // Not consumed when the host does not parse: the names inside
            // "https://gosuslugi.ru,evil.top/login" are still found as bare ones.
            val host = HostNames.normalize(rawHost) ?: continue
            consumed += start until end
            out += FoundLink(
                text = text.substring(start, end),
                host = host,
                isIp = isIpv4(host),
                isApk = pathIsApk(rest.substring(authority.length)),
                mixedScript = mixesScripts(rawHost),
                span = start until end,
            )
        }
    }

    // ── bare domains ──────────────────────────────────────────────────────

    private fun bareLinks(
        text: String,
        bareTlds: Set<String>,
        out: MutableList<FoundLink>,
        consumed: List<IntRange>,
    ) {
        var i = 0
        val n = text.length
        var skipIdx = 0 // consumed is sorted by start
        while (i < n) {
            while (skipIdx < consumed.size && consumed[skipIdx].last < i) skipIdx++
            val skip = consumed.getOrNull(skipIdx)?.takeIf { i in it }
            if (skip != null) { i = skip.last + 1; continue }
            if (!isHostChar(text[i])) { i++; continue }
            var e = i
            while (e < n && (isHostChar(text[e]) || text[e] in DOTS)) e++
            val link = bareCandidate(text, i, e, bareTlds)
            if (link != null) {
                out += link
                i = link.span.last + 1
            } else {
                i = e
            }
        }
    }

    private fun bareCandidate(text: String, runStart: Int, runEnd: Int, bareTlds: Set<String>): FoundLink? {
        // E-mail: the local part ends at '@', the domain starts after it.
        if (runStart > 0 && text[runStart - 1] in NOT_BEFORE_BARE) return null
        if (runEnd < text.length && text[runEnd] == '@') return null
        var s = runStart
        var e = runEnd
        while (s < e && (text[s] in DOTS || text[s] == '-')) s++
        while (e > s && (text[e - 1] in DOTS || text[e - 1] == '-' || text[e - 1] == '_')) e--
        if (e <= s) return null
        val all = text.substring(s, e).split('.', '。', '．', '｡')
        if (all.size < 2 || all.any { it.isEmpty() || it.length > 63 }) return null

        val ip = all.size == 4 && all.all { l -> l.all { it.isDigit() } && l.length <= 3 && l.toInt() <= 255 }
        if (ip) {
            // A bare dotted quad reads like a version or a date unless a path or port follows.
            val next = text.getOrNull(e)
            if (next != '/' && next != ':') return null
        } else {
            // "gosuslugi-lk.ru.Срок 24 часа": the next sentence glued on after
            // the dot. The SMS app still links the name, so drop labels from
            // the right until the last one is a TLD.
            val keep = (all.size downTo 2).firstOrNull { k ->
                plausibleTld(all.subList(0, k), bareTlds, pathFollows = k == all.size && text.getOrNull(e) == '/')
            } ?: return null
            e = s + all.subList(0, keep).sumOf { it.length } + keep - 1
        }
        val raw = text.substring(s, e)
        val next = text.getOrNull(e)
        val host = HostNames.normalize(raw) ?: return null

        var end = e
        if (next == ':' && text.getOrNull(e + 1)?.isDigit() == true) {
            end = e + 1
            while (end < text.length && text[end].isDigit()) end++
        }
        val pathStart = end
        if (end < text.length && text[end] in "/?#") end = trimTrailing(text, end, runEnd(text, end))
        return FoundLink(
            text = text.substring(s, end),
            host = host,
            isIp = ip,
            isApk = pathIsApk(text.substring(pathStart, end)),
            mixedScript = mixesScripts(raw),
            span = s until end,
        )
    }

    /**
     * [bareTlds] holds every country code and the generic TLDs SMS scams use.
     * With a path after it ("sber-help.homes/login") any Latin TLD is a link:
     * nobody writes "word.word/" in a sentence, and the SMS app links it.
     */
    private fun plausibleTld(labels: List<String>, bareTlds: Set<String>, pathFollows: Boolean): Boolean {
        val written = labels.last()
        val tld = MessageText.normalizeWord(written)
        if (tld.startsWith("xn--")) return true
        if (tld.any { !it.isLetter() }) return false
        val cyrillic = tld.all { MessageText.isCyrillic(it) }
        val latin = tld.all { it in 'a'..'z' }
        if (!cyrillic && !latin) return false
        // "г.Москва", "ул.Ленина": a one-letter abbreviation glued to a word.
        if (cyrillic && labels[labels.size - 2].length < 2) return false
        if (latin && pathFollows && tld.length in 2..MAX_TLD) return true
        if (tld !in bareTlds) return false
        // "Буду в 7.Ok", "Call me.Today", "Я дома.No": a capitalised word after
        // a dot starts a sentence. A real TLD is written in one case (".ru", ".RU").
        return !(written.length > 1 && written[0].isUpperCase() && written.drop(1).all { it.isLowerCase() } &&
            tld in SENTENCE_WORDS)
    }

    // ── helpers ───────────────────────────────────────────────────────────

    private fun isHostChar(c: Char): Boolean = c.isLetterOrDigit() || c == '-' || c == '_'

    /** First index at or after [from] that cannot belong to a URL. */
    private fun runEnd(text: String, from: Int): Int {
        var e = from
        while (e < text.length && !text[e].isWhitespace() && text[e] !in HARD_STOPS) e++
        return e
    }

    /** Drop sentence punctuation a link drags along ("…/login)." → "…/login"). */
    private fun trimTrailing(text: String, start: Int, end: Int): Int {
        var e = end
        while (e > start && text[e - 1] in TRAILING) {
            // Keep a closing bracket the URL itself opened.
            if (text[e - 1] == ')' && text.substring(start, e - 1).contains('(')) break
            e--
        }
        return e
    }

    private fun pathIsApk(path: String): Boolean {
        val p = path.substringBefore('?').substringBefore('#').lowercase(Locale.ROOT)
        return p.endsWith(".apk")
    }

    private fun isIpv4(host: String): Boolean {
        val parts = host.split('.')
        return parts.size == 4 && parts.all { p -> p.isNotEmpty() && p.length <= 3 && p.all { it.isDigit() } && p.toInt() <= 255 }
    }

    /** "sberbаnk" with a Cyrillic а: one label, two scripts. */
    private fun mixesScripts(host: String): Boolean =
        host.split('.', '-').any { label ->
            label.any { it in 'a'..'z' || it in 'A'..'Z' } && label.any { MessageText.isCyrillic(it) }
        }

    /** One entry per host; a later mention can only add the .apk flag. */
    private fun dedupe(links: List<FoundLink>): List<FoundLink> {
        val byHost = LinkedHashMap<String, FoundLink>()
        for (l in links) {
            val prev = byHost[l.host]
            byHost[l.host] = if (prev == null) l else prev.copy(isApk = prev.isApk || l.isApk)
        }
        return byHost.values.toList()
    }

    /**
     * Where "http(s)" starts before "://", or null for another scheme. Found
     * even when glued to the word before it — "по ссылкеhttps://…",
     * "1.https://…": the SMS app still links those.
     */
    private fun webSchemeStart(text: String, sep: Int): Int? {
        for (scheme in WEB_SCHEMES) {
            val start = sep - scheme.length
            if (start >= 0 && text.regionMatches(start, scheme, 0, scheme.length, ignoreCase = true)) return start
        }
        return null
    }

    private const val MAX_TLD = 24

    /** TLDs that are also everyday words; written capitalised after a dot, they start a sentence. */
    private val SENTENCE_WORDS = setOf(
        "no", "me", "to", "so", "in", "it", "is", "at", "be", "by", "do", "my", "am", "an", "as", "us", "go", "ok",
        "hi", "one", "today", "free", "best", "live", "life", "work", "run", "win", "fun", "news", "sale", "blog",
        "page", "team", "world", "money", "cash", "gift", "gifts", "video", "photo", "photos", "games", "game",
    )
}

/**
 * Phone numbers in a message, normalised to +<digits>.
 *
 * Only full numbers are returned (10–15 digits). Three-to-five digit service
 * numbers (900, 0919, 115) are read by the rules from the words right after
 * "позвоните"; a bare short number anywhere else is an amount or a code.
 * Card numbers (16 digits), 20-digit account numbers, amounts ("250 000") and
 * dates (dots are not separators) fall outside the shape.
 */
object PhoneExtractor {
    private const val MAX_SPAN = 24
    private val SEPARATORS = setOf(' ', '-', '(', ')', ' ', '‑', '‒', '–')

    enum class Kind { MOBILE, TOLL_FREE, CITY, FOREIGN }

    data class Phone(val number: String, val kind: Kind)

    fun extract(text: String): List<Phone> {
        val out = LinkedHashMap<String, Phone>()
        var i = 0
        while (i < text.length) {
            val c = text[i]
            val startsHere = (c == '+' && text.getOrNull(i + 1)?.isDigit() == true) || c.isDigit()
            if (!startsHere || gluedToPrevious(text, i)) {
                i++
                continue
            }
            val (phone, end) = readAt(text, i)
            if (phone != null) out.putIfAbsent(phone.number, phone)
            i = maxOf(end, i + 1)
        }
        return out.values.toList()
    }

    /**
     * A digit run that continues a word, a card mask ("*1234") or a decimal
     * ("1.500") is not the start of a phone number. "тел.+7…" still is.
     */
    private fun gluedToPrevious(text: String, i: Int): Boolean {
        val prev = text.getOrNull(i - 1) ?: return false
        if (prev.isLetterOrDigit() || prev == '*') return true
        return (prev == '.' || prev == ',') && text.getOrNull(i - 2)?.isDigit() == true
    }

    /** Normalise a number written anywhere (rules file, sender id). Null when it is not one. */
    fun normalize(raw: String): String? {
        val digits = raw.filter { it.isDigit() }
        if (digits.length in 3..6 && raw.none { it == '+' }) return digits // service short number
        return classify(digits, plus = raw.trim().startsWith("+"), separated = true)?.number
    }

    private fun readAt(text: String, start: Int): Pair<Phone?, Int> {
        val plus = text[start] == '+'
        val digits = StringBuilder()
        var j = if (plus) start + 1 else start
        var lastDigit = j
        var separated = false
        while (j < text.length && j - start <= MAX_SPAN) {
            val c = text[j]
            if (c.isDigit()) {
                digits.append(c); lastDigit = j + 1
                // A complete Russian number followed by a gap: stop, so "…22-33 8 800…"
                // stays two numbers. A digit right after it makes it a longer
                // number (a 14-digit tracking code), which then fails the length.
                if (digits.length == 11 && (digits[0] == '7' || digits[0] == '8') &&
                    text.getOrNull(j + 1)?.isDigit() != true
                ) break
            } else if (c in SEPARATORS && text.getOrNull(j + 1)?.let { it.isDigit() || it in SEPARATORS } == true) {
                separated = true
            } else {
                break
            }
            j++
        }
        // A digit glued to the end ("89161234567р") is an amount, not a number.
        val after = text.getOrNull(lastDigit)
        if (after != null && (after.isLetter() || after == '.' && text.getOrNull(lastDigit + 1)?.isDigit() == true)) {
            return null to lastDigit
        }
        return classify(digits.toString(), plus, separated) to lastDigit
    }

    private fun classify(digits: String, plus: Boolean, separated: Boolean): Phone? {
        val ru = when {
            digits.length == 11 && (digits[0] == '7' || (digits[0] == '8' && !plus)) -> digits.substring(1)
            // "912 345-67-89": a Russian mobile without its prefix — only when written like a phone.
            digits.length == 10 && digits[0] == '9' && !plus && separated -> digits
            else -> null
        }
        if (ru != null) {
            val kind = when {
                ru.startsWith("9") -> Kind.MOBILE
                ru.startsWith("800") -> Kind.TOLL_FREE
                else -> Kind.CITY
            }
            return Phone("+7$ru", kind)
        }
        if (plus && digits.length in 10..15) return Phone("+$digits", Kind.FOREIGN)
        return null
    }
}
