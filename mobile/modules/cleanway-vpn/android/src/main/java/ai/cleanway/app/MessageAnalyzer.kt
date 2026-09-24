package ai.cleanway.app

import java.net.IDN

/** Overall result. There is deliberately no "safe": a message can only show no signals. */
enum class MessageVerdict(val wire: String) {
    DANGEROUS("dangerous"),
    CAUTION("caution"),
    NO_SIGNALS("no_signals"),
}

/** A link found in the message, as the UI may show it. */
data class MessageLink(
    /** As written, path included. Stays on the phone. */
    val text: String,
    /** Lowercase punycode host — the only part that may be sent for a domain check. */
    val host: String,
    val status: LinkStatus,
    val shortener: Boolean,
    val messenger: Boolean,
)

data class MessageAnalysis(
    val verdict: MessageVerdict,
    /** Stable snake_case codes the UI translates, most important first. Empty for no_signals. */
    val reasons: List<String>,
    val links: List<MessageLink>,
    /** Full phone numbers found, normalised to +<digits>. */
    val phones: List<String>,
    /** The message looks like a known legitimate shape (login code, payment alert…), or null. */
    val legitShape: String?,
    /** Ids of the organisations the message names (message_rules.json). */
    val organisations: List<String>,
    /** The text was longer than [MessageAnalyzer.MAX_CHARS]; only the start was read. */
    val truncated: Boolean,
) {
    /** Plain maps and lists for the Expo bridge. Carries no message text beyond the links as written. */
    fun toWire(): Map<String, Any?> = mapOf(
        "verdict" to verdict.wire,
        "reasons" to reasons,
        "links" to links.map {
            mapOf(
                "text" to it.text,
                "host" to it.host,
                "status" to it.status.wire,
                "shortener" to it.shortener,
                "messenger" to it.messenger,
            )
        },
        "phones" to phones,
        "legitShape" to legitShape,
        "organisations" to organisations,
        "truncated" to truncated,
    )
}

/**
 * The on-device message check: a pasted or shared SMS in, a verdict out.
 * The text never leaves the phone and is never stored or logged; only the
 * hosts of the links may later be sent, one by one, to the existing
 * domain-only endpoint — and that is the caller's decision, not this class's.
 *
 * ## Rule shape (never one word)
 *
 * A warning needs a COMBINATION. Signal groups (see MessageSignals):
 *  - A: names an organisation — Госуслуги, a bank, the police, an operator…
 *  - B: a threat or urgency — "взломан", "заблокирована", "срочно", "до 23:59"
 *  - E: bait — "компенсация", "вы выиграли", "вычет"
 *  - an action: call a number that is not the organisation's official one,
 *    follow a link that is not the brand's, tell a code to a person, move
 *    money to a "safe account", pay a fee, install an app.
 *
 * DANGEROUS: a blocklisted link; A+B+call back; A+B+foreign link; A+fee+
 * foreign link; a code asked for a person; a safe-account instruction; a
 * relative with a new number asking for money; a photo/app lure with a
 * foreign link or an .apk; bait plus a fee; an SMS-banking transfer command.
 * CAUTION: the partial combinations (A + foreign link; an authority + an
 * unknown number; pressure + a hidden link; a look-alike link; with no
 * organisation named, a fine, fee or payout through an unknown site…).
 *
 * ## Legitimate shapes are excluded first
 *
 * A real login code ("никому не сообщайте код… позвоните на 900"), a bank
 * payment alert, a parcel pickup code, a public emergency alert. They use the
 * scam vocabulary on purpose, so none of them may raise a text warning — but
 * only while they carry no foreign link, no unknown callback number and no
 * request for the code, and their links are still checked against the list.
 *
 * Pure Kotlin: the link status comes in as a function, so the whole class is
 * JVM-testable against an in-memory BlockList.
 */
class MessageAnalyzer(
    private val rules: MessageRules,
    private val linkStatus: (String) -> LinkStatus,
) {
    fun analyze(text: String, sender: String? = null): MessageAnalysis {
        val truncated = text.length > MAX_CHARS
        val cleaned = MessageText.clean(if (truncated) text.substring(0, MAX_CHARS) else text)
        val found = LinkExtractor.extract(cleaned.text, rules.bareTlds)
        // Every link is judged; only the list the person sees is capped.
        val links = found.map { facts(it) }
        val phones = PhoneExtractor.extract(blank(cleaned.text, found.map { it.span }))
        val signals = MessageSignals(
            rules = rules,
            index = MessageText.index(cleaned.text, found.map { it.span }),
            text = MessageText.normalizeWord(cleaned.text),
            hiddenInWord = cleaned.hiddenInWord,
            links = links,
            phones = phones,
            sender = sender,
        )
        val shape = legitShape(signals)
        val (verdict, reasons) = decide(signals, excluded = shape != null)
        return MessageAnalysis(
            verdict = verdict,
            reasons = reasons,
            links = shown(links).map {
                MessageLink(it.found.text, it.found.host, it.status, it.shortener, it.messenger)
            },
            phones = phones.map { it.number },
            // "Looks like a pickup code" next to a listed link would read as reassurance.
            legitShape = shape.takeIf { verdict != MessageVerdict.DANGEROUS },
            organisations = signals.organisations.map { it.id },
            truncated = truncated,
        )
    }

    /**
     * At most [MAX_LINKS] links for the screen, in message order — listed ones
     * first to keep: twenty harmless links must not push a listed one out.
     */
    private fun shown(links: List<LinkFacts>): List<LinkFacts> {
        if (links.size <= MAX_LINKS) return links
        val listed = links.filter { it.status == LinkStatus.BLOCKED }.take(MAX_LINKS)
        val keep = (listed + links.filter { it.status != LinkStatus.BLOCKED }.take(MAX_LINKS - listed.size)).toSet()
        return links.filter { it in keep }
    }

    private fun facts(link: FoundLink): LinkFacts {
        val official = rules.isOfficial(link.host)
        return LinkFacts(
            found = link,
            status = linkStatus(link.host),
            shortener = HostNames.under(link.host, rules.shorteners),
            messenger = HostNames.under(link.host, rules.messengers),
            official = official,
            imitatesBrand = !official && imitatesBrand(link.host),
        )
    }

    /**
     * "sberbank-bonus.ru", "gosuslugi-help.ru", "t2-gosuslugi.ru": a brand in a
     * name that is not the brand's. A short brand must stand as its own token
     * — "apple" inside goldapple.ru is a cosmetics shop, not Apple — and only
     * a long, distinctive one ("sberbank") may hide inside a longer word.
     * A Cyrillic name ("госуслуги-выплаты.рф") is read as written, not as its
     * punycode.
     */
    private fun imitatesBrand(host: String): Boolean {
        val tokens = (hostTokens(host) + hostTokens(unicode(host))).distinct()
        return rules.organisations.any { org ->
            org.domainTokens.any { brand ->
                tokens.any { t ->
                    t == brand || (brand.length >= 6 && (t.startsWith(brand) || t.endsWith(brand))) ||
                        (brand.length >= 8 && t.contains(brand))
                }
            }
        }
    }

    private fun hostTokens(host: String): List<String> =
        MessageText.normalizeWord(host).substringBeforeLast('.').split('.', '-').filter { it.isNotEmpty() }

    private fun unicode(host: String): String {
        if (!host.contains("xn--")) return host
        return try {
            IDN.toUnicode(host, IDN.ALLOW_UNASSIGNED)
        } catch (_: IllegalArgumentException) {
            host
        }
    }

    private fun legitShape(s: MessageSignals): String? {
        val clean = s.links.none { it.unofficial } && s.apkLinks.isEmpty() && !s.callbackStrong && !s.codeAsked &&
            !s.safeAccount && !s.malwareLure && !s.smsTransferCommand
        if (!clean) return null
        return when {
            // Pickup first: "Код получения: 4821" is also code-shaped.
            s.pickupCode -> SHAPE_PICKUP_CODE
            s.loginCode -> SHAPE_LOGIN_CODE
            s.paymentAlert -> SHAPE_PAYMENT_ALERT
            s.publicAlert -> SHAPE_PUBLIC_ALERT
            // "Мошенники могут списать деньги. Срочно позвоните 8 800…" borrows
            // the warning's words; a real one asks for no call and does not rush.
            s.safetyNotice && !s.moneyMove && !s.install && !s.callbackWeak && !s.pressure -> SHAPE_SAFETY_NOTICE
            else -> null
        }
    }

    private fun decide(s: MessageSignals, excluded: Boolean): Pair<MessageVerdict, List<String>> {
        val danger = LinkedHashSet<String>()
        val caution = LinkedHashSet<String>()
        if (s.links.any { it.status == LinkStatus.BLOCKED }) danger += R_LINK_BLOCKLISTED
        if (!excluded) {
            dangerous(s, danger)
            cautious(s, caution)
        }
        return when {
            danger.isNotEmpty() -> MessageVerdict.DANGEROUS to (danger + caution).toList()
            caution.isNotEmpty() -> MessageVerdict.CAUTION to caution.toList()
            else -> MessageVerdict.NO_SIGNALS to emptyList()
        }
    }

    private fun dangerous(s: MessageSignals, out: MutableSet<String>) {
        val foreign = s.links.filter { it.unofficial }
        val pressureReasons = pressureReasons(s)
        // A housing office or intercom firm really does text its own number and
        // site next to "задолженность", so only bodies whose numbers and
        // domains we know can make a callback or a link foreign.
        // Call back: "Госуслуги взломаны — срочно позвоните +7 9…".
        if (s.namesKnownBody && s.pressure && s.callbackStrong) {
            out += listOf(R_ORGANISATION) + pressureReasons + R_CALL_UNKNOWN
        }
        // A foreign link under a claimed brand, with a threat, a deadline or "подтвердите данные".
        // For a bank we know only by "банк*" the link may be its real site,
        // so a bare "до 31.10" — how every promotion ends — is not enough.
        val linkPressure = if (s.namesOnlyCatchAll) s.pressureBeyondDate else s.pressure
        if (s.namesKnownBody && linkPressure && foreign.isNotEmpty()) {
            out += listOf(R_ORGANISATION) + pressureReasons + linkReasons(foreign)
        }
        if (s.namesKnownBody && s.fee && foreign.isNotEmpty()) {
            out += listOf(R_ORGANISATION, R_PAYMENT) + linkReasons(foreign)
        }
        // The state and the police do not pay out through a foreign link.
        if (s.namesState && s.bait && foreign.isNotEmpty()) {
            out += listOf(R_ORGANISATION, R_BAIT) + linkReasons(foreign)
        }
        if (s.codeAsked) out += if (s.namesAnyBody) listOf(R_CODE, R_ORGANISATION) else listOf(R_CODE)
        if (s.safeAccount && (s.moneyMove || s.namesAuthority || s.callbackStrong)) out += R_SAFE_ACCOUNT
        if (s.kin && s.moneyMove && (s.newNumber || s.emergency)) out += R_RELATIVE
        if (s.malwareLure && foreign.isNotEmpty()) out += listOf(R_MALWARE_LURE) + linkReasons(foreign)
        if (s.install && foreign.any { it.suspicious || s.namesKnownBody }) out += listOf(R_INSTALL) + linkReasons(foreign)
        if (s.apkLinks.isNotEmpty()) out += listOf(R_INSTALL) + linkReasons(s.apkLinks)
        if (s.bait && s.fee) out += listOf(R_BAIT, R_PAYMENT)
        if (s.smsTransferCommand) out += R_SMS_COMMAND
    }

    private fun cautious(s: MessageSignals, out: MutableSet<String>) {
        val foreign = s.links.filter { it.unofficial }
        val hidden = foreign.filter { it.suspicious }
        // Shops put "кешбэк до 30.09" behind clck.ru every day; a short link
        // earns caution only next to a threat or a request for data.
        val hiddenBeyondShortener = hidden.filter { !it.shortener || it.found.isApk || it.imitatesBrand }
        if (s.namesKnownBody && foreign.isNotEmpty()) {
            out += listOf(R_ORGANISATION) + (if (s.bait) listOf(R_BAIT) else emptyList()) + linkReasons(foreign)
        }
        // A regional МФЦ or bailiffs' office does give its city number ("справки
        // по тел. 8 (843)…"); with no pressure or bait only a personal number counts.
        if (s.namesAuthority && s.callbackStrong && (s.pressure || s.bait || s.callbackPersonal)) {
            out += listOf(R_ORGANISATION, R_CALL_UNKNOWN)
        }
        if (s.namesKnownBody && s.pressure && s.callbackWeak) {
            out += listOf(R_ORGANISATION) + pressureReasons(s) + R_CALL_UNKNOWN
        }
        // A housing office's outage notice gives its dispatcher's number; that is not a callback lure.
        if (s.pressure && s.callbackStrong && !s.namesServiceOnly) out += pressureReasons(s) + R_CALL_UNKNOWN
        if (s.threat && s.callbackWeak) out += listOf(R_THREAT, R_CALL_UNKNOWN)
        if (s.bait && s.callbackStrong) out += listOf(R_BAIT, R_CALL_UNKNOWN)
        if ((s.threat || s.confirmData) && hidden.isNotEmpty()) {
            out += pressureReasons(s) + (if (s.bait) listOf(R_BAIT) else emptyList()) + linkReasons(hidden)
        } else if ((s.urgency || s.bait) && hiddenBeyondShortener.isNotEmpty()) {
            out += pressureReasons(s) + (if (s.bait) listOf(R_BAIT) else emptyList()) + linkReasons(hiddenBeyondShortener)
        }
        val disguisedLinks = foreign.filter { it.found.isIp || it.found.mixedScript || it.imitatesBrand }
        if (disguisedLinks.isNotEmpty()) out += linkReasons(disguisedLinks)
        // The phrase alone is one group; it needs a second to say anything.
        if (s.safeAccount && (s.namesAnyBody || s.pressure || s.callAsked || foreign.isNotEmpty())) out += R_SAFE_ACCOUNT
        if (s.disguised && (s.namesAnyBody || s.pressure || foreign.isNotEmpty())) out += R_DISGUISED
        if (s.kin && s.moneyMove && (s.secrecy || s.urgency)) out += R_RELATIVE
        // "Это Серёга, пишу с нового номера, займи 5000 срочно": the same family without "мама".
        if (s.newNumber && s.moneyMove && (s.secrecy || s.urgency)) out += R_RELATIVE
        // "МВД: ожидайте звонка следователя, не кладите трубку": the coming call is the scam.
        // A police warning ABOUT such calls names no call to the reader and gives no orders.
        if (s.namesSecurity && s.callComing && s.obey) out += listOf(R_ORGANISATION, R_THREAT)
        nobodyNamed(s, foreign, out)
        if (s.install && foreign.isNotEmpty() && s.pressure) out += listOf(R_INSTALL) + linkReasons(foreign)
        if (s.namesKnownBody && s.senderPersonal) out += listOf(R_ORGANISATION, R_SENDER_PERSONAL)
        if (s.senderMismatch) out += listOf(R_ORGANISATION, R_SENDER_MISMATCH)
    }

    /**
     * Nobody named, so no site to compare the link with — but a fine, a fee
     * or a payout through an unknown site is the scam family itself
     * ("Штраф 1500 р… оплатите: oplata-pdd.ru", "положена доплата… до 01.10").
     */
    private fun nobodyNamed(s: MessageSignals, foreign: List<LinkFacts>, out: MutableSet<String>) {
        if (s.namesAnyBody || foreign.isEmpty()) return
        if (s.threat && s.payAsked) out += listOf(R_THREAT, R_PAYMENT) + linkReasons(foreign)
        if (s.fee) out += listOf(R_PAYMENT) + linkReasons(foreign)
        if (s.payout && (s.urgency || s.confirmData)) out += pressureReasons(s) + R_BAIT + linkReasons(foreign)
    }

    private fun pressureReasons(s: MessageSignals): List<String> = buildList {
        if (s.threat || s.urgency) add(R_THREAT)
        if (s.confirmData) add(R_CONFIRM_DATA)
    }

    /** Why a set of links is a problem, most specific first after "not the brand's". */
    private fun linkReasons(links: List<LinkFacts>): List<String> = buildList {
        if (links.any { !it.official }) add(R_LINK_NOT_OFFICIAL)
        if (links.any { it.shortener }) add(R_LINK_SHORTENER)
        if (links.any { it.messenger }) add(R_LINK_MESSENGER)
        if (links.any { it.found.isIp }) add(R_LINK_IP)
        if (links.any { it.found.mixedScript }) add(R_LINK_LOOKALIKE)
        if (links.any { it.imitatesBrand }) add(R_LINK_IMITATES_BRAND)
        if (links.any { it.found.isApk }) add(R_LINK_APK)
    }

    /** Spaces over [spans] so a number inside a URL is not read as a phone. */
    private fun blank(text: String, spans: List<IntRange>): String {
        if (spans.isEmpty()) return text
        val chars = text.toCharArray()
        for (r in spans) for (i in r) if (i in chars.indices) chars[i] = ' '
        return String(chars)
    }

    companion object {
        /** Longer input is cut: a pasted chat log must not stall the check. */
        const val MAX_CHARS = 10_000
        /** Links reported to the screen (all of them are judged). */
        const val MAX_LINKS = 20

        const val SHAPE_LOGIN_CODE = "login_code"
        const val SHAPE_PAYMENT_ALERT = "payment_alert"
        const val SHAPE_PICKUP_CODE = "pickup_code"
        const val SHAPE_PUBLIC_ALERT = "public_alert"
        const val SHAPE_SAFETY_NOTICE = "safety_notice"

        const val R_LINK_BLOCKLISTED = "link_blocklisted"
        const val R_ORGANISATION = "claims_organisation"
        const val R_THREAT = "threat_or_urgency"
        const val R_CONFIRM_DATA = "asks_to_confirm_data"
        const val R_BAIT = "reward_bait"
        const val R_CALL_UNKNOWN = "call_unknown_number"
        const val R_LINK_NOT_OFFICIAL = "link_not_official"
        const val R_LINK_SHORTENER = "link_shortener"
        const val R_LINK_MESSENGER = "link_messenger"
        const val R_LINK_IP = "link_ip_address"
        const val R_LINK_LOOKALIKE = "link_lookalike"
        const val R_LINK_IMITATES_BRAND = "link_imitates_brand"
        const val R_LINK_APK = "link_apk"
        const val R_CODE = "asks_for_code"
        const val R_SAFE_ACCOUNT = "safe_account"
        const val R_PAYMENT = "asks_for_payment"
        const val R_RELATIVE = "relative_in_trouble"
        const val R_INSTALL = "install_app"
        const val R_MALWARE_LURE = "malware_lure"
        const val R_SMS_COMMAND = "sms_transfer_command"
        const val R_DISGUISED = "disguised_letters"
        const val R_SENDER_PERSONAL = "sender_personal_number"
        const val R_SENDER_MISMATCH = "sender_mismatch"

        /** Every reason code the analyzer can emit — the UI must translate each one. */
        val ALL_REASONS = listOf(
            R_LINK_BLOCKLISTED, R_ORGANISATION, R_THREAT, R_CONFIRM_DATA, R_BAIT, R_CALL_UNKNOWN,
            R_LINK_NOT_OFFICIAL, R_LINK_SHORTENER, R_LINK_MESSENGER, R_LINK_IP, R_LINK_LOOKALIKE,
            R_LINK_IMITATES_BRAND, R_LINK_APK, R_CODE, R_SAFE_ACCOUNT, R_PAYMENT, R_RELATIVE, R_INSTALL,
            R_MALWARE_LURE, R_SMS_COMMAND, R_DISGUISED, R_SENDER_PERSONAL, R_SENDER_MISMATCH,
        )
    }
}
