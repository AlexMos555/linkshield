package ai.cleanway.app

import ai.cleanway.app.MessageRules.Companion as G

/**
 * The scheme-independent ingredients of one message.
 *
 * The scheme rules in [MessageAnalyzer] wait for a scheme's own words; a
 * paraphrase ("внесите остаток" for "оплатите доставку", "комбинация из
 * входящего сообщения" for "код из SMS") slips past them. These are the
 * ingredients every scheme is built from, in broad vocabulary groups:
 *  - money asked: pay, settle, deposit, transfer — an order, not an option
 *    ("оплатить можно на месте") — or card details asked for;
 *  - a code asked for a person, a code or password to type into a site, or
 *    personal data (passport, "подтвердите владельца");
 *  - a promise of money: a payout, a prize, income, money waiting to be taken;
 *  - a threat: a debt, a fine, a loss, a block, "от вашего имени";
 *  - urgency, secrecy, a claimed authority, a call back or a call to come.
 *
 * None of them is a warning; [GenericLayer] combines them. Every lookup
 * honours negation and the awareness framing ("мошенники просят…") the same
 * way the scheme rules do.
 */
internal class GenericSignals(private val s: MessageSignals) {

    /**
     * Links that are no organisation's own, that the person has not vouched
     * for, and that are not the site of the name the message signs with
     * ("Ivi: … ivi.ru/profile", "Мосэнергосбыт: … mosenergosbyt.ru"). A link
     * that hides where it goes or wears a brand stays foreign whatever the
     * signature says.
     */
    val foreign: List<LinkFacts> by lazy { s.links.filter { it.unofficial && !(ownSite(it) && !it.suspicious) } }

    /** Links that can be a payment page: a file on Yandex Disk is a document, not a checkout. */
    val payable: List<LinkFacts> by lazy { foreign.filter { !HostNames.under(it.found.host, s.rules.userContentHosts) } }

    // ── money asked ───────────────────────────────────────────────────────

    /**
     * "Погасите", "требуется уплатить", "внести платёж:" — and "если не внести
     * остаток", whose negation is the condition, not a refusal. Not "оплатить
     * можно на месте": an option offered is not a demand.
     */
    val moneyAsked: Boolean by lazy {
        moneyDemanded || s.hits(G.GEN_MONEY_INFINITIVE).any { h -> live(h) && !optional(h) }
    }

    /**
     * An order to pay, not a bill's "Оплатить онлайн:" label: an imperative, an
     * infinitive under "необходимо"/"требуется", or card details asked for.
     */
    val moneyDemanded: Boolean by lazy {
        s.hits(G.GEN_MONEY_ASK).any { h -> live(h) && !optional(h) } ||
            s.hits(G.GEN_MONEY_INFINITIVE).any { h -> live(h) && !optional(h) && directed(h) } ||
            cardData
    }

    /** "Укажите номер карты", "проверьте реквизиты", "update your billing details". */
    val cardData: Boolean by lazy { asked(G.GEN_CARD_DATA) }

    /**
     * Money for a charge: "оплатите обучение 1 990 р", "для повторной отправки
     * необходимо доплатить". A booking's "оплатите в течение 30 минут" or a
     * class collection "оплатите экскурсию" pays for the thing itself.
     */
    val feeDemanded: Boolean by lazy {
        val fees = s.hits(G.FEE_WORD) + s.hits(G.GEN_FEE)
        (s.hits(G.GEN_MONEY_ASK) + s.hits(G.GEN_MONEY_INFINITIVE)).any { h ->
            live(h) && !optional(h) && fees.any { f ->
                s.index.sameSentence(h.start, f.start) && (f.start in h.end + 1..h.end + FEE_WINDOW || f.end in h.start - FEE_WINDOW until h.start)
            }
        }
    }

    /** Not negated — unless the negation is the condition ("если не внести") — and not a scam described. */
    private fun live(h: Hit): Boolean = !s.aware(h.start) && (!s.negated(h.start) || s.conditional(h.start))

    /** "Можно оплатить", "оплатить можно": a modal next to the verb, in its clause. */
    private fun optional(h: Hit): Boolean =
        s.hits(G.GEN_MODAL).any { m ->
            s.index.sameClause(m.start, h.start) && (m.start in h.start - 2 until h.start || m.start in h.end + 1..h.end + 2)
        }

    /** "Необходимо доплатить", "нужно назвать": a live directive or request right before the infinitive. */
    private fun directed(h: Hit): Boolean = (s.hits(G.DIRECTIVE) + s.hits(G.CODE_REQUEST)).any { d ->
        d.end < h.start && h.start - d.end <= 2 && s.index.sameClause(d.end, h.start) && s.active(d) && !s.conditional(d.start)
    }

    /** A live data verb ("укажите", "подтвердите", "введите") with a noun of [group] right after it. */
    private fun asked(group: String): Boolean =
        s.hits(G.GEN_DATA_VERB).any { v -> s.active(v) && s.hits(group).any { s.follows(v, it, 5) } }

    // ── a code or personal data asked ─────────────────────────────────────

    /**
     * "Сообщите специалисту комбинацию из входящего сообщения", "будьте готовы
     * назвать код, который придёт": a secret for a person — someone to hear it
     * or a code still to arrive. A courier's pickup code is the legitimate twin,
     * and "банк никогда не попросит вас назвать код" asks nothing.
     */
    val codeToPerson: Boolean by lazy {
        !s.pickupHandover() &&
            (s.has(G.CODE_TARGET) || s.has(G.CALL_CONTEXT) || s.has(G.CODE_INCOMING) || s.callComing) &&
            (
                s.hits(G.GEN_TELL_VERB).any { v -> s.active(v) && secretAfter(v) } ||
                    s.hits(G.CODE_INFINITIVE).any { v -> s.active(v) && (directed(v) || ifBefore(v)) && secretAfter(v) }
                )
    }

    /** "Сохранить тариф можно, если сообщить специалисту комбинацию": the condition is the instruction. */
    private fun ifBefore(v: Hit): Boolean = s.index.isWord(v.start - 1, IF) && s.index.sameClause(v.start - 1, v.start)

    /**
     * "Введите пароль", "подтвердите участие кодом из SMS": a secret typed into a
     * page. A login code SMS says the same of its own code, so not when the
     * message carries the code itself.
     */
    val codeOnSite: Boolean by lazy {
        !s.loginCode && !s.codeInMessage && s.hits(G.GEN_DATA_VERB).any { v -> s.active(v) && secretAfter(v) }
    }

    /** "Подтвердите владельца", "введите паспортные данные", "обновите сведения". */
    val identityAsked: Boolean by lazy { s.confirmData || asked(G.GEN_IDENTITY) }

    val code: Boolean get() = codeToPerson || codeOnSite || identityAsked

    private fun secretAfter(v: Hit): Boolean = s.hits(G.GEN_SECRET).any { c ->
        s.follows(v, c, 6) && s.hits(G.CODE_HOUSEHOLD).none { s.follows(c, it, 2) }
    }

    // ── a promise of money ────────────────────────────────────────────────

    private val amount: Boolean by lazy { s.amount() }

    /** Points, promo codes, cashback and gifts with an order are a shop's currency, not money handed out. */
    val promo: Boolean by lazy { s.has(G.GEN_PROMO) }

    /** A claim verb: "получите", "заберите", "активируйте", "для участия". */
    val claim: Boolean by lazy { s.hits(G.GEN_CLAIM).any { s.active(it) } }

    /**
     * A payout, a prize, income, money waiting for the reader — or "получите
     * 50 000 р" outright. "Получите скидку 1 000 р" is a shop's promotion.
     */
    val promise: Boolean by lazy {
        s.payout || s.has(G.GEN_PROMISE) || s.receiveMoney || (claim && amount && !promo)
    }

    /** The promise is money — a sum, income, funds — not concert tickets won in a radio draw. */
    val promiseOfMoney: Boolean by lazy {
        promise && (amount || s.has(G.MONEY_CONTEXT) || s.has(G.GEN_MONEY_NOUN))
    }

    // ── pressure, secrecy, a role ─────────────────────────────────────────

    /**
     * A threat or a loss. Not checked for negation — "чтобы не потерять доступ"
     * is the threat itself — but a receipt's "долга нет", "производство
     * окончено" reports its absence.
     */
    val threat: Boolean by lazy {
        s.obey || (s.hits(G.THREAT) + s.hits(G.GEN_THREAT)).any { h ->
            s.hits(G.GEN_ABSENT).none { it.start in h.end + 1..h.end + 3 && s.index.sameClause(h.end, it.start) }
        }
    }
    val urgency: Boolean by lazy { s.urgency || s.has(G.GEN_URGENCY) }

    /**
     * "Никому не рассказывайте о ситуации", "разговор конфиденциален". Not a
     * login code's "никому не сообщайте этот код / его", which guards the code.
     */
    val secrecy: Boolean by lazy {
        (s.hits(G.SECRECY) + s.hits(G.GEN_SECRECY)).any { h -> !guardsCode(h) }
    }

    private val codeWords: List<Hit> by lazy { s.hits(G.CODE_WORD) + s.hits(G.CODE_PRONOUN) + s.hits(G.GEN_SECRET) }

    private fun guardsCode(h: Hit): Boolean = codeWords.any {
        it.start in h.start..h.end + 3 && s.index.sameSentence(h.start, it.start)
    }

    /** Claims a role: a body we know, or "служба финансового контроля", "дознаватель", "регулятор". */
    val authority: Boolean by lazy { s.namesKnownBody || s.has(G.GEN_AUTHORITY) }

    /** "Напишите куратору: wa.me/…", "давайте в телеграм". */
    val chat: Boolean by lazy { s.chatMove || foreign.any { it.messenger } }

    // ── the sender's own site ─────────────────────────────────────────────

    /** The name the message signs with: the label before the first colon, or the alpha sender id. */
    private val signatures: List<String> by lazy {
        val label = SIGNATURE.find(s.text)?.groupValues?.get(1)?.takeIf { it.trim().split(SPACES).size <= 3 }
        listOfNotNull(label, s.sender?.takeIf { it.any(Char::isLetter) })
            .map { MessageText.normalizeWord(it).filter(Char::isLetterOrDigit) }
            .filter { it.length >= 3 }
    }

    /** "Ivi" signs ivi.ru, "Дом.ру" lk.domru.ru, "Mail.ru" id.mail.ru — a label, or the name with its zone. */
    private fun ownSite(link: LinkFacts): Boolean {
        if (signatures.isEmpty()) return false
        val parts = link.found.host.split('.').map { it.replace("-", "") }
        val labels = parts.dropLast(1) + listOfNotNull(parts.takeLast(2).takeIf { it.size == 2 }?.joinToString(""))
        return labels.filter { it.length >= 3 }.any { l -> signatures.any { spells(it, l) } }
    }

    private companion object {
        val IF = setOf("если", "if")
        /** "Оплатите 120 р за повторную доставку": the charge may sit a few words from the verb. */
        const val FEE_WINDOW = 6
        val SPACES = Regex("\\s+")
        /** "Ivi:", "Мосэнергосбыт:", "Дом.ру:" at the very start. */
        val SIGNATURE = Regex("""^\s*([^:\n]{2,30}):""")

        /** Latin spellings of each Cyrillic letter, as Russian brands write their domains. */
        val LATIN: Map<Char, List<String>> = mapOf(
            'а' to listOf("a"), 'б' to listOf("b"), 'в' to listOf("v", "w"), 'г' to listOf("g"), 'д' to listOf("d"),
            'е' to listOf("e", "ye"), 'ж' to listOf("zh", "j"), 'з' to listOf("z"), 'и' to listOf("i"),
            'й' to listOf("y", "i", "j", ""), 'к' to listOf("k", "c"), 'л' to listOf("l"), 'м' to listOf("m"),
            'н' to listOf("n"), 'о' to listOf("o"), 'п' to listOf("p"), 'р' to listOf("r"), 'с' to listOf("s"),
            'т' to listOf("t"), 'у' to listOf("u"), 'ф' to listOf("f"), 'х' to listOf("h", "kh", "x"),
            'ц' to listOf("c", "ts", "tz"), 'ч' to listOf("ch"), 'ш' to listOf("sh"), 'щ' to listOf("sch", "sh", "shch"),
            'ъ' to listOf(""), 'ы' to listOf("y", "i"), 'ь' to listOf(""), 'э' to listOf("e"),
            'ю' to listOf("yu", "ju", "u"), 'я' to listOf("ya", "ja", "a"),
        )

        /** Does the Latin host label [latin] spell the signature [name] (Latin as is, Cyrillic transliterated)? */
        fun spells(name: String, latin: String): Boolean {
            fun go(i: Int, j: Int): Boolean {
                if (i == name.length) return j == latin.length
                val options = LATIN[name[i]] ?: listOf(name[i].toString())
                return options.any { o -> latin.startsWith(o, j) && go(i + 1, j + o.length) }
            }
            return go(0, 0)
        }
    }
}

/**
 * The generic layer: warnings from ingredients, whatever the scheme.
 *
 * DANGEROUS:
 *  - a foreign link and two of: money asked, a code or data asked, a promise, a threat;
 *  - a code asked for a person, by someone claiming a role or under pressure,
 *    secrecy or a coming call;
 *  - a claimed authority with secrecy and a call (coming or back), money or a code;
 *  - secrecy over money to move, with a threat or a claimed authority;
 *  - a threat from a claimed authority with a personal number to call back;
 *  - a foreign link from a claimed authority with a threat or a request for data.
 * CAUTION:
 *  - a foreign link and one of them — money only as an order, through a page
 *    that can take it, for a fee or card details (a booking or a class trip
 *    is paid for the thing itself); a promise only of money, with something
 *    to claim or a chat to write to, and not a shop's cashback or points;
 *  - a promise or a threat with a personal number to call back;
 *  - a claimed authority with a coming call, secrecy or orders to obey;
 *  - money to a card number written out, with a threat or secrecy.
 *
 * A city number is how public offices and housing firms really answer, so
 * only a mobile or foreign one is a callback here.
 *
 * Thresholds picked on MessageGenericCorpus (scam paraphrases and the
 * legitimate traffic that carries the same ingredients), not guessed.
 * It only adds: it runs after the scheme rules, leaves a message they found
 * dangerous exactly as they left it, and can raise a caution to dangerous.
 */
internal object GenericLayer {

    fun judge(s: MessageSignals, danger: MutableSet<String>, caution: MutableSet<String>) {
        // Already dangerous by a scheme rule: nothing to add, and the scheme's reasons say it best.
        if (danger.isNotEmpty()) return
        val g = GenericSignals(s)
        val linked = g.foreign.isNotEmpty()
        val core = listOf(g.moneyAsked, g.code, g.promise, g.threat).count { it }
        val moneyMoved = g.moneyAsked || s.moneyMove

        val dangerous = (linked && core >= 2) ||
            (g.codeToPerson && (g.authority || g.secrecy || g.threat || g.urgency || s.callComing)) ||
            (g.authority && g.secrecy && (s.callComing || s.callbackPersonal || moneyMoved || g.code)) ||
            (g.secrecy && moneyMoved && (g.threat || g.authority)) ||
            (g.threat && g.authority && s.callbackPersonal) ||
            (linked && g.authority && (g.threat || g.code))
        if (dangerous) {
            danger += reasons(s, g)
            return
        }
        val cautious = (linked && (g.threat || g.code)) ||
            (g.moneyDemanded && g.payable.isNotEmpty() && (g.feeDemanded || g.cardData || g.payable.any { it.suspicious })) ||
            (linked && g.promiseOfMoney && !g.promo && (g.claim || g.chat)) ||
            ((g.promise || g.threat) && s.callbackPersonal && !s.namesServiceOnly) ||
            (g.authority && s.callComing && (g.secrecy || s.obey)) ||
            (s.moneyMove && s.cardNumber && (g.threat || g.secrecy))
        if (cautious) caution += reasons(s, g)
    }

    /** The ingredients present, most important first, then why the links are a problem. */
    internal fun reasons(s: MessageSignals, g: GenericSignals): List<String> = buildList {
        if (g.authority) add(MessageAnalyzer.R_ORGANISATION)
        if (g.threat || g.urgency) add(MessageAnalyzer.R_THREAT)
        if (g.codeToPerson || g.codeOnSite) add(MessageAnalyzer.R_CODE)
        if (g.identityAsked) add(MessageAnalyzer.R_CONFIRM_DATA)
        if (g.moneyAsked) add(MessageAnalyzer.R_PAYMENT)
        if (g.promise) add(MessageAnalyzer.R_BAIT)
        if (g.secrecy) add(MessageAnalyzer.R_SECRECY)
        if (s.callbackPersonal) add(MessageAnalyzer.R_CALL_UNKNOWN)
        addAll(MessageAnalyzer.linkReasons(g.foreign))
    }
}
