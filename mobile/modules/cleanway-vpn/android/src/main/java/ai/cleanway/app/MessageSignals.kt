package ai.cleanway.app

import ai.cleanway.app.MessageRules.Companion as G
import ai.cleanway.app.MessageRules.Kind

/** One link with everything the rules need to know about it. */
internal data class LinkFacts(
    val found: FoundLink,
    val status: LinkStatus,
    val shortener: Boolean,
    val messenger: Boolean,
    /** Belongs to a known organisation or a trusted body (NOT a safety verdict). */
    val official: Boolean,
    /** Not official, yet its name carries a brand ("sberbank-bonus.ru"). */
    val imitatesBrand: Boolean,
    /** The brand it carries is a state body's: "shtraf-oplata.online", "nalog-vozvrat.site". */
    val imitatesState: Boolean = false,
) {
    /** A link whose destination is hidden, disguised or unusual — worse than just "not the brand's". */
    val suspicious: Boolean
        get() = !official && (shortener || messenger || found.isIp || found.mixedScript || found.isApk || imitatesBrand)

    /**
     * The person marked the site "not a scam". A system host is NOT vouched
     * for: the shield only never blocks docs.google.com so Android keeps
     * working, and anyone can publish a page there.
     */
    val vouched: Boolean get() = status == LinkStatus.ALLOWED_BY_USER

    /** A link that is not the organisation's own, and that the person has not vouched for. */
    val unofficial: Boolean get() = !official && !vouched
}

/**
 * The signal groups of one message (see the rule shape in MessageAnalyzer).
 *
 * Each group is a fact about the text — "names a bank", "asks to call a
 * number" — and none of them is a verdict. Imperatives are checked for
 * negation ("никому не сообщайте код") and for the awareness framing banks
 * use ("мошенники просят перевести…"), because the same words carry the
 * opposite meaning there.
 */
internal class MessageSignals(
    internal val rules: MessageRules,
    internal val index: WordIndex,
    internal val text: String,
    private val hiddenInWord: Boolean,
    val links: List<LinkFacts>,
    val phones: List<PhoneExtractor.Phone>,
    internal val sender: String?,
) {
    private val cache = HashMap<String, List<Hit>>()
    internal fun hits(group: String): List<Hit> = cache.getOrPut(group) { index.hits(rules.group(group)) }
    internal fun has(group: String): Boolean = hits(group).isNotEmpty()

    // ── who the message claims to be ───────────────────────────────────────

    val organisations: List<MessageRules.Organisation> by lazy {
        rules.organisations.filter { org -> org.names.any { index.hits(it).isNotEmpty() } }
    }
    /** A body scammers impersonate and whose domains we know (not a housing office). */
    val namesKnownBody: Boolean get() = organisations.any { it.kind != Kind.SERVICE }
    /** Government, law enforcement or a bank — the callback and safe-account families. */
    val namesAuthority: Boolean get() = organisations.any { it.kind in AUTHORITY }
    val namesAnyBody: Boolean get() = organisations.isNotEmpty()
    /** Government or law enforcement — they never pay out or collect through a link. */
    val namesState: Boolean get() = organisations.any { it.kind == Kind.GOV || it.kind == Kind.SECURITY }
    /** Only a housing office, intercom firm or the like — bodies that do text their own numbers. */
    val namesServiceOnly: Boolean get() = organisations.isNotEmpty() && organisations.all { it.kind == Kind.SERVICE }
    /** The police, the FSB, the Central Bank — the "a caller will guide you" family. */
    val namesSecurity: Boolean get() = organisations.any { it.kind == Kind.SECURITY }
    /** A bank named by its own name ("ВТБ", "Сбер"), not only by the "банк*" catch-all. */
    val namesBankByName: Boolean get() = organisations.any { it.kind == Kind.BANK && !it.catchAll }
    /** Ozon, Wildberries, Яндекс Маркет, Почта — the names on the task-scam job offers. */
    val namesMarketplace: Boolean get() = organisations.any { it.kind == Kind.DELIVERY }
    /** Only a catch-all ("Банк Уралсиб" → "банк*"): its real site may simply be one we do not know. */
    val namesOnlyCatchAll: Boolean get() = organisations.isNotEmpty() && organisations.all { it.catchAll }
    /** Only a messenger ("напишите нам в WhatsApp"): named to say where its chat link leads. */
    val namesOnlyMessenger: Boolean get() = organisations.isNotEmpty() && organisations.all { it.kind == Kind.MESSENGER }

    // ── pressure and bait ─────────────────────────────────────────────────

    /** "Выполняйте его указания", "не кладите трубку": obey the caller — pressure of its own. */
    val obey: Boolean by lazy { has(G.OBEY) }
    /** A threat in words — "уголовное дело", "заблокирована" — not only an order to obey. */
    val threatWords: Boolean by lazy { has(G.THREAT) }
    val threat: Boolean by lazy { threatWords || obey }
    val urgency: Boolean by lazy { has(G.URGENCY) || within() || dateDeadline() }
    val confirmData: Boolean by lazy { hits(G.CONFIRM_DATA).any { active(it) } }
    val pressure: Boolean get() = threat || urgency || confirmData
    /** Pressure beyond a bare "до 31.10", which is also how every promotion ends. */
    val pressureBeyondDate: Boolean get() = threat || has(G.URGENCY) || within() || confirmData
    val bait: Boolean by lazy { has(G.BAIT) }
    /** Money handed OUT — a payout, a win, a compensation — not a shop's cashback or bonus points. */
    val payout: Boolean by lazy { has(G.PAYOUT) }
    /** "Подработка", "оценка товаров", "за отзывы": the task-scam job offer. */
    val jobOffer: Boolean by lazy { has(G.JOB_OFFER) }

    // ── what it asks the reader to do ─────────────────────────────────────

    val callAsked: Boolean by lazy { hits(G.CALL).any { active(it) } }
    private val unofficialPhones by lazy { phones.filter { it.number !in rules.officialPhones } }
    /** Call a personal, city or foreign number that is no organisation's official one. */
    val callbackStrong: Boolean by lazy { callAsked && unofficialPhones.any { it.kind != PhoneExtractor.Kind.TOLL_FREE } }
    /** Call a mobile or foreign number: an organisation does not work from someone's personal phone (41-FZ). */
    val callbackPersonal: Boolean by lazy {
        callAsked && unofficialPhones.any { it.kind == PhoneExtractor.Kind.MOBILE || it.kind == PhoneExtractor.Kind.FOREIGN }
    }
    /** Call an 8-800 number that is not on our official list — weaker: scammers rarely rent them. */
    val callbackWeak: Boolean by lazy { callAsked && !callbackStrong && unofficialPhones.isNotEmpty() }
    /**
     * "Вам позвонит следователь", "ожидайте звонка": a call to the reader is
     * coming. Not "если вам позвонит «следователь»…" — the police warning
     * about that call — and not "вам не позвонят".
     */
    val callComing: Boolean by lazy {
        hits(G.CALL_COMING).any { h ->
            active(h) && !conditional(h.start) && (h.start..h.end).none { index.isWord(it, rules.negators) }
        }
    }

    val codeAsked: Boolean by lazy { codeToPerson() || flashCallDigits() }
    /** Live instructions to move money: an imperative, or an infinitive after "необходимо". */
    private val liveMoneyVerbs: List<Hit> by lazy {
        hits(G.MONEY_VERB).filter { active(it) } + hits(G.MONEY_REQUEST).filter { active(it) } +
            hits(G.MONEY_INFINITIVE).filter { active(it) && directiveBefore(it) }
    }
    /**
     * "Выручи" moves money only next to a card number or a sum: "мам, выручи,
     * забери Сашу из садика" asks for no money at all.
     */
    private val moneyPlea: Boolean by lazy {
        (cardNumber || amount()) && hits(G.MONEY_PLEA).any { active(it) }
    }
    val moneyMove: Boolean get() = liveMoneyVerbs.isNotEmpty() || moneyPlea
    /** A full card number written out: where the money is to go. */
    val cardNumber: Boolean by lazy { CARD_NUMBER.containsMatchIn(text) }
    val safeAccount: Boolean by lazy { hits(G.SAFE_ACCOUNT).any { safeAccountActive(it) } }
    val payAsked: Boolean by lazy { hits(G.PAY_VERB).any { active(it) } }
    /**
     * Pay a fee, duty or delivery charge — "оплатите без комиссии" is the
     * opposite. The charge may also come first, as unpaid: "не оплачена
     * доставка 189 ₽. Оплатите по ссылке…".
     */
    val fee: Boolean by lazy {
        hits(G.PAY_VERB).any { p ->
            active(p) && hits(G.FEE_WORD).any { f -> follows(p, f, 4) && !index.isWord(f.start - 1, WITHOUT) }
        } || (payAsked && hits(G.FEE_UNPAID).any { u -> hits(G.FEE_WORD).any { f -> follows(u, f, 2) || follows(f, u, 2) } })
    }
    val install: Boolean by lazy { hits(G.INSTALL).any { active(it) } }
    val malwareLure: Boolean by lazy { has(G.MALWARE_LURE) }
    val smsTransferCommand: Boolean by lazy {
        has(G.SMS_COMMAND) && (phones.isNotEmpty() || index.words.any { it.isNumber && it.forms[0].length >= 10 })
    }

    // ── relative in trouble ───────────────────────────────────────────────

    val kin: Boolean by lazy { has(G.KIN) }
    val newNumber: Boolean by lazy { has(G.NEW_NUMBER) }
    val emergency: Boolean by lazy { has(G.EMERGENCY) }
    val secrecy: Boolean by lazy { has(G.SECRECY) }

    val disguised: Boolean get() = index.disguised || hiddenInWord

    // ── the boss and the vote ─────────────────────────────────────────────

    /** "Ваш руководитель", "это директор": FakeBoss relays a call from the security services. */
    val boss: Boolean by lazy { has(G.BOSS) }
    /** "Проголосуй за мою племянницу": the vote that needs "a code from the SMS" takes over the account. */
    val vote: Boolean by lazy { hits(G.VOTE).any { active(it) } }
    /** The message talks about a code at all (not a door code, not the bank's code word). */
    val codeMentioned: Boolean by lazy {
        hits(G.CODE_WORD).any { c -> hits(G.CODE_HOUSEHOLD).none { follows(c, it, 2) } }
    }

    // ── the 2026-10 schemes ───────────────────────────────────────────────

    /** "Иначе разошлю всем твоим контактам", "видео увидят все": a leak, threatened. */
    val leakThreat: Boolean by lazy { has(G.LEAK_THREAT) }
    /** Intimate material — "интимные фото", "сайты для взрослых", "компромат". */
    val intimate: Boolean by lazy { has(G.INTIMATE) }
    /**
     * Money demanded at all: a sum, a card, a pay or transfer verb — even
     * under "если не оплатите", since a blackmailer's condition is the demand.
     */
    val moneyDemand: Boolean by lazy {
        amount() || cardNumber || has(G.PAY_VERB) || has(G.MONEY_VERB) || has(G.MONEY_INFINITIVE)
    }
    /** A dating site or app — the fake date's opening. */
    val dating: Boolean by lazy { has(G.DATING) }
    /** "Купи билеты тут", "забронируй столик": the fake date's payment. */
    val ticketBuy: Boolean by lazy { hits(G.TICKET_BUY).any { active(it) } }

    /**
     * The reader recruited as a drop: "сдай карту в аренду", "принимай переводы
     * на свою карту и переводи дальше", "нужны дропы" — with a cut for it. A
     * warning that names the same offer names the crime too ("уголовное").
     */
    val muleOffer: Boolean by lazy {
        hits(G.MULE_OFFER).any { active(it) } && (has(G.MULE_REWARD) || PERCENT_CUT.containsMatchIn(text)) &&
            !has(G.LEGAL_WARNING) && !safetyNotice
    }
    /** "Требуются курьеры: забирать наличные у клиентов" — the cash courier of the safe-account scams. */
    val cashJob: Boolean by lazy {
        hits(G.CASH_JOB).any { active(it) } && (has(G.HIRE) || jobOffer) && !has(G.LEGAL_WARNING) && !safetyNotice
    }

    /** A classified ad, its buyer or its seller. */
    val listing: Boolean by lazy { has(G.LISTING) }
    /** "Получите деньги", "для получения средств": money said to wait for the reader. */
    val receiveMoney: Boolean by lazy { hits(G.RECEIVE_MONEY).any { active(it) } }
    /** "Безопасная сделка", "Авито Доставка": the marketplace's own feature, offered by a stranger. */
    val safeDeal: Boolean by lazy { has(G.SAFE_DEAL) }
    /** "Давайте продолжим в WhatsApp", "напишите в телеграм". */
    val chatMove: Boolean by lazy { has(G.CHAT_MOVE) }

    /** "Установите", "скачайте": an install verb, live. */
    val installVerb: Boolean by lazy { hits(G.INSTALL_VERB).any { active(it) } }
    /** "Установите RustDesk", "скачайте AnyDesk": a remote-access app the reader is told to put on the phone. */
    val remoteAsked: Boolean by lazy { has(G.REMOTE_APP) && installVerb }
    /** "Приложите карту к задней панели телефона": the NFC relay that copies the card. */
    val nfcTap: Boolean by lazy { hits(G.NFC_TAP).any { active(it) } }
    /** "Для возврата средств", "для защиты сбережений": the pretext of the relay and remote-access apps. */
    val refund: Boolean by lazy { has(G.REFUND) }
    /** "Файл vozvrat.apk": an app package named in words, with no link to check. */
    val apkNamed: Boolean by lazy { has(G.APK_WORD) }
    /** The message is about the reader's money at all. */
    val moneyContext: Boolean by lazy { has(G.MONEY_CONTEXT) || refund }

    /** "Снимите наличные и передайте курьеру / инкассатору": cash handed to a stranger at the door. */
    val cashHandover: Boolean by lazy { hits(G.CASH_HANDOVER).any { active(it) && !conditional(it.start) } }

    /** "Ошибся номером", "указал ваш номер по ошибке": the pretext for "send me my code". */
    val wrongNumber: Boolean by lazy { has(G.WRONG_NUMBER) }

    /** "По новому закону", "перерегистрация": the SIM re-registration pretext. */
    val lawPretext: Boolean by lazy { has(G.LAW_PRETEXT) }
    /** "Пришлите фото паспорта": a passport or СНИЛС sent to whoever wrote. */
    val passportAsked: Boolean by lazy {
        hits(G.CODE_VERB).any { v -> active(v) && hits(G.PASSPORT).any { follows(v, it, 4) } }
    }

    /** "Вы вызываетесь в качестве свидетеля", "судебное уведомление", "подан иск". */
    val summons: Boolean by lazy { hits(G.SUMMONS).any { active(it) } }
    /** "По делу № 12-4471/2026", "ст. 159 УК РФ": a case or an article cited. */
    val caseCited: Boolean by lazy { CASE_NUMBER.containsMatchIn(text) || ARTICLE.containsMatchIn(text) }

    /** "Из органов", "из компетентных органов": the security services, left unnamed. */
    val organs: Boolean by lazy { has(G.ORGANS) }
    /**
     * "Куратор", "из ведомства" — vague on their own (a project has a
     * curator too), so only next to what they would be investigating:
     * "проверка", "утечка", "дело".
     */
    val organsVague: Boolean by lazy { has(G.ORGANS_VAGUE) && has(G.PROBE) }

    /**
     * .apk links. Sideloading is the harm itself, so only an app store or the
     * named organisation's own site is expected to hand one out: a file on
     * Yandex Disk or in a VK post is not the bank's app, whoever it claims.
     */
    val apkLinks: List<LinkFacts> by lazy {
        val own = organisations.flatMap { it.domains }.toSet()
        links.filter { l ->
            l.found.isApk && !l.vouched && !HostNames.under(l.found.host, rules.appStores) &&
                !(l.official && HostNames.under(l.found.host, own))
        }
    }

    // ── legitimate shapes ─────────────────────────────────────────────────

    val loginCode: Boolean by lazy {
        hits(G.CODE_LABEL).any { h -> numberNear(h.start, window = 4, digits = 4..8) }
    }
    val paymentAlert: Boolean by lazy { amount() && has(G.PAYMENT_OP) && (CARD_MASK.containsMatchIn(text) || has(G.BALANCE_WORD)) }
    val pickupCode: Boolean by lazy { has(G.PICKUP) && index.words.any { it.isNumber && it.forms[0].length in 3..8 } }
    val publicAlert: Boolean by lazy { has(G.PUBLIC_ALERT) }
    val safetyNotice: Boolean by lazy { has(G.AWARENESS) }
    /** A code the reader is told to hand over is IN the message ("назовите курьеру код 5930"). */
    internal val codeInMessage: Boolean by lazy { hits(G.CODE_WORD).any { numberNear(it.start, window = 3, digits = 3..8) } }

    // ── sender (optional; only ever adds suspicion) ───────────────────────

    /** An organisation writing from an ordinary personal number (41-FZ: organisations must be labelled). */
    val senderPersonal: Boolean by lazy {
        val s = sender?.takeIf { it.isNotBlank() } ?: return@lazy false
        PhoneExtractor.extract(s).any { it.kind != PhoneExtractor.Kind.TOLL_FREE && it.number !in rules.officialPhones }
    }
    /** Claims to be Госуслуги but the sender is not one of its ids (МВД's first sign of a fake). */
    val senderMismatch: Boolean by lazy {
        val s = sender?.trim()?.lowercase()?.takeIf { it.isNotEmpty() } ?: return@lazy false
        val only = organisations.singleOrNull() ?: return@lazy false
        only.senders.isNotEmpty() && only.kind == Kind.GOV && !senderPersonal && s !in only.senders
    }

    // ── helpers ───────────────────────────────────────────────────────────

    /** Not negated ("не сообщайте") and not described as what scammers do. */
    internal fun active(hit: Hit): Boolean = !negated(hit.start) && !aware(hit.start)

    internal fun negated(i: Int): Boolean {
        if (index.isWord(i - 1, rules.negators) && index.sameClause(i - 1, i)) return true
        return index.isWord(i - 2, rules.negators) && index.isWord(i - 1, rules.intermediates) &&
            index.sameClause(i - 2, i)
    }

    internal fun aware(i: Int): Boolean =
        hits(G.AWARENESS).any { it.end < i && i - it.end <= AWARE_WINDOW && index.sameSentence(it.end, i) }

    /**
     * "…попросит назвать", "необходимо сообщить": a live request right before the
     * infinitive. Not "банк не попросит вас назвать", not "если сотрудник
     * попросит назвать код — это мошенники".
     */
    private fun codeRequested(h: Hit): Boolean = (hits(G.DIRECTIVE) + hits(G.CODE_REQUEST)).any { d ->
        d.end < h.start && h.start - d.end <= 2 && index.sameClause(d.end, h.start) && active(d) && !conditional(d.start)
    }

    /** An "если"/"if" earlier in the same clause: the sentence describes a case, it does not instruct. */
    internal fun conditional(i: Int): Boolean {
        var j = i - 1
        while (j >= 0 && index.sameClause(j, i)) {
            if (index.isWord(j, IF)) return true
            j--
        }
        return false
    }

    private fun directiveBefore(h: Hit): Boolean =
        hits(G.DIRECTIVE).any { d -> d.end < h.start && h.start - d.end <= 2 && index.sameClause(d.end, h.start) }

    /** Does [g] start within [after] words after [h], in the same sentence? */
    internal fun follows(h: Hit, g: Hit, after: Int): Boolean =
        g.start > h.end && g.start - h.end <= after && index.sameSentence(h.end, g.start)

    /**
     * "Продиктуйте код оператору", "сообщите ему код из SMS — мастер позвонит",
     * "перешли мне его", "никому не сообщайте код, кроме сотрудника, который
     * позвонит". A pickup code you tell the courier is the legitimate twin of
     * this sentence (see [pickupHandover]).
     */
    private fun codeToPerson(): Boolean {
        if (pickupHandover()) return false
        // "Продиктуйте код" needs no listener named: one only dictates to a person.
        if (hits(G.CODE_DICTATE).any { v -> active(v) && takesCode(v) }) return true
        // "Мастер позвонит и попросит назвать код", "нужно будет сообщить ему код":
        // the infinitive is an instruction once something asks for it.
        // "Ошибся номером… можете отправить его?": the stranger's plea is the request.
        val infinitive = hits(G.CODE_INFINITIVE).any { v -> active(v) && (codeRequested(v) || wrongNumber) && takesCode(v) }
        val asked = infinitive || hits(G.CODE_VERB).any { v -> active(v) && takesCode(v) }
        // "…назовите код из СМС": a real code SMS never asks to pass on another one.
        if (asked && (has(G.CODE_TARGET) || has(G.CALL_CONTEXT) || has(G.CODE_INCOMING) || wrongNumber)) return true
        return hits(G.CODE_VERB).any { v -> negated(v.start) && takesCode(v) && exceptListener(v) }
    }

    /**
     * The verb takes a code: "код"/"пароль" after it (not "код от домофона"),
     * or "его"/"этот код" once the message has already named one — "Ваш код
     * 4412. Продиктуйте его оператору".
     */
    private fun takesCode(v: Hit): Boolean {
        val direct = hits(G.CODE_WORD).any { c ->
            follows(v, c, 6) && hits(G.CODE_HOUSEHOLD).none { follows(c, it, 2) }
        }
        return direct || (hits(G.CODE_PRONOUN).any { follows(v, it, 2) } && hits(G.CODE_LABEL).any { it.start < v.start })
    }

    /** "Никому не сообщайте код, кроме сотрудника…": the negation carves out the very listener it warns about. */
    private fun exceptListener(v: Hit): Boolean = hits(G.CODE_EXCEPT).any { x ->
        follows(v, x, 8) && (hits(G.CODE_TARGET) + hits(G.CALL_CONTEXT)).any { follows(x, it, 3) }
    }

    /**
     * Telling a courier the pickup code: a courier or pickup point, only a
     * carrier in the story, and a carrier named or the code in the message
     * ("СДЭК: назовите курьеру код 5930"). A bank or Госуслуги behind the
     * "курьер", or a code that is still to arrive by SMS from nobody, is the
     * fake-delivery pretext.
     */
    internal fun pickupHandover(): Boolean =
        has(G.PICKUP_CONTEXT) && organisations.all { it.kind == Kind.DELIVERY } &&
            (organisations.isNotEmpty() || codeInMessage)

    /** "Назовите последние 4 цифры номера, который вам позвонит" — the flash-call code. */
    private fun flashCallDigits(): Boolean = hits(G.FLASH_CALL).any { f ->
        hits(G.CODE_VERB).any { v -> active(v) && index.sameSentence(v.start, f.start) }
    }

    /**
     * The safe-account family. The phrase alone appears in every bank's
     * warning ("банк никогда не просит переводить деньги на безопасный
     * счёт"), so it counts only when the verb that governs it is a live
     * instruction, or — with no money verb before it — nothing negates it and
     * nothing right after it names it a scam ("…безопасный счёт — уловка
     * мошенников", "…безопасных счетов не существует").
     */
    private fun safeAccountActive(h: Hit): Boolean {
        if (aware(h.start)) return false
        val verbs = (hits(G.MONEY_VERB) + hits(G.MONEY_INFINITIVE) + hits(G.MONEY_REQUEST))
            .filter { it.start < h.start && index.sameSentence(it.start, h.start) }
        if (verbs.isNotEmpty()) return verbs.any { it in liveMoneyVerbs }
        if (hits(G.SCAM_LABEL).any { follows(h, it, LABEL_WINDOW) }) return false
        var j = h.start - 1
        while (j >= 0 && index.sameClause(j, h.start)) {
            if (index.isWord(j, rules.negators)) return false
            j--
        }
        return true
    }

    private fun numberNear(i: Int, window: Int, digits: IntRange): Boolean =
        (maxOf(0, i - window)..minOf(index.words.size - 1, i + window)).any { j ->
            val w = index.words[j]
            w.isNumber && w.forms[0].length in digits
        }

    /** "356р", "1 500 руб", "RUB 1299" — a sum of money. */
    internal fun amount(): Boolean {
        val words = index.words
        val currency = rules.group(G.CURRENCY)
        fun isCurrency(j: Int) = j in words.indices && currency.any { it.stems.size == 1 && it.stems[0].matches(words[j]) }
        return words.indices.any { j ->
            val w = words[j]
            GLUED_AMOUNT.matches(w.forms[0]) ||
                (w.isNumber && (isCurrency(j + 1) || isCurrency(j - 1)))
        }
    }

    /** "в течение 24 часов", "через 2 часа". */
    private fun within(): Boolean = WITHIN.containsMatchIn(text)

    /** Russian typed in Latin letters (see [MessageText.index]). */
    private val translit: Boolean by lazy { index.words.any { it.translit } }

    /** "до 23:59", "до 30.09" ("do 30.09" in Latin letters) — a deadline, not a time range ("с 10:00 до 14:00"). */
    private fun dateDeadline(): Boolean = (if (translit) DEADLINE_LATIN else DEADLINE).findAll(text).any { m ->
        val before = text.substring(maxOf(0, m.range.first - 16), m.range.first)
        !RANGE_START.containsMatchIn(before)
    }

    private companion object {
        val AUTHORITY = setOf(Kind.GOV, Kind.SECURITY, Kind.BANK)
        const val AWARE_WINDOW = 5
        const val LABEL_WINDOW = 4
        val WITHOUT = setOf("без", "no", "without")
        val IF = setOf("если", "if")
        /** 16 digits in fours with a Mir, Visa, Mastercard or UnionPay first digit. */
        val CARD_NUMBER = Regex("""(?<![\p{N}])[2-6]\d{3}(?:[ -]?\d{4}){3}(?![\p{N}])""")

        val CARD_MASK = Regex(
            """(?:[*•]{1,4}|[xх]{2,4})\s?\d{4}(?!\d)|(?<!\p{L})(?:mir|visa|ecmc|mc|maestro|мир|сч[её]т|сч|карт\p{L}{0,2}|card)\s?[-*•.]{0,4}\s?\d{4}(?!\d)""",
            RegexOption.IGNORE_CASE,
        )
        val GLUED_AMOUNT = Regex("""^\d+(?:р|руб\p{L}*|rub|rur)$""")
        val DEADLINE = Regex("""(?<![\p{L}\p{N}])до\s+\d{1,2}[.:]\d{2}(?!\d)""", RegexOption.IGNORE_CASE)
        val DEADLINE_LATIN = Regex("""(?<![\p{L}\p{N}])do\s+\d{1,2}[.:]\d{2}(?!\d)""", RegexOption.IGNORE_CASE)
        val RANGE_START = Regex("""(?<!\p{L})[сcs]\s*\d{1,2}[.:]\d{2}\s*[-–—]?\s*$""", RegexOption.IGNORE_CASE)
        /** "10% от суммы", "5% тебе": the drop's cut. */
        val PERCENT_CUT = Regex("""\d{1,2}\s?%\s*(?:от|с|тебе|твои|твоих|себе|вам|ваши|за)(?!\p{L})""")
        /** "По делу № 12-4471/2026", "дело №1-245". */
        val CASE_NUMBER = Regex("""(?<!\p{L})дел[оауе]?\s*(?:№|n|номер)\s*\d""")
        /** "Ст. 159 УК РФ", "статья 395 ГК", "ст. 12.9 ч. 2 КоАП". */
        val ARTICLE = Regex(
            """(?<!\p{L})(?:ст\.?|стать\p{L}*)\s*\d{1,3}(?:\.\d{1,2})?(?:\s*ч\.?\s*\d)?\s*(?:ук|гк|коап|упк|гпк|апк)(?!\p{L})""",
        )
        val WITHIN = Regex(
            """(?<![\p{L}\p{N}])(?:(?:в\s+течение|within)\s+\d{1,3}\s*(?:час|мин|сут|дн|день|дня|hour|minute|day)|(?:через|in)\s+\d{1,3}\s*(?:час|сут|дн|день|дня|hour|day))""",
            RegexOption.IGNORE_CASE,
        )
    }
}
