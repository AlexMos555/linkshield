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
 * foreign link or an .apk; bait plus a fee; an SMS-banking transfer command;
 * a fine through a site named after a state body; a bank's payout through a
 * foreign link; a marketplace job through a chat; the police with a criminal
 * case, a coming call and orders to obey; and the 2026-10 schemes (see
 * [newSchemes]): intimate blackmail, recruiting a drop, a buyer's payment
 * behind a link, NFC relay and remote-access apps, cash for a courier, SIM
 * re-registration "by the new law", a summons with an article number,
 * FakeBoss with "из органов".
 * CAUTION: the partial combinations (A + foreign link; an authority + an
 * unknown number; pressure + a hidden link; a look-alike link; with no
 * organisation named, a fine, fee or payout through an unknown site; a fake
 * date's ticket link; a summons or the SIM law with a call still to come…).
 *
 * ## The generic layer
 *
 * Each rule above waits for its scheme's own words, so a paraphrase slips
 * past it. After them, [GenericLayer] scores the ingredients every scheme is
 * made of — money asked, a code or personal data asked, a promise of money, a
 * threat, urgency, secrecy, a claimed authority, a call back or to come — in
 * broad groups, and combines them: a foreign link and two of the first four
 * is dangerous, one is a caution (MessageGeneric.kt has the full table). It
 * only adds: a message the scheme rules found dangerous is left as it was.
 *
 * ## Legitimate shapes are excluded first
 *
 * A real login code ("никому не сообщайте код… позвоните на 900"), a bank
 * payment alert, a parcel pickup code, a public emergency alert. They use the
 * scam vocabulary on purpose, so none of them may raise a text warning — but
 * only while they carry no foreign link, no unknown callback number and no
 * request for the code, and their links are still checked against the list.
 *
 * ## The text model
 *
 * Last, [model] (MessageModel.kt, trained in ml/sms) scores how much the
 * whole text reads like a scam, paraphrase or not. It only adds, and never
 * to a legitimate shape or to a message the rules already found dangerous:
 *  - a score at or above its danger threshold, with at least one ingredient
 *    of the generic layer ([modelIngredients]: a foreign link, money asked or
 *    moved, a code or data asked, a promise, a threat, a personal number to
 *    call back, an app to install, secrecy) → dangerous;
 *  - a score at or above its caution threshold → at least caution.
 * Either adds the reason [R_TEXT_RESEMBLES_SCAM]. Thresholds and why they
 * hold: docs/EVALUATION_2026-10.md §3.14.
 *
 * The server can switch the model off, or raise its thresholds, without a new
 * APK ([remote], RemoteConfig.kt). Off, the analysis is exactly the rules'
 * one — the same as a build without the model's assets.
 *
 * Pure Kotlin: the link status comes in as a function, so the whole class is
 * JVM-testable against an in-memory BlockList.
 */
class MessageAnalyzer(
    private val rules: MessageRules,
    /** The text model; null runs the rules alone (a missing or broken asset). */
    private val model: MessageModel? = null,
    /** The server's switches for the model (RemoteConfig.kt): off, or quieter thresholds. */
    private val remote: RemoteConfig = RemoteConfig.DEFAULT,
    private val linkStatus: (String) -> LinkStatus,
) {
    fun analyze(text: String, sender: String? = null): MessageAnalysis {
        val truncated = text.length > MAX_CHARS
        val cut = if (truncated) text.substring(0, MAX_CHARS) else text
        val signals = read(cut, sender)
        val links = signals.links
        val phones = signals.phones
        val shape = legitShape(signals)
        val (ruleVerdict, ruleReasons) = decide(signals, excluded = shape != null)
        val active = model?.takeIf { remote.smsTextModelEnabled }
        val (verdict, reasons) = if (active == null || shape != null || ruleVerdict == MessageVerdict.DANGEROUS) {
            ruleVerdict to ruleReasons
        } else {
            withModel(active, cut, signals, ruleVerdict, ruleReasons)
        }
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

    /** What the text model adds to the rules' verdict (see the class comment): it only ever raises it. */
    private fun withModel(
        model: MessageModel,
        text: String,
        s: MessageSignals,
        verdict: MessageVerdict,
        reasons: List<String>,
    ): Pair<MessageVerdict, List<String>> {
        val g = GenericSignals(s)
        if (officialChannelsOnly(s, g)) return verdict to reasons
        val p = model.score(text) ?: return verdict to reasons
        val danger = remote.dangerThreshold(model.dangerThreshold)
        val caution = remote.cautionThreshold(model.cautionThreshold)
        if (p < danger && p < caution) return verdict to reasons
        return when {
            p >= danger && modelIngredients(s, g).isNotEmpty() ->
                MessageVerdict.DANGEROUS to (listOf(R_TEXT_RESEMBLES_SCAM) + reasons + GenericLayer.reasons(s, g)).distinct()
            p < caution -> verdict to reasons
            verdict == MessageVerdict.CAUTION -> verdict to (reasons + R_TEXT_RESEMBLES_SCAM).distinct()
            else -> MessageVerdict.CAUTION to (listOf(R_TEXT_RESEMBLES_SCAM) + GenericLayer.reasons(s, g)).distinct()
        }
    }

    /** The signals of [text], already cut to [MAX_CHARS]: links judged, phones found, words indexed. */
    internal fun read(text: String, sender: String? = null): MessageSignals {
        val cleaned = MessageText.clean(text)
        val found = LinkExtractor.extract(cleaned.text, rules.bareTlds)
        // Every link is judged; only the list the person sees is capped.
        val links = found.map { facts(it) }
        val phones = PhoneExtractor.extract(blank(cleaned.text, found.map { it.span }))
        return MessageSignals(
            rules = rules,
            index = MessageText.index(cleaned.text, found.map { it.span }, rules.translitMarkers),
            text = MessageText.normalizeWord(cleaned.text),
            hiddenInWord = cleaned.hiddenInWord,
            links = links,
            phones = phones,
            sender = sender,
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
        val imitated = if (official) emptyList() else imitated(link.host)
        return LinkFacts(
            found = link,
            status = linkStatus(link.host),
            shortener = HostNames.under(link.host, rules.shorteners),
            messenger = HostNames.under(link.host, rules.messengers),
            official = official,
            imitatesBrand = imitated.isNotEmpty(),
            imitatesState = imitated.any { it.kind == MessageRules.Kind.GOV || it.kind == MessageRules.Kind.SECURITY },
        )
    }

    /**
     * The organisations whose brand a non-official host carries.
     * "sberbank-bonus.ru", "gosuslugi-help.ru", "t2-gosuslugi.ru": a brand in a
     * name that is not the brand's. A short brand must stand as its own token
     * — "apple" inside goldapple.ru is a cosmetics shop, not Apple — and only
     * a long, distinctive one ("sberbank") may hide inside a longer word. A
     * five-letter Latin one may start one ("nalog" in nalogvozvrat.online);
     * the Cyrillic "альфа" may not, it starts too many ordinary names.
     * A Cyrillic name ("госуслуги-выплаты.рф") is read as written, not as its
     * punycode.
     */
    private fun imitated(host: String): List<MessageRules.Organisation> {
        val tokens = (hostTokens(host) + hostTokens(unicode(host))).distinct()
        return rules.organisations.filter { org ->
            org.domainTokens.any { brand ->
                tokens.any { t ->
                    t == brand || (brand.length >= 6 && (t.startsWith(brand) || t.endsWith(brand))) ||
                        (brand.length == 5 && brand.all { it in 'a'..'z' || it in '0'..'9' } && t.startsWith(brand)) ||
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

    internal fun legitShape(s: MessageSignals): String? {
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
            // Last, and only adding: the ingredients the scheme rules have no words for.
            GenericLayer.judge(s, danger, caution)
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
        // The state and the police do not pay out through a foreign link, and
        // neither does a bank we know by name ("компенсация по вкладам СССР").
        if ((s.namesState && s.bait || s.namesBankByName && s.payout) && foreign.isNotEmpty()) {
            out += listOf(R_ORGANISATION, R_BAIT) + linkReasons(foreign)
        }
        // "Штраф 3 000 ₽, оплатите: parkovka-shtraf.ru": nobody named in words, but
        // the site wears a state body's name, and the state collects on its own site.
        val stateLookalike = foreign.filter { it.imitatesState }
        if (s.threat && s.payAsked && stateLookalike.isNotEmpty()) {
            out += listOf(R_THREAT, R_PAYMENT) + linkReasons(stateLookalike)
        }
        // "Подработка на Ozon: оценка товаров, пишите t.me/…": a marketplace does not
        // hire for paid reviews through a Telegram or WhatsApp chat. A gig at a
        // shop down the road may well be passed on that way, so only marketplaces.
        val chats = foreign.filter { it.messenger }
        if (s.namesMarketplace && s.jobOffer && chats.isNotEmpty()) {
            out += listOf(R_ORGANISATION, R_BAIT) + linkReasons(chats)
        }
        if (s.codeAsked) out += if (s.namesAnyBody) listOf(R_CODE, R_ORGANISATION) else listOf(R_CODE)
        if (s.safeAccount && (s.moneyMove || s.namesAuthority || s.callbackStrong)) out += R_SAFE_ACCOUNT
        if (s.kin && s.moneyMove && (s.newNumber || s.emergency)) out += R_RELATIVE
        // FakeBoss: "это ваш руководитель — вам позвонит куратор из ФСБ, никому не
        // говорите". A real boss may pass on a police visit, never one to keep secret.
        if (s.boss && s.namesSecurity && s.callComing && s.secrecy) out += listOf(R_ORGANISATION, R_THREAT)
        // "Возбуждено уголовное дело по ст. 275… следователь свяжется, выполняйте его
        // указания": a real investigator summons, he does not order obedience by SMS.
        if (s.namesSecurity && s.threatWords && s.callComing && s.obey) out += listOf(R_ORGANISATION, R_THREAT)
        if (s.malwareLure && foreign.isNotEmpty()) out += listOf(R_MALWARE_LURE) + linkReasons(foreign)
        if (s.install && foreign.any { it.suspicious || s.namesKnownBody }) out += listOf(R_INSTALL) + linkReasons(foreign)
        if (s.apkLinks.isNotEmpty()) out += listOf(R_INSTALL) + linkReasons(s.apkLinks)
        if (s.bait && s.fee) out += listOf(R_BAIT, R_PAYMENT)
        if (s.smsTransferCommand) out += R_SMS_COMMAND
        newSchemes(s, foreign, out)
    }

    /**
     * The 2026-10 schemes the rules had no vocabulary for. Each needs the
     * scheme's own move, not its words: an intimate leak AND money; a drop
     * offer AND a cut; a buyer AND money waiting behind a link; a remote or
     * NFC app AND a bank or money; cash AND a stranger to hand it to.
     */
    private fun newSchemes(s: MessageSignals, foreign: List<LinkFacts>, out: MutableSet<String>) {
        val named = if (s.namesAnyBody) listOf(R_ORGANISATION) else emptyList()
        // "Переведи 20 000, иначе твои интимные фото увидят все": sextortion.
        if (s.leakThreat && s.intimate && (s.moneyDemand || foreign.isNotEmpty())) {
            out += listOf(R_THREAT, R_PAYMENT) + linkReasons(foreign)
        }
        // "Сдай карту в аренду, 5 000 ₽ в неделю", "принимай переводы и переводи
        // дальше за 10%", "требуются курьеры забирать наличные": the reader made a drop.
        if (s.muleOffer || s.cashJob) out += listOf(R_BAIT) + linkReasons(foreign)
        // "Покупатель оплатил ваш товар, получите деньги: avito-pay.site", "давайте в
        // WhatsApp, скину ссылку на безопасную сделку": a buyer never pays through a link.
        val sites = foreign.filter { !it.messenger }
        val chats = foreign.filter { it.messenger }
        if (s.listing && sites.isNotEmpty() && (s.receiveMoney || s.safeDeal || s.confirmData)) {
            out += listOf(R_PAYMENT) + linkReasons(sites)
        }
        if (s.listing && chats.isNotEmpty() && (s.receiveMoney || s.safeDeal)) out += listOf(R_PAYMENT) + linkReasons(chats)
        // "Приложите карту к задней панели телефона": NFC relay — with an app from a link or a
        // file, or a refund pretext. A wallet from the store may ask the same tap.
        if (s.nfcTap && (s.apkNamed || s.apkLinks.isNotEmpty() || foreign.isNotEmpty() || s.refund || s.payout)) {
            out += named + R_INSTALL + linkReasons(foreign)
        }
        // "Сбербанк: установите RustDesk", "скачайте AnyDesk, чтобы вернуть деньги".
        // An IT department installing AnyDesk on a work laptop names neither.
        if (s.remoteAsked && (s.namesKnownBody || s.moneyContext)) out += named + R_INSTALL + linkReasons(foreign)
        // "Установите приложение по ссылке, чтобы получить компенсацию / вернуть деньги".
        if (s.install && foreign.isNotEmpty() && (s.refund || s.payout || s.safeAccount)) out += listOf(R_INSTALL) + linkReasons(foreign)
        // "Файл vozvrat.apk — установите": a package handed over in words.
        if (s.apkNamed && (s.install || s.installVerb) && (s.namesKnownBody || s.moneyContext || s.pressure)) {
            out += named + R_INSTALL
        }
        // "Снимите наличные и передайте инкассатору / курьеру ЦБ": a bank never collects at the door.
        if (s.cashHandover && (s.namesAuthority || s.safeAccount || s.callComing || s.secrecy || s.obey)) {
            out += named + R_SAFE_ACCOUNT
        }
        // "По новому закону номер будет заблокирован — подтвердите паспорт: …", with a
        // link, a call-back, a passport photo or a code. Operators ask in the salon or on Госуслуги.
        if (s.lawPretext && (s.threat || s.urgency) &&
            (foreign.isNotEmpty() || s.callbackStrong || s.passportAsked || s.codeAsked)
        ) {
            out += pressureReasons(s) + (if (s.callbackStrong) listOf(R_CALL_UNKNOWN) else emptyList()) + linkReasons(foreign)
        }
        if (s.lawPretext && s.passportAsked) out += listOf(R_CONFIRM_DATA) + pressureReasons(s)
        // "Вы вызываетесь свидетелем по делу № …, ст. 159 УК — позвоните +7 9…". A court
        // does text hearings, with its own city number; never a mobile one or a site of its own.
        if (s.summons && s.caseCited && (s.callbackPersonal || foreign.isNotEmpty())) {
            out += named + R_THREAT + (if (s.callbackPersonal) listOf(R_CALL_UNKNOWN) else emptyList()) + linkReasons(foreign)
        }
        // FakeBoss without the FSB's name: "вам позвонят из органов… никому не говорите".
        if (s.boss && s.callComing && (s.secrecy || s.obey) && (s.organs || s.organsVague)) out += listOf(R_ORGANISATION, R_THREAT)
    }

    private fun cautious(s: MessageSignals, out: MutableSet<String>) {
        val foreign = s.links.filter { it.unofficial }
        val hidden = foreign.filter { it.suspicious }
        // Shops put "кешбэк до 30.09" behind clck.ru every day; a short link
        // earns caution only next to a threat or a request for data.
        val hiddenBeyondShortener = hidden.filter { !it.shortener || it.found.isApk || it.imitatesBrand }
        // "Вопросы? Напишите нам в WhatsApp: wa.me/…" names the messenger only to say
        // where its own chat link goes.
        val chatInvite = s.namesOnlyMessenger && foreign.all { it.messenger }
        if (s.namesKnownBody && foreign.isNotEmpty() && !chatInvite) {
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
        // "МВД: ожидайте звонка следователя, не кладите трубку / никому не сообщайте":
        // the coming call is the scam. A police warning ABOUT such calls names no
        // call to the reader ("если вам позвонят…") and gives no orders.
        if (s.namesSecurity && s.callComing && (s.obey || s.secrecy)) out += listOf(R_ORGANISATION, R_THREAT)
        // "Проголосуй за мою племянницу: golos-deti.site, подтверди кодом": the vote is the account takeover.
        if (s.vote && s.codeMentioned && foreign.isNotEmpty()) out += listOf(R_CODE) + linkReasons(foreign)
        nobodyNamed(s, foreign, out)
        // Partial schemes: blackmail before the price, the fake date's ticket site, a buyer
        // moving to a chat for "the money", a summons or the SIM law with the call still to come.
        if (s.leakThreat && s.intimate) out += R_THREAT
        if (s.dating && s.ticketBuy && foreign.isNotEmpty()) out += listOf(R_PAYMENT) + linkReasons(foreign)
        if (s.listing && s.chatMove && (s.receiveMoney || s.safeDeal)) out += listOf(R_PAYMENT) + linkReasons(foreign)
        if (s.summons && s.caseCited && (s.callComing || s.callbackWeak)) {
            out += (if (s.namesAnyBody) listOf(R_ORGANISATION) else emptyList()) + R_THREAT
        }
        if (s.lawPretext && (s.threat || s.urgency) && s.callComing) out += pressureReasons(s)
        if (s.install && foreign.isNotEmpty() && s.pressure) out += listOf(R_INSTALL) + linkReasons(foreign)
        if (s.namesKnownBody && s.senderPersonal) out += listOf(R_ORGANISATION, R_SENDER_PERSONAL)
        if (s.senderMismatch) out += listOf(R_ORGANISATION, R_SENDER_MISMATCH)
    }

    /**
     * Nobody named, so no site to compare the link with — but a fine, a fee,
     * a payout or "confirm your card or the account is frozen" through an
     * unknown site is the scam family itself ("Штраф 1500 р… оплатите:
     * oplata-pdd.ru", "положена доплата… до 01.10").
     */
    private fun nobodyNamed(s: MessageSignals, foreign: List<LinkFacts>, out: MutableSet<String>) {
        if (s.namesAnyBody || foreign.isEmpty()) return
        if (s.threat && s.payAsked) out += listOf(R_THREAT, R_PAYMENT) + linkReasons(foreign)
        // "Счёт будет заморожен — подтвердите данные карты: karta-zashita.ru".
        if (s.threat && s.confirmData) out += pressureReasons(s) + linkReasons(foreign)
        if (s.fee) out += listOf(R_PAYMENT) + linkReasons(foreign)
        if (s.payout && (s.urgency || s.confirmData)) out += pressureReasons(s) + R_BAIT + linkReasons(foreign)
    }

    private fun pressureReasons(s: MessageSignals): List<String> = buildList {
        if (s.threat || s.urgency) add(R_THREAT)
        if (s.confirmData) add(R_CONFIRM_DATA)
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
        const val R_SECRECY = "asks_for_secrecy"
        const val R_TEXT_RESEMBLES_SCAM = "text_resembles_scam"

        /** Every reason code the analyzer can emit — the UI must translate each one. */
        val ALL_REASONS = listOf(
            R_LINK_BLOCKLISTED, R_ORGANISATION, R_THREAT, R_CONFIRM_DATA, R_BAIT, R_CALL_UNKNOWN,
            R_LINK_NOT_OFFICIAL, R_LINK_SHORTENER, R_LINK_MESSENGER, R_LINK_IP, R_LINK_LOOKALIKE,
            R_LINK_IMITATES_BRAND, R_LINK_APK, R_CODE, R_SAFE_ACCOUNT, R_PAYMENT, R_RELATIVE, R_INSTALL,
            R_MALWARE_LURE, R_SMS_COMMAND, R_DISGUISED, R_SENDER_PERSONAL, R_SENDER_MISMATCH, R_SECRECY,
            R_TEXT_RESEMBLES_SCAM,
        )

        /**
         * Every link and number the message gives is the organisation's own
         * (or one the person vouched for): "Сбербанк: подозрительная операция,
         * позвоните 8 800 555-55-50" reads like a scam and is the bank. The
         * model cannot tell a real number from a fake one; the rules can.
         */
        internal fun officialChannelsOnly(s: MessageSignals, g: GenericSignals): Boolean =
            (s.links.isNotEmpty() || s.phones.isNotEmpty()) && g.foreign.isEmpty() &&
                s.phones.all { it.number in s.rules.officialPhones }

        /**
         * The rules' ingredients that let a high model score make a message
         * dangerous: something the reader is asked to do or is promised.
         * A score alone, on a text with none of them, stays a caution.
         */
        internal fun modelIngredients(s: MessageSignals, g: GenericSignals): List<String> = buildList {
            if (g.foreign.isNotEmpty()) add("foreign")
            if (g.moneyAsked) add("moneyAsked")
            if (s.moneyMove) add("moneyMove")
            if (g.code || s.codeAsked) add("code")
            if (g.promise) add("promise")
            if (g.threat) add("threat")
            if (s.callbackPersonal) add("callbackPersonal")
            if (s.install || s.apkLinks.isNotEmpty() || s.remoteAsked) add("install")
            if (g.secrecy) add("secrecy")
        }

        /** Why a set of links is a problem, most specific first after "not the brand's". */
        internal fun linkReasons(links: List<LinkFacts>): List<String> = buildList {
            if (links.any { !it.official }) add(R_LINK_NOT_OFFICIAL)
            if (links.any { it.shortener }) add(R_LINK_SHORTENER)
            if (links.any { it.messenger }) add(R_LINK_MESSENGER)
            if (links.any { it.found.isIp }) add(R_LINK_IP)
            if (links.any { it.found.mixedScript }) add(R_LINK_LOOKALIKE)
            if (links.any { it.imitatesBrand }) add(R_LINK_IMITATES_BRAND)
            if (links.any { it.found.isApk }) add(R_LINK_APK)
        }
    }
}
