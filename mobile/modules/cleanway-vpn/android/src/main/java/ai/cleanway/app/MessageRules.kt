package ai.cleanway.app

import org.json.JSONArray
import org.json.JSONObject

/**
 * The vocabulary of the on-device message check, parsed from the module
 * asset `message_rules.json`. Data only — which combinations raise a warning
 * is decided in [MessageAnalyzer], so a vocabulary edit can widen or narrow
 * what a group recognises but can never make one word a warning.
 *
 * Immutable once parsed; one instance is shared by every analysis.
 */
class MessageRules internal constructor(
    internal val groups: Map<String, List<Phrase>>,
    internal val organisations: List<Organisation>,
    internal val negators: Set<String>,
    internal val intermediates: Set<String>,
    val shorteners: Set<String>,
    val messengers: Set<String>,
    /** App stores and public bodies whose links never count as "not the brand's". */
    val trustedDomains: Set<String>,
    /** TLDs a bare (scheme-less) name may end in: every country code plus the generic ones scams use. */
    val bareTlds: Set<String>,
    /**
     * Hosts under an official domain where anyone can upload (disk.yandex.ru,
     * forms.yandex.ru): never official, whatever domain they sit under.
     */
    val userContentHosts: Set<String>,
    /** Where an .apk link is expected: app stores. Anywhere else sideloading is the harm. */
    val appStores: Set<String>,
) {
    /** Kind of body a message claims to come from; decides which rules apply. */
    enum class Kind { GOV, SECURITY, BANK, OPERATOR, DELIVERY, MESSENGER, COMPANY, SERVICE }

    internal data class Organisation(
        val id: String,
        val kind: Kind,
        val names: List<Phrase>,
        val domains: Set<String>,
        /** Host tokens that name the brand ("sberbank" in sberbank-bonus.ru). */
        val domainTokens: Set<String>,
        /** Normalised official numbers, short service numbers included. */
        val phones: Set<String>,
        /** Alpha or short sender ids the organisation really sends from. */
        val senders: Set<String>,
        /**
         * A catch-all ("банк*") for bodies we have no list of domains for: a
         * link can look foreign only because we do not know the real site.
         */
        val catchAll: Boolean = false,
    )

    internal fun group(name: String): List<Phrase> = groups[name].orEmpty()

    /** Every official number of every organisation: calling one of these is never "unknown". */
    internal val officialPhones: Set<String> by lazy { organisations.flatMap { it.phones }.toSet() }

    /** Every official domain, plus the trusted ones. */
    internal val officialDomains: Set<String> by lazy {
        organisations.flatMap { it.domains }.toSet() + trustedDomains
    }

    /** Belongs to a known organisation or a trusted body, and is not an upload host (NOT a safety verdict). */
    internal fun isOfficial(host: String): Boolean =
        HostNames.under(host, officialDomains) && !HostNames.under(host, userContentHosts)

    companion object {
        // Group names the analyzer reads. A missing group degrades to "never
        // matches" — the check gets weaker, never louder.
        const val THREAT = "threat"
        const val URGENCY = "urgency"
        const val CONFIRM_DATA = "confirm_data"
        const val BAIT = "bait"
        const val CALL = "call"
        const val CODE_VERB = "code_verb"
        const val CODE_DICTATE = "code_dictate"
        const val CODE_WORD = "code_word"
        const val CODE_TARGET = "code_target"
        const val CALL_CONTEXT = "call_context"
        const val PICKUP_CONTEXT = "pickup_context"
        const val FLASH_CALL = "flash_call"
        const val MONEY_VERB = "money_verb"
        const val MONEY_INFINITIVE = "money_infinitive"
        const val DIRECTIVE = "directive"
        const val MONEY_REQUEST = "money_request"
        const val SAFE_ACCOUNT = "safe_account"
        const val PAY_VERB = "pay_verb"
        const val FEE_WORD = "fee_word"
        const val INSTALL = "install"
        const val MALWARE_LURE = "malware_lure"
        const val KIN = "kin"
        const val NEW_NUMBER = "new_number"
        const val EMERGENCY = "emergency"
        const val SECRECY = "secrecy"
        const val AWARENESS = "awareness"
        const val CODE_LABEL = "code_label"
        const val CODE_DISCLAIMER = "code_disclaimer"
        const val PAYMENT_OP = "payment_op"
        const val BALANCE_WORD = "balance_word"
        const val CURRENCY = "currency"
        const val PICKUP = "pickup"
        const val PUBLIC_ALERT = "public_alert"
        const val SMS_COMMAND = "sms_command"
        const val PAYOUT = "payout"
        const val CODE_INCOMING = "code_incoming"
        const val CODE_PRONOUN = "code_pronoun"
        const val CODE_EXCEPT = "code_except"
        const val CODE_HOUSEHOLD = "code_household"
        const val SCAM_LABEL = "scam_label"
        const val OBEY = "obey"
        const val CALL_COMING = "call_coming"

        val REQUIRED_GROUPS = listOf(
            THREAT, URGENCY, CONFIRM_DATA, BAIT, CALL, CODE_VERB, CODE_DICTATE, CODE_WORD, CODE_TARGET, CALL_CONTEXT,
            PICKUP_CONTEXT, FLASH_CALL, MONEY_VERB, MONEY_INFINITIVE, DIRECTIVE, MONEY_REQUEST, SAFE_ACCOUNT,
            PAY_VERB, FEE_WORD, INSTALL, MALWARE_LURE, KIN, NEW_NUMBER, EMERGENCY, SECRECY, AWARENESS,
            CODE_LABEL, CODE_DISCLAIMER, PAYMENT_OP, BALANCE_WORD, CURRENCY, PICKUP, PUBLIC_ALERT, SMS_COMMAND,
            PAYOUT, CODE_INCOMING, CODE_PRONOUN, CODE_EXCEPT, CODE_HOUSEHOLD, SCAM_LABEL, OBEY, CALL_COMING,
        )

        /** No vocabulary at all: links are still checked against the blocklist. */
        fun empty(): MessageRules = MessageRules(
            emptyMap(), emptyList(), emptySet(), emptySet(), emptySet(), emptySet(), emptySet(), emptySet(), emptySet(), emptySet(),
        )

        /** Parse the asset. Throws on malformed JSON so a broken ship is caught by the tests. */
        fun parse(json: String): MessageRules {
            val root = JSONObject(json)
            val groupsJson = root.optJSONObject("groups") ?: JSONObject()
            val groups = groupsJson.keys().asSequence().associateWith { key ->
                phrases(groupsJson.optJSONArray(key))
            }
            val orgs = root.optJSONArray("organisations") ?: JSONArray()
            val organisations = (0 until orgs.length()).mapNotNull { organisation(orgs.optJSONObject(it)) }
            return MessageRules(
                groups = groups,
                organisations = organisations,
                negators = words(root.optJSONArray("negators")),
                intermediates = words(root.optJSONArray("intermediates")),
                shorteners = hosts(root.optJSONArray("shorteners")),
                messengers = hosts(root.optJSONArray("messengers")),
                trustedDomains = hosts(root.optJSONArray("trusted_domains")),
                bareTlds = words(root.optJSONArray("bare_tlds")) + words(root.optJSONArray("country_tlds")),
                userContentHosts = hosts(root.optJSONArray("user_content_hosts")),
                appStores = hosts(root.optJSONArray("app_stores")),
            )
        }

        private fun organisation(o: JSONObject?): Organisation? {
            o ?: return null
            val id = o.optString("id").ifEmpty { return null }
            val kind = runCatching { Kind.valueOf(o.optString("kind").uppercase()) }.getOrNull() ?: return null
            return Organisation(
                id = id,
                kind = kind,
                names = phrases(o.optJSONArray("names")),
                domains = hosts(o.optJSONArray("domains")),
                domainTokens = strings(o.optJSONArray("domain_tokens")).map { MessageText.normalizeWord(it) }.toSet(),
                phones = strings(o.optJSONArray("phones")).mapNotNull { PhoneExtractor.normalize(it) }.toSet(),
                senders = strings(o.optJSONArray("senders")).map { it.lowercase() }.toSet(),
                catchAll = o.optBoolean("catch_all", false),
            )
        }

        private fun strings(arr: JSONArray?): List<String> =
            if (arr == null) emptyList() else (0 until arr.length()).map { arr.optString(it) }.filter { it.isNotBlank() }

        private fun phrases(arr: JSONArray?): List<Phrase> = strings(arr).mapNotNull { Phrase.parse(it) }

        private fun words(arr: JSONArray?): Set<String> = strings(arr).map { MessageText.normalizeWord(it.trim()) }.toSet()

        private fun hosts(arr: JSONArray?): Set<String> = strings(arr).mapNotNull { HostNames.normalize(it) }.toSet()
    }
}
