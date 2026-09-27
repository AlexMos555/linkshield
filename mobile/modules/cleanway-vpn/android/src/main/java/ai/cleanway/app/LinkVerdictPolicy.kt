package ai.cleanway.app

import org.json.JSONArray
import org.json.JSONObject

/** The parts of GET /api/v1/public/check/{host} the link guard acts on. */
data class LinkAnswer(
    val level: String,
    /** False when the server says the name does not exist. Null on servers that do not say. */
    val exists: Boolean?,
    /** What the verdict rests on, when the server says (`verdict_basis`, string or list). */
    val verdictBasis: List<String>,
    val reasonCodes: List<String>,
    /** Plain-language signals, positionally aligned with [reasonCodes]. */
    val signals: List<String>,
)

/** What the link guard does once the server has answered about a link that already opened. */
enum class LinkAction {
    /** Nothing to say. */
    NONE,
    /** Tell the person (notification + History); the site stays reachable. */
    WARN,
    /** Tell the person, and have the DNS shield block the site for the rest of the session. */
    WARN_AND_BLOCK,
}

/**
 * What the link guard does with the server's answer about a tapped link.
 *
 * The link opened already (fail-open fast path), so this decides two separate
 * things, with deliberately different bars:
 *
 *  - WARN — "this looks like a scam, close it" — on a dangerous verdict that
 *    rests on something the phone can stand behind: a threat feed, the ML
 *    model being sure, or (newer servers) the server having opened and
 *    judged the site itself. Also on "caution" when the model is sure: a
 *    caution at 50 with the model at 100% (seen 2026-09-25 on a live
 *    wallet-drainer page) used to pass in silence.
 *  - BLOCK — the site stops resolving on this phone — ONLY when the verdict
 *    rests on threat intel: a curated list saw this site doing harm.
 *
 * Why a heuristics-only "dangerous" from an older server is neither: that
 * server read "could not connect from abroad" as "no HTTPS, no security
 * headers" and called a real bank, two regional governments and президент.рф
 * dangerous (report #1). The warning reads «Этот сайт похож на мошеннический
 * … закройте его» and comes with or without the "All apps" shield — told
 * about her own bank's link, a grandmother learns to ignore the next warning.
 * Servers that send `verdict_basis` separate "judged the site" from "could
 * not open it" (`unreachable`), so their dangerous verdicts are trusted when
 * they judged the site.
 *
 * `verdict_basis` from the server decides BLOCK when present; older servers
 * do not send it, and then a conservative allowlist of reason codes that only
 * a feed hit can produce stands in. A name the server says does not exist is
 * never warned about: there is nothing there to be a scam.
 *
 * Pure: JVM-tested in LinkVerdictPolicyTest.
 */
object LinkVerdictPolicy {
    /** `verdict_basis` values that mean "a threat feed listed this site". */
    val INTEL_BASES = setOf("threat_intel", "blocklist")

    /**
     * `verdict_basis` values that mean "the server opened the site and judged
     * it" (api/services/verdict_basis.py). Not here: `unreachable` (the
     * verdict rests on the name alone), `allowlist`, `not_found`, and any
     * value this build has never seen.
     */
    val SITE_BASES = setOf("heuristics", "ml_and_heuristics")

    /**
     * Reason codes only a threat-feed hit produces (api/services/scoring.py).
     * Not here on purpose: AlienVault OTX (pulse counts misfired on real
     * sites), IPQS (a commercial score, not a listing), and every heuristic.
     */
    val INTEL_CODES = setOf(
        "safe_browsing", "phishtank", "urlhaus", "phishstats", "threatfox",
        "spamhaus_dbl", "surbl", "malware_bazaar", "feodo", "multi_blocklist",
    )

    /** The server's code for "ML model: >85% phishing, confident". */
    const val ML_HIGH_CODE = "ml_high_risk"
    const val ML_WARN_PERCENT = 85
    const val NOT_FOUND_CODE = "domain_not_found"
    private val ML_DETAIL = Regex("""ML model:\s*(\d{1,3})% phishing probability""")

    fun decide(answer: LinkAnswer): LinkAction = when {
        doesNotExist(answer) -> LinkAction.NONE
        answer.level == "dangerous" && restsOnIntel(answer) -> LinkAction.WARN_AND_BLOCK
        answer.level == "dangerous" && (judgedTheSite(answer) || mlIsSure(answer)) -> LinkAction.WARN
        answer.level == "caution" && mlIsSure(answer) -> LinkAction.WARN
        else -> LinkAction.NONE
    }

    fun doesNotExist(answer: LinkAnswer): Boolean = answer.exists == false || NOT_FOUND_CODE in answer.reasonCodes

    fun restsOnIntel(answer: LinkAnswer): Boolean {
        if (answer.verdictBasis.isNotEmpty()) return answer.verdictBasis.any { basis(it) in INTEL_BASES }
        return answer.reasonCodes.any { it in INTEL_CODES }
    }

    /** The server says it opened the site and judged it. Older servers never say so. */
    fun judgedTheSite(answer: LinkAnswer): Boolean = answer.verdictBasis.any { basis(it) in SITE_BASES }

    private fun basis(value: String): String = value.trim().lowercase().replace('-', '_')

    fun mlIsSure(answer: LinkAnswer): Boolean {
        if (ML_HIGH_CODE in answer.reasonCodes) return true
        return answer.signals.any { signal ->
            val pct = ML_DETAIL.find(signal)?.groupValues?.get(1)?.toIntOrNull()
            pct != null && pct >= ML_WARN_PERCENT
        }
    }

    /** Parse the response body; null when it is not a verdict we can read. */
    fun parse(body: String): LinkAnswer? = try {
        val o = JSONObject(body)
        val level = o.optString("level")
        if (level.isEmpty()) {
            null
        } else {
            LinkAnswer(
                level = level,
                exists = if (o.has("exists") && !o.isNull("exists")) o.optBoolean("exists", true) else null,
                verdictBasis = stringsOf(o.opt("verdict_basis")),
                reasonCodes = stringsOf(o.opt("reason_codes")),
                signals = stringsOf(o.opt("signals")),
            )
        }
    } catch (_: Exception) {
        null
    }

    private fun stringsOf(value: Any?): List<String> = when (value) {
        is String -> if (value.isBlank()) emptyList() else listOf(value)
        is JSONArray -> (0 until value.length()).mapNotNull { value.opt(it) as? String }
        else -> emptyList()
    }
}
