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
 *  - WARN — "this looks like a scam, close it" — on a dangerous verdict, and
 *    on "caution" when the ML model is sure it is phishing. A caution at 50
 *    with the model at 100% (seen 2026-09-25 on a live wallet-drainer page)
 *    used to pass in silence.
 *  - BLOCK — the site stops resolving on this phone — ONLY when the verdict
 *    rests on threat intel: a curated list saw this site doing harm. A
 *    heuristics-only "dangerous" never blocks: the same heuristics called
 *    real Russian banks and regional governments dangerous from abroad
 *    (report #1), and a false block of someone's bank is worse than no block.
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
        answer.level == "dangerous" -> if (restsOnIntel(answer)) LinkAction.WARN_AND_BLOCK else LinkAction.WARN
        answer.level == "caution" && mlIsSure(answer) -> LinkAction.WARN
        else -> LinkAction.NONE
    }

    fun doesNotExist(answer: LinkAnswer): Boolean = answer.exists == false || NOT_FOUND_CODE in answer.reasonCodes

    fun restsOnIntel(answer: LinkAnswer): Boolean {
        if (answer.verdictBasis.isNotEmpty()) {
            return answer.verdictBasis.any { it.trim().lowercase().replace('-', '_') in INTEL_BASES }
        }
        return answer.reasonCodes.any { it in INTEL_CODES }
    }

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
