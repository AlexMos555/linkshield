package ai.cleanway.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * What the link guard does with the server's answer about a link that
 * already opened (LinkVerdictPolicy), and how hard it tries to get one
 * (LinkCheckRunner).
 *
 * The line this file holds: a site stops resolving on the phone ONLY when a
 * threat feed listed it. On 2026-09-25 the server called a real bank, two
 * regional governments and президент.рф "dangerous" from heuristics alone;
 * with the old rule, tapping such a link in an SMS darkened the site until
 * the shield restarted.
 */
class LinkVerdictPolicyTest {

    private fun answer(
        level: String,
        codes: List<String> = emptyList(),
        basis: List<String> = emptyList(),
        exists: Boolean? = null,
        signals: List<String> = emptyList(),
    ) = LinkAnswer(level, exists, basis, codes, signals)

    // ── decide ────────────────────────────────────────────────────────

    @Test
    fun `dangerous on a threat feed - warn and block`() {
        assertEquals(LinkAction.WARN_AND_BLOCK, LinkVerdictPolicy.decide(answer("dangerous", listOf("no_https", "phishtank"))))
        assertEquals(LinkAction.WARN_AND_BLOCK, LinkVerdictPolicy.decide(answer("dangerous", listOf("safe_browsing"))))
    }

    @Test
    fun `an older server's heuristics-only dangerous - no warning, no block`() {
        // Production answers of 2026-09-25, no verdict_basis: a real bank and
        // президент.рф, "dangerous" only because the scanner abroad could not
        // connect. A tapped link from an SMS must not be called a scam.
        val bankspb = answer("dangerous", listOf("no_https", "missing_headers", "abnormal_vowel_ratio", "consonant_cluster"))
        val president = answer("dangerous", listOf("no_https", "missing_headers", "excessive_special_chars", "unnatural_ngram"))
        assertEquals(LinkAction.NONE, LinkVerdictPolicy.decide(bankspb))
        assertEquals(LinkAction.NONE, LinkVerdictPolicy.decide(president))
        // OTX pulses and IPQS scores are not listings either.
        assertEquals(LinkAction.NONE, LinkVerdictPolicy.decide(answer("dangerous", listOf("alienvault_otx_high", "ipqs_phishing"))))
    }

    @Test
    fun `an older server's dangerous with the ML model sure - warn, never block`() {
        val sure = answer("dangerous", listOf("no_https", "missing_headers", "cross_domain_redirect", "ml_high_risk"))
        assertEquals(LinkAction.WARN, LinkVerdictPolicy.decide(sure))
        assertEquals(
            LinkAction.WARN,
            LinkVerdictPolicy.decide(answer("dangerous", listOf("missing_headers"), signals = listOf("ML model: 92% phishing probability"))),
        )
    }

    @Test
    fun `verdict_basis decides when the server sends it, over the codes`() {
        assertEquals(LinkAction.WARN, LinkVerdictPolicy.decide(answer("dangerous", listOf("phishtank"), basis = listOf("heuristics"))))
        assertEquals(LinkAction.WARN_AND_BLOCK, LinkVerdictPolicy.decide(answer("dangerous", listOf("no_https"), basis = listOf("threat_intel"))))
        assertEquals(LinkAction.WARN_AND_BLOCK, LinkVerdictPolicy.decide(answer("dangerous", basis = listOf("Blocklist"))))
        assertEquals(LinkAction.WARN_AND_BLOCK, LinkVerdictPolicy.decide(answer("dangerous", basis = listOf("heuristics", "threat-intel"))))
    }

    @Test
    fun `a newer server's dangerous warns when it judged the site itself`() {
        // The server opened the site and its rules (and model) found it dangerous.
        assertEquals(LinkAction.WARN, LinkVerdictPolicy.decide(answer("dangerous", listOf("no_mx_record"), basis = listOf("heuristics"))))
        assertEquals(LinkAction.WARN, LinkVerdictPolicy.decide(answer("dangerous", basis = listOf("ML_and_heuristics"))))
    }

    @Test
    fun `a newer server's dangerous it could not open, or of unknown basis, warns only when the ML model is sure`() {
        // A bank that turns away foreign addresses: the verdict rests on the name alone.
        assertEquals(LinkAction.NONE, LinkVerdictPolicy.decide(answer("dangerous", listOf("unreachable_from_scanner"), basis = listOf("unreachable"))))
        assertEquals(LinkAction.NONE, LinkVerdictPolicy.decide(answer("dangerous", basis = listOf("some_future_basis"))))
        assertEquals(LinkAction.WARN, LinkVerdictPolicy.decide(answer("dangerous", listOf("ml_high_risk"), basis = listOf("unreachable"))))
    }

    @Test
    fun `caution warns only when the ML model is sure it is phishing`() {
        assertEquals(LinkAction.WARN, LinkVerdictPolicy.decide(answer("caution", listOf("ml_high_risk"))))
        // Older answer without the code: the plain-language line carries the number.
        assertEquals(
            LinkAction.WARN,
            LinkVerdictPolicy.decide(answer("caution", signals = listOf("ML model: 100% phishing probability (confidence: 98%)"))),
        )
        assertEquals(LinkAction.NONE, LinkVerdictPolicy.decide(answer("caution", listOf("ml_suspicious"), signals = listOf("ML model: 70% phishing probability"))))
        assertEquals(LinkAction.NONE, LinkVerdictPolicy.decide(answer("caution", listOf("no_https"))))
        // A caution never blocks, whatever feed it names.
        assertEquals(LinkAction.WARN, LinkVerdictPolicy.decide(answer("caution", listOf("ml_high_risk", "phishtank"))))
    }

    @Test
    fun `a site that does not exist is never warned about`() {
        assertEquals(LinkAction.NONE, LinkVerdictPolicy.decide(answer("dangerous", listOf("no_https"), exists = false)))
        assertEquals(LinkAction.NONE, LinkVerdictPolicy.decide(answer("dangerous", listOf("domain_not_found", "phishtank"))))
    }

    @Test
    fun `safe is silent`() {
        assertEquals(LinkAction.NONE, LinkVerdictPolicy.decide(answer("safe", listOf("known_legitimate"))))
    }

    // ── parse ─────────────────────────────────────────────────────────

    @Test
    fun `parses the current response and the new fields, string or list`() {
        val current = LinkVerdictPolicy.parse(
            """{"domain":"x.tld","level":"caution","score":50,"signals":["ML model: 100% phishing probability"],"reason_codes":["ml_high_risk"]}""",
        )!!
        assertEquals("caution", current.level)
        assertNull(current.exists)
        assertEquals(listOf("ml_high_risk"), current.reasonCodes)
        assertTrue(current.verdictBasis.isEmpty())

        val next = LinkVerdictPolicy.parse("""{"level":"dangerous","exists":false,"verdict_basis":"threat_intel"}""")!!
        assertEquals(false, next.exists)
        assertEquals(listOf("threat_intel"), next.verdictBasis)
        assertEquals(listOf("a", "b"), LinkVerdictPolicy.parse("""{"level":"safe","verdict_basis":["a","b"]}""")!!.verdictBasis)
    }

    @Test
    fun `an unreadable body is no verdict`() {
        assertNull(LinkVerdictPolicy.parse("not json"))
        assertNull(LinkVerdictPolicy.parse("""{"detail":"Not found"}"""))
    }

    // ── runner ────────────────────────────────────────────────────────

    private class Fake(vararg results: CheckFetch) : CheckFetcher {
        private val queue = ArrayDeque(results.toList())
        var calls = 0
        override fun fetch(host: String): CheckFetch {
            calls++
            return queue.removeFirstOrNull() ?: CheckFetch.Failed("exhausted")
        }
    }

    private val body = """{"level":"dangerous","reason_codes":["phishtank"]}"""

    @Test
    fun `a timeout is retried once and the late answer is used`() {
        val fake = Fake(CheckFetch.TimedOut, CheckFetch.Answered(body))
        assertEquals("dangerous", LinkCheckRunner.run("x.tld", fake)!!.level)
        assertEquals(2, fake.calls)
    }

    @Test
    fun `two timeouts give up, any other failure is final at once`() {
        val timeouts = Fake(CheckFetch.TimedOut, CheckFetch.TimedOut, CheckFetch.Answered(body))
        assertNull(LinkCheckRunner.run("x.tld", timeouts))
        assertEquals(2, timeouts.calls)
        val limited = Fake(CheckFetch.Failed("http 429"), CheckFetch.Answered(body))
        assertNull(LinkCheckRunner.run("x.tld", limited))
        assertEquals(1, limited.calls)
    }

    @Test
    fun `an answer on the first try is not asked twice`() {
        val fake = Fake(CheckFetch.Answered(body))
        assertEquals("dangerous", LinkCheckRunner.run("x.tld", fake)!!.level)
        assertEquals(1, fake.calls)
    }

    // ── install id ────────────────────────────────────────────────────

    @Test
    fun `install id is a random UUID and nothing else`() {
        assertTrue(InstallId.isValid(java.util.UUID.randomUUID().toString()))
        assertFalse(InstallId.isValid("00000000-0000-1000-8000-000000000000")) // not random (v1)
        assertFalse(InstallId.isValid("android-id-1234"))
        assertFalse(InstallId.isValid(""))
    }
}
