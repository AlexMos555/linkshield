package ai.cleanway.app

import java.io.File

/** Shared fixtures for the message-check tests. */
internal object MessageTestSupport {

    /**
     * The SHIPPED vocabulary and root zone, read from the module assets — the
     * tests must judge what goes into the APK, not a copy. Gradle runs unit
     * tests with the module's project dir (android/) as the working directory.
     */
    val rules: MessageRules by lazy { MessageRules.parse(asset("message_rules.json").readText(), rootZone) }

    /** The SHIPPED text model (message_model.json + message_model.bin). */
    val model: MessageModel by lazy {
        MessageModel.parse(asset(MessageModel.ASSET_JSON).readText(), asset(MessageModel.ASSET_WEIGHTS).readBytes())
    }

    /** Every list of the Kotlin dev corpora by name ("MessageCorpus.LEGIT_RU", as ml/sms/data.py names them), with its label. */
    val corpora: Map<String, Pair<String, List<String>>> by lazy {
        linkedMapOf(
            "MessageCorpus.SCAMS_RU" to ("scam" to MessageCorpus.SCAMS_RU),
            "MessageCorpus.SCAMS_EN" to ("scam" to MessageCorpus.SCAMS_EN),
            "MessageCorpus.SCAM_VARIANTS" to ("scam" to MessageCorpus.SCAM_VARIANTS),
            "MessageCorpus.SCAM_REVIEW" to ("scam" to MessageCorpus.SCAM_REVIEW),
            "MessageCorpus.LEGIT_RU" to ("legit" to MessageCorpus.LEGIT_RU),
            "MessageCorpus.LEGIT_EN" to ("legit" to MessageCorpus.LEGIT_EN),
            "MessageCorpus.LEGIT_VARIANTS" to ("legit" to MessageCorpus.LEGIT_VARIANTS),
            "MessageCorpus.SCAM_2026_10_DANGEROUS" to ("scam" to MessageCorpus.SCAM_2026_10_DANGEROUS),
            "MessageCorpus.SCAM_2026_10_CAUTION" to ("scam" to MessageCorpus.SCAM_2026_10_CAUTION),
            "MessageCorpus.LEGIT_2026_10" to ("legit" to MessageCorpus.LEGIT_2026_10),
            "MessageCorpus.SCAM_2026_10_UPGRADES" to ("scam" to MessageCorpus.SCAM_2026_10_UPGRADES),
            "MessageCorpus.LEGIT_2026_10_UPGRADES" to ("legit" to MessageCorpus.LEGIT_2026_10_UPGRADES),
            "MessageSchemeCorpus.SCAM_DANGEROUS" to ("scam" to MessageSchemeCorpus.SCAM_DANGEROUS),
            "MessageSchemeCorpus.SCAM_CAUTION" to ("scam" to MessageSchemeCorpus.SCAM_CAUTION),
            "MessageSchemeCorpus.LEGIT" to ("legit" to MessageSchemeCorpus.LEGIT),
            "MessageGenericCorpus.SCAM_DANGEROUS" to ("scam" to MessageGenericCorpus.SCAM_DANGEROUS),
            "MessageGenericCorpus.SCAM_CAUTION" to ("scam" to MessageGenericCorpus.SCAM_CAUTION),
            "MessageGenericCorpus.LEGIT" to ("legit" to MessageGenericCorpus.LEGIT),
        )
    }

    /** The shipped IANA root zone (root_zone_tlds.txt), as MessageCheck loads it. */
    val rootZone: Set<String> by lazy { RootZone.parse(asset(RootZone.ASSET).readText()) }

    private fun asset(name: String): File =
        listOf(File("src/main/assets/$name"), File("android/src/main/assets/$name")).firstOrNull { it.exists() }
            ?: error("$name not found from ${File(".").absolutePath}")

    /** A v2 list the way the publisher renders it (same helper as DnsDecisionTest). */
    fun list(vararg names: String): BlockList {
        val hashes = names.map { BlockList.hashOf(it) }.distinct().sorted()
        val out = java.io.ByteArrayOutputStream()
        out.write("CWBL2\n".toByteArray())
        out.write("# cleanway-dns-blocklist v2 generated=1 count=${hashes.size} status=ok\n".toByteArray())
        for (h in hashes) for (b in BlockList.HASH_BYTES - 1 downTo 0) out.write(((h shr (8 * b)) and 0xFF).toInt())
        return requireNotNull(BlockList.parse(out.toByteArray(), popularVeto = emptySet(), nowMs = 0L))
    }

    /** The analyzer as MessageCheck builds it: the shipped rules AND the shipped model, unless [withModel] is false. */
    fun analyzer(list: BlockList? = null, allowed: Set<String> = emptySet(), withModel: Boolean = true): MessageAnalyzer =
        MessageAnalyzer(rules, if (withModel) model else null) { host -> LinkPolicy.classify(host, list, allowed) }
}
