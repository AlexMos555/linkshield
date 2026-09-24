package ai.cleanway.app

import java.io.File

/** Shared fixtures for the message-check tests. */
internal object MessageTestSupport {

    /**
     * The SHIPPED vocabulary, read from the module asset — the tests must
     * judge what goes into the APK, not a copy. Gradle runs unit tests with
     * the module's project dir (android/) as the working directory.
     */
    val rules: MessageRules by lazy {
        val candidates = listOf(
            File("src/main/assets/message_rules.json"),
            File("android/src/main/assets/message_rules.json"),
        )
        val file = candidates.firstOrNull { it.exists() }
            ?: error("message_rules.json not found from ${File(".").absolutePath}")
        MessageRules.parse(file.readText())
    }

    /** A v2 list the way the publisher renders it (same helper as DnsDecisionTest). */
    fun list(vararg names: String): BlockList {
        val hashes = names.map { BlockList.hashOf(it) }.distinct().sorted()
        val out = java.io.ByteArrayOutputStream()
        out.write("CWBL2\n".toByteArray())
        out.write("# cleanway-dns-blocklist v2 generated=1 count=${hashes.size} status=ok\n".toByteArray())
        for (h in hashes) for (b in BlockList.HASH_BYTES - 1 downTo 0) out.write(((h shr (8 * b)) and 0xFF).toInt())
        return requireNotNull(BlockList.parse(out.toByteArray(), popularVeto = emptySet(), nowMs = 0L))
    }

    fun analyzer(list: BlockList? = null, allowed: Set<String> = emptySet()): MessageAnalyzer =
        MessageAnalyzer(rules) { host -> LinkPolicy.classify(host, list, allowed) }
}
