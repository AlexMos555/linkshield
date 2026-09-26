package ai.cleanway.app

/** What the on-device list says about one link's host. */
enum class LinkStatus(val wire: String) {
    /** On the blocklist: a known phishing or malware host. */
    BLOCKED("blocked"),
    /**
     * A system domain the shield never blocks (google.com, googleapis.com…),
     * so that DNS never breaks Android. NOT a verdict on the page: anyone can
     * publish on sites.google.com or storage.googleapis.com, so the message
     * rules still treat it as a link that is not the organisation's.
     */
    SYSTEM("system"),
    /** The person marked the site "not a scam": they vouched for it. */
    ALLOWED_BY_USER("allowed_by_user"),
    /** Not on the list. Says nothing about safety — the list only knows what it has seen. */
    UNKNOWN("unknown"),
}

/**
 * The DNS decision's order, applied to a host found in a message.
 *
 * It has to agree with [DnsDecision.classify] where the two overlap: a host
 * the shield would forward (system suffix, or allowed by the person) must not
 * be called blocked here, and a host the shield would block must be. Only the
 * person's allow vouches for a site; a system suffix only keeps DNS working. The
 * canary branches do not apply — nothing in a message is a probe — and
 * cleanway.ai is a system suffix anyway. The session-scoped dynamic blocks
 * live only inside the running service and are not consulted.
 *
 * Pure: JVM-tested in LinkPolicyTest.
 */
object LinkPolicy {
    fun classify(host: String, list: BlockList?, allowed: Set<String>): LinkStatus = when {
        UserAllow.covers(allowed, host) != null -> LinkStatus.ALLOWED_BY_USER
        DomainPolicy.isSystemDomain(host) -> LinkStatus.SYSTEM
        list?.match(host) != null -> LinkStatus.BLOCKED
        else -> LinkStatus.UNKNOWN
    }

    /** The listed suffix that blocks [host], or null — same rules as [classify]. */
    fun listedSuffix(host: String, list: BlockList?, allowed: Set<String>): String? {
        if (DomainPolicy.isSystemDomain(host) || UserAllow.covers(allowed, host) != null) return null
        return list?.match(host)
    }
}
