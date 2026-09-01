package ai.cleanway.app

import android.content.Context
import org.json.JSONArray

/**
 * Sites the person told us are not scams.
 *
 * Why this exists: our own rule is that a false positive is worse than a
 * miss, because it breaks the phone for someone who cannot debug it. Until
 * now a wrongly blocked site had exactly one remedy — turn protection off —
 * and that is the outcome we least want. A person who can rescue one site
 * keeps the shield on for everything else.
 *
 * Semantics mirror the blocklist: an allowed name covers itself and all its
 * subdomains, because that is the shape of what was blocked. The allow list
 * is consulted BEFORE the blocklist, is never expired behind the person's
 * back (an entry that silently lapses breaks the site again a day later, and
 * then the shield comes off for good), and is visible and revocable in
 * Settings.
 *
 * Trade-off, deliberately taken: a scammer could coach someone into tapping
 * "Not a scam". Every filtering product carries this; the mitigations here
 * are that the entry is recorded in history, shown in Settings with a remove
 * button, and confirmed by a follow-up notification, so it is never silent.
 */
object UserAllow {
    private const val PREFS = "cleanway_user_allow"
    private const val KEY = "domains"
    private const val MAX = 200
    private val lock = Any()

    fun list(context: Context): List<String> = synchronized(lock) {
        parse(context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY, null))
    }

    fun add(context: Context, domain: String): Boolean {
        val name = normalize(domain) ?: return false
        synchronized(lock) {
            val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val current = parse(prefs.getString(KEY, null))
            if (name in current) return true
            val next = (listOf(name) + current).take(MAX)
            prefs.edit().putString(KEY, render(next)).apply()
        }
        return true
    }

    fun remove(context: Context, domain: String) {
        val name = normalize(domain) ?: return
        synchronized(lock) {
            val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val next = parse(prefs.getString(KEY, null)).filterNot { it == name }
            prefs.edit().putString(KEY, render(next)).apply()
        }
    }

    /** Pure: does [allowed] cover [qname] (itself or a subdomain)? */
    fun covers(allowed: Set<String>, qname: String): String? {
        if (allowed.isEmpty()) return null
        val q = qname.lowercase().trimEnd('.')
        val parts = q.split('.')
        for (i in 0..parts.size - 2) {
            val suffix = parts.subList(i, parts.size).joinToString(".")
            if (suffix in allowed) return suffix
        }
        return if (q in allowed) q else null
    }

    /** Pure: normalise a user-supplied name, or null if it is not a domain. */
    fun normalize(domain: String?): String? {
        val d = domain?.trim()?.lowercase()?.trimEnd('.') ?: return null
        if (d.isEmpty() || d.length > 253) return null
        val labels = d.split('.')
        if (labels.size < 2) return null
        val ok = labels.all { l ->
            l.isNotEmpty() && l.length <= 63 && !l.startsWith("-") && !l.endsWith("-") &&
                l.all { it.isDigit() || (it in 'a'..'z') || it == '-' }
        }
        return if (ok) d else null
    }

    private fun parse(json: String?): List<String> {
        if (json.isNullOrBlank()) return emptyList()
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).mapNotNull { normalize(arr.optString(it)) }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun render(names: List<String>): String {
        val arr = JSONArray()
        names.forEach { arr.put(it) }
        return arr.toString()
    }
}
