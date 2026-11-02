package ai.cleanway.app

import android.content.Context
import android.content.pm.PackageManager
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Apps kept OUT of the shield's tunnel (VpnService.Builder.addDisallowedApplication).
 *
 * Why this exists: the shield is a VpnService, and since April 2026 Russian
 * apps refuse to work while they see a VPN — MAX stops sending messages,
 * Gosuslugi does not open, banks ask to "turn off the VPN". A person who hits
 * that turns Cleanway off for good. An app outside the tunnel has its own
 * network as its default network, so the check those apps are known to use
 * (the active network's TRANSPORT_VPN) no longer fires for it.
 *
 * What it costs, and the UI says so: an excluded app's own DNS lookups skip
 * the blocklist — including the pages its built-in browser opens. Links it
 * hands to a normal browser are still filtered, because the browser is not
 * excluded.
 *
 * What it hides and what it does not (measured with a probe app on an
 * Android 15 emulator, 2026-09-27): for an excluded app the active network,
 * its capabilities, the default-network callback and a VPN-only
 * NetworkRequest all stop showing a VPN, and its DNS bypasses the shield.
 * It still sees the VPN through ConnectivityManager.getAllNetworks(), the
 * deprecated getNetworkInfo(TYPE_VPN) (which even names the VPN's package),
 * and NetworkInterface (tun0 is listed to every app). An app that looks there
 * keeps complaining; exclusion helps only with apps that check their own
 * default network.
 *
 * Three sources, one rule:
 *  - the default list, shipped in assets/[ASSET] (a product decision; entries
 *    marked `"default": false` are only offered first in the picker);
 *  - apps the person added ("this app says: turn off the VPN");
 *  - defaults the person put back under the filter.
 * Only installed packages are applied (see [applyTo]), and Cleanway itself is
 * never excluded: its own canary lookup must cross the tunnel, or the shield
 * can never prove it is on (see CleanwayVpnService).
 */
object AppExclusions {
    const val ASSET = "vpn_exclusions.json"

    private const val FILE = "cleanway_vpn_exclusions.json"
    private const val KEY_ADDED = "added"
    private const val KEY_REFILTERED = "refiltered"

    /** Upper bound on each stored list; a phone has far fewer apps that complain. */
    const val MAX = 100

    private val lock = Any()

    /** One app from the shipped data file. */
    data class Known(val pkg: String, val name: String, val default: Boolean)

    /** What happened when the list met the builder. Counts are what gets logged — never names. */
    data class Applied(val excluded: List<String>, val notInstalled: List<String>, val failed: List<String>)

    // ── Pure ──────────────────────────────────────────────────────────────

    private val PACKAGE = Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$")

    /** Pure: is [s] a well-formed Android package name? */
    fun isPackageName(s: String?): Boolean = s != null && s.length <= 255 && PACKAGE.matches(s)

    /**
     * Pure: the shipped data file. A malformed file is an empty list (the
     * shield runs as before, every app inside); a malformed or duplicate entry
     * is dropped on its own.
     */
    fun parseKnown(json: String?): List<Known> {
        if (json.isNullOrBlank()) return emptyList()
        val apps = try {
            JSONObject(json).optJSONArray("apps") ?: return emptyList()
        } catch (_: Exception) {
            return emptyList()
        }
        val seen = HashSet<String>()
        val out = ArrayList<Known>()
        for (i in 0 until apps.length()) {
            val o = apps.optJSONObject(i) ?: continue
            val pkg = o.optString("package")
            if (!isPackageName(pkg) || !seen.add(pkg)) continue
            out += Known(pkg, o.optString("name").ifBlank { pkg }, o.optBoolean("default", false))
        }
        return out
    }

    /**
     * Pure: the packages to keep out of the tunnel, in a stable order —
     * defaults first (minus those put back under the filter), then the
     * person's additions. Never [self], never a malformed name, no repeats.
     */
    fun effective(defaults: List<String>, added: List<String>, refiltered: Set<String>, self: String): List<String> {
        val out = LinkedHashSet<String>()
        for (p in defaults) if (p !in refiltered) out += p
        out += added
        return out.filter { it != self && isPackageName(it) }
    }

    /**
     * Apply [packages] through [disallow] (the builder's
     * addDisallowedApplication), installed ones only.
     *
     * [isInstalled] is asked first, and it is not optional: on Android 15 the
     * builder accepted all 12 defaults on an emulator that had none of them
     * installed — its NameNotFoundException never came — so "installed" would
     * otherwise mean "listed". A NameNotFoundException that does come (other
     * versions) is still treated as not installed, and anything else one
     * package throws is skipped too: one odd entry must never keep the shield
     * from starting. [self] is refused here as well, whatever the list says.
     */
    fun applyTo(
        packages: List<String>,
        self: String,
        isInstalled: (String) -> Boolean,
        disallow: (String) -> Unit,
    ): Applied {
        val excluded = ArrayList<String>()
        val notInstalled = ArrayList<String>()
        val failed = ArrayList<String>()
        for (p in packages.distinct()) {
            if (p == self || !isPackageName(p)) continue
            try {
                if (!isInstalled(p)) {
                    notInstalled += p
                    continue
                }
                disallow(p)
                excluded += p
            } catch (_: PackageManager.NameNotFoundException) {
                notInstalled += p
            } catch (_: Exception) {
                failed += p
            }
        }
        return Applied(excluded, notInstalled, failed)
    }

    /**
     * Is [pkg] installed, as far as this app may know? Package visibility
     * applies: the manifest's <queries> must cover it (the shipped list is
     * named there; launcher apps are covered by intent). An app we cannot see
     * reads as not installed and stays inside the tunnel — the platform would
     * exclude it regardless (measured), but the shield only keeps out what it
     * can show the person in Settings.
     */
    fun isInstalled(context: Context, pkg: String): Boolean = try {
        context.packageManager.getApplicationInfo(pkg, 0)
        true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    }

    /** Pure: the new (added, refiltered) after the person excludes [pkg]. */
    fun afterAdd(pkg: String, defaults: List<String>, added: List<String>, refiltered: Set<String>): Pair<List<String>, Set<String>> =
        if (pkg in defaults) {
            // A default they had put back under the filter: just undo that.
            added to (refiltered - pkg)
        } else {
            (if (pkg in added) added else (listOf(pkg) + added).take(MAX)) to refiltered
        }

    /** Pure: the new (added, refiltered) after the person puts [pkg] back under the filter. */
    fun afterRemove(pkg: String, defaults: List<String>, added: List<String>, refiltered: Set<String>): Pair<List<String>, Set<String>> {
        val nextAdded = added - pkg
        val nextRefiltered = if (pkg in defaults && refiltered.size < MAX) refiltered + pkg else refiltered
        return nextAdded to nextRefiltered
    }

    // ── Stored state ──────────────────────────────────────────────────────

    @Volatile
    private var knownCache: List<Known>? = null

    /** The shipped data file (read once per process). */
    fun known(context: Context): List<Known> =
        knownCache ?: (
            try {
                context.assets.open(ASSET).bufferedReader().use { it.readText() }
            } catch (_: Exception) {
                null
            }
            ).let { parseKnown(it) }.also { knownCache = it }

    fun defaults(context: Context): List<String> = known(context).filter { it.default }.map { it.pkg }

    /** What the tunnel should keep out right now (installed or not — see [applyTo]). */
    fun current(context: Context): List<String> = synchronized(lock) {
        val choices = read(context)
        effective(defaults(context), choices.added, choices.refiltered, context.packageName)
    }

    /** Does a change to [pkg] (installed / removed) change what the tunnel keeps out? */
    fun concerns(context: Context, pkg: String): Boolean = pkg in current(context)

    /** The person excludes [pkg]. False for a malformed name, Cleanway itself, or a failed write. */
    fun add(context: Context, pkg: String): Boolean {
        if (!isPackageName(pkg) || pkg == context.packageName) return false
        synchronized(lock) {
            val now = read(context)
            val (added, refiltered) = afterAdd(pkg, defaults(context), now.added, now.refiltered)
            return write(context, Choices(added, refiltered))
        }
    }

    /** The person puts [pkg] back under the filter. False when it could not be saved. */
    fun remove(context: Context, pkg: String): Boolean {
        if (!isPackageName(pkg)) return false
        synchronized(lock) {
            val now = read(context)
            val (added, refiltered) = afterRemove(pkg, defaults(context), now.added, now.refiltered)
            return write(context, Choices(added, refiltered))
        }
    }

    /** The person's choices: apps they added, defaults they put back under the filter. */
    data class Choices(val added: List<String>, val refiltered: Set<String>)

    /** Pure: the stored choices. Anything malformed reads as "no choices", never as a crash. */
    fun parseChoices(json: String?): Choices {
        if (json.isNullOrBlank()) return Choices(emptyList(), emptySet())
        return try {
            val o = JSONObject(json)
            Choices(names(o.optJSONArray(KEY_ADDED)).take(MAX), names(o.optJSONArray(KEY_REFILTERED)).take(MAX).toSet())
        } catch (_: Exception) {
            Choices(emptyList(), emptySet())
        }
    }

    /** Pure: the stored form of [choices]. */
    fun renderChoices(choices: Choices): String = JSONObject()
        .put(KEY_ADDED, JSONArray(choices.added))
        .put(KEY_REFILTERED, JSONArray(choices.refiltered.sorted()))
        .toString()

    private fun names(arr: JSONArray?): List<String> =
        if (arr == null) emptyList() else (0 until arr.length()).map { arr.optString(it) }.filter { isPackageName(it) }.distinct()

    /**
     * Kept in noBackupFilesDir, like InstallId and StopReasonStore: Android's
     * backup copies every SharedPreferences file to the person's Google
     * account, and which bank apps someone has is not something to send
     * there. Nothing about it leaves the phone. Main process only.
     */
    private fun file(context: Context) = File(context.noBackupFilesDir, FILE)

    private fun read(context: Context): Choices = try {
        parseChoices(file(context).takeIf { it.isFile }?.readText())
    } catch (_: Exception) {
        Choices(emptyList(), emptySet())
    }

    /** Write whole, then rename, so a crash mid-write cannot leave half a list. */
    private fun write(context: Context, choices: Choices): Boolean = try {
        val target = file(context)
        val tmp = File(target.parentFile, "$FILE.tmp")
        tmp.writeText(renderChoices(choices))
        tmp.renameTo(target) || run {
            target.delete()
            tmp.renameTo(target)
        }
    } catch (e: Exception) {
        android.util.Log.w("CleanwayVPN", "exclusions_write_error: ${e.javaClass.simpleName}")
        false
    }
}
