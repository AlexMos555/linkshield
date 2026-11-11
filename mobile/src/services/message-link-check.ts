import { checkDomain } from "./api";
import type { LinkCheck, ServerLevel } from "../utils/message-verdict";
import { isNotFound } from "../utils/check-verdict";
import { advisoryKeepMs, hasGoogleAdvisory } from "../utils/google-advisory";

/**
 * The domain-only server check for one host found in a message.
 *
 * Same endpoint and same privacy as a typed link: GET /public/check/{host},
 * the host alone. Answers are cached for a short while, so checking the same
 * message twice — or a scam blast that repeats one site — does not spend the
 * per-IP quota again (Tele2 CGNAT puts many phones behind one address). One
 * that rests on Google's lists is kept only while Google's answer is valid —
 * Web Risk allows a warning under no other circumstances — so for the
 * server's `advisory_ttl`, if that is shorter (src/utils/google-advisory.ts).
 */

const CACHE_TTL_MS = 15 * 60_000;
const CACHE_MAX = 100;

/** Only settled answers are cached — never a failure, which may be gone on the next try. */
type Settled = Extract<LinkCheck, { kind: "checked" } | { kind: "not_found" }>;

const cache = new Map<string, { answer: Settled; until: number }>();

function isServerLevel(level: unknown): level is ServerLevel {
  return level === "safe" || level === "caution" || level === "dangerous";
}

function remember(host: string, answer: Settled, keepMs = CACHE_TTL_MS): Settled {
  cache.delete(host);
  if (keepMs <= 0) return answer;
  cache.set(host, { answer, until: Date.now() + keepMs });
  // Insertion order is age order: drop the oldest past the cap.
  if (cache.size > CACHE_MAX) cache.delete(cache.keys().next().value as string);
  return answer;
}

export async function checkMessageHost(host: string): Promise<LinkCheck> {
  const cached = cache.get(host);
  if (cached && Date.now() < cached.until) return cached.answer;
  try {
    const { data, error } = await checkDomain(host);
    // The site does not exist (newer servers say so): a fact about the link,
    // never a "dangerous" verdict built on its missing HTTPS.
    if (data && isNotFound(data)) return remember(host, { kind: "not_found" });
    if (data && isServerLevel(data.level)) {
      // Google's reason among the server's: the links card credits Google.
      return remember(
        host,
        { kind: "checked", level: data.level, google: hasGoogleAdvisory(data.reasons) },
        advisoryKeepMs(data, CACHE_TTL_MS),
      );
    }
    // An answer we cannot read is a failed check, never a clean one.
    if (!error) return { kind: "failed", why: "error" };
    if (error.kind === "rate_limited") return { kind: "failed", why: "rate_limited" };
    if (error.kind === "timeout") return { kind: "failed", why: "timeout" };
    if (error.kind === "network") return { kind: "failed", why: "offline" };
    return { kind: "failed", why: "error" };
  } catch {
    return { kind: "failed", why: "offline" };
  }
}
