import { checkDomain } from "./api";
import type { LinkCheck, ServerLevel } from "../utils/message-verdict";

/**
 * The domain-only server check for one host found in a message.
 *
 * Same endpoint and same privacy as a typed link: GET /public/check/{host},
 * the host alone. Answers are cached for a short while, so checking the same
 * message twice — or a scam blast that repeats one site — does not spend the
 * per-IP quota again (Tele2 CGNAT puts many phones behind one address).
 */

const CACHE_TTL_MS = 15 * 60_000;
const CACHE_MAX = 100;

const cache = new Map<string, { level: ServerLevel; at: number }>();

function isServerLevel(level: unknown): level is ServerLevel {
  return level === "safe" || level === "caution" || level === "dangerous";
}

function remember(host: string, level: ServerLevel): void {
  cache.delete(host);
  cache.set(host, { level, at: Date.now() });
  // Insertion order is age order: drop the oldest past the cap.
  if (cache.size > CACHE_MAX) cache.delete(cache.keys().next().value as string);
}

export async function checkMessageHost(host: string): Promise<LinkCheck> {
  const cached = cache.get(host);
  if (cached && Date.now() - cached.at < CACHE_TTL_MS) return { kind: "checked", level: cached.level };
  try {
    const { data, error } = await checkDomain(host);
    if (data && isServerLevel(data.level)) {
      remember(host, data.level);
      return { kind: "checked", level: data.level };
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
