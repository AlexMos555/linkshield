/**
 * Android update check for sideloaded builds.
 *
 * The Tele2 launch ships the APK directly (SMS → landing → download), so a
 * phone has no store to push updates. Left alone, a user stays on v1 forever —
 * including past a security fix. This module lets the app ask the backend
 * "is there something newer, and am I too old to be safe?" and decide what to
 * show, WITHOUT any new native dependency: we compare the build's embedded
 * version NAME (expo Constants.version) against names the server returns.
 *
 * Honesty contract, same as the rest of the app: we only ever *offer* an
 * update or, for a build below the security floor, insist on one. We never
 * claim the user is protected by a version they don't have, and a network
 * failure means "say nothing" — never a scary false "you're out of date".
 *
 * The decide/compare functions are pure so they can be reasoned about and
 * tested in isolation; the fetch is the only side-effecting part.
 */

export type UpdateDecision = "none" | "optional" | "required";

export interface VersionInfo {
  latestVersionName: string;
  minSupportedVersionName: string | null;
  apkUrl: string | null;
  releaseNotes: string | null;
}

/**
 * Parse a dotted numeric version ("1.2.3", "0.1.0", "10.0") into comparable
 * parts. Non-numeric junk in a segment collapses to 0 rather than throwing —
 * a malformed server value must never crash the app or, worse, be read as
 * "newer" and nag every launch.
 */
export function parseVersion(name: string): number[] {
  if (!name || typeof name !== "string") return [0];
  return name
    .trim()
    .split(".")
    .map((seg) => {
      const n = parseInt(seg, 10);
      return Number.isFinite(n) && n >= 0 ? n : 0;
    });
}

/** -1 if a<b, 0 if equal, 1 if a>b. Missing trailing segments read as 0. */
export function compareVersions(a: string, b: string): number {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/**
 * Decide what the app should show given the running build and the server's
 * numbers. Required beats optional; an empty/absent floor never forces.
 * Anything we can't make sense of falls back to "none" (stay quiet).
 *
 * Two guards against a misconfigured server trapping the user:
 *  - A floor ABOVE the latest published version is nonsense (nothing you could
 *    install would satisfy it), so it is ignored rather than obeyed. Without
 *    this, one fat-fingered env value shows every user a permanent, undismissable
 *    "you must update" with no version in existence that clears it.
 *  - `hasDownload: false` means we have no signed artifact to send them to (the
 *    /android page still says "coming soon"). Insisting on an update the user
 *    physically cannot perform is a trap, so it degrades to the dismissible nudge.
 */
export function decideUpdate(
  running: string,
  latest: string,
  minSupported: string | null,
  hasDownload = true,
): UpdateDecision {
  if (!running || !latest) return "none";
  const floorIsSane = !!minSupported && compareVersions(minSupported, latest) <= 0;
  const belowFloor = floorIsSane && compareVersions(running, minSupported!) < 0;
  const behindLatest = compareVersions(running, latest) < 0;
  if (belowFloor) return hasDownload ? "required" : "optional";
  if (behindLatest) return "optional";
  return "none";
}

/** Only https:// URLs may be opened from the update banner. */
export function isSafeDownloadUrl(v: unknown): boolean {
  return typeof v === "string" && /^https:\/\/[^\s]+$/i.test(v.trim());
}

/**
 * Ask the backend for the current release. Tolerant on purpose: a timeout,
 * a non-200, or a body missing the one field we require (latest_version_name)
 * all resolve to null so the caller shows nothing. Never throws.
 */
export async function fetchVersionInfo(
  apiBase: string,
  timeoutMs = 5000,
): Promise<VersionInfo | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(`${apiBase.replace(/\/+$/, "")}/api/v1/mobile/version`, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: controller.signal,
    });
    if (!resp.ok) return null;
    const body = (await resp.json()) as Record<string, unknown>;
    const latest = typeof body.latest_version_name === "string" ? body.latest_version_name : "";
    if (!latest) return null;
    return {
      latestVersionName: latest,
      minSupportedVersionName:
        typeof body.min_supported_version_name === "string" ? body.min_supported_version_name : null,
      // Only ever hand an https URL to Linking.openURL. The value comes from a
      // server env var, and a wrong or tampered one (intent://, market://, a
      // javascript: scheme) would otherwise be opened verbatim on the user's
      // phone from a banner they trust.
      apkUrl: isSafeDownloadUrl(body.apk_url) ? (body.apk_url as string) : null,
      releaseNotes: typeof body.release_notes === "string" ? body.release_notes : null,
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
