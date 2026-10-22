/**
 * The APK the /android button downloads — one source for the link, the
 * version and the checksum shown next to it.
 *
 * NEXT_PUBLIC_APK_URL is the file (a GitHub release asset today). The version
 * shown is read from that file's own name — the release asset is named
 * cleanway-<version>-<versionCode>-<abi>.apk — so the page cannot show one
 * version and download another.
 *
 * NEXT_PUBLIC_APK_SHA256 is the line `shasum -a 256 <file>` prints: the hash
 * AND the file name. The hash is shown only when that name is the file the
 * button downloads, so when the URL moves to a new release and the checksum
 * is not updated, the page shows no checksum rather than a wrong one (a
 * careful reader comparing it would take a genuine file for a forged one).
 *
 * The page names the host the file comes from, and for a GitHub release also
 * the host GitHub hands it over from: github.com answers a release link with a
 * redirect to its file store, and that store is what the browser's download
 * list shows — a careful reader told only "github.com" would see another
 * address and stop.
 *
 * Both are NEXT_PUBLIC_* and inlined at build time: change them in Vercel and
 * redeploy without the build cache.
 */
export interface ApkEnv {
  readonly NEXT_PUBLIC_APK_URL?: string;
  readonly NEXT_PUBLIC_APK_SHA256?: string;
}

export interface ApkRelease {
  /** The download link, exactly as configured. */
  readonly url: string;
  /** Last path segment of the link, or null when it is not a web address. */
  readonly fileName: string | null;
  /** Host the link points at. */
  readonly host: string | null;
  /**
   * Host that really serves the file when `host` answers with a redirect —
   * what the browser then shows as the download's source; null when `host`
   * serves it itself.
   */
  readonly servedFrom: string | null;
  /** "1.0.3" from cleanway-1.0.3-103-arm.apk; null for any other file name. */
  readonly version: string | null;
  readonly versionCode: number | null;
  /** Lower-case hex SHA-256 of that file, or null when not known for it. */
  readonly sha256: string | null;
}

const RELEASE_FILE = /^cleanway-(\d+\.\d+\.\d+)-(\d+)(?:-[a-z0-9_]+)?\.apk$/i;
// github.com/<owner>/<repo>/releases/download/<tag>/<file> → 302 to the file store.
const GITHUB_RELEASE_ASSET = /^\/[^/]+\/[^/]+\/releases\/download\/[^/]+\/[^/]+$/;
const GITHUB_RELEASE_STORE = "release-assets.githubusercontent.com";
// `shasum -a 256` / `sha256sum` output; "*" marks binary mode in the latter.
const SHASUM_LINE = /^([0-9a-f]{64})\s+\*?(\S+)$/i;

function parseUrl(raw: string): URL | null {
  try {
    const url = new URL(raw);
    return url.protocol === "https:" || url.protocol === "http:" ? url : null;
  } catch {
    return null;
  }
}

function lastSegment(url: URL): string | null {
  const segment = url.pathname.split("/").pop() ?? "";
  try {
    return decodeURIComponent(segment) || null;
  } catch {
    return null;
  }
}

function servedFrom(url: URL): string | null {
  return url.hostname === "github.com" && GITHUB_RELEASE_ASSET.test(url.pathname) ? GITHUB_RELEASE_STORE : null;
}

/** The configured release, or null when no APK is hosted yet. */
export function apkReleaseFrom(env: ApkEnv): ApkRelease | null {
  const url = (env.NEXT_PUBLIC_APK_URL ?? "").trim();
  if (!url) return null;
  const parsed = parseUrl(url);
  const fileName = parsed ? lastSegment(parsed) : null;
  const release = fileName ? RELEASE_FILE.exec(fileName) : null;
  const sum = SHASUM_LINE.exec((env.NEXT_PUBLIC_APK_SHA256 ?? "").trim());
  return {
    url,
    fileName,
    host: parsed ? parsed.hostname : null,
    servedFrom: parsed ? servedFrom(parsed) : null,
    version: release ? release[1] : null,
    versionCode: release ? Number(release[2]) : null,
    sha256: sum && fileName && sum[2] === fileName ? sum[1].toLowerCase() : null,
  };
}
