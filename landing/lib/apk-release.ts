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
  /** Host the file downloads from (what the browser shows as its source). */
  readonly host: string | null;
  /** "1.0.3" from cleanway-1.0.3-103-arm.apk; null for any other file name. */
  readonly version: string | null;
  readonly versionCode: number | null;
  /** Lower-case hex SHA-256 of that file, or null when not known for it. */
  readonly sha256: string | null;
}

const RELEASE_FILE = /^cleanway-(\d+\.\d+\.\d+)-(\d+)(?:-[a-z0-9_]+)?\.apk$/i;
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
    version: release ? release[1] : null,
    versionCode: release ? Number(release[2]) : null,
    sha256: sum && fileName && sum[2] === fileName ? sum[1].toLowerCase() : null,
  };
}
