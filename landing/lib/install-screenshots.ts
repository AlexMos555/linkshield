import fs from "node:fs";
import path from "node:path";

/**
 * Screenshots for the three scary moments of a sideloaded install (report
 * #13): Chrome's download warning, Samsung's Auto Blocker, Play Protect.
 *
 * The page renders each one only when its file exists, so there is never a
 * broken image or a "screenshot coming soon" box in front of a first-time
 * user. To add one, drop a PNG/JPEG/WebP taken on a real phone into
 *
 *   landing/public/install/<locale>/<slot>.png      e.g. public/install/ru/samsung-auto-blocker.png
 *
 * and redeploy. Russian screens belong under `ru/`; a locale without its own
 * files shows text only (a Russian screenshot on the German page would help
 * nobody).
 */
export const INSTALL_SCREENSHOT_SLOTS = [
  "chrome-download-warning",
  "samsung-auto-blocker",
  "play-protect-warning",
] as const;

export type InstallScreenshotSlot = (typeof INSTALL_SCREENSHOT_SLOTS)[number];

const EXTENSIONS = [".png", ".jpg", ".jpeg", ".webp"] as const;
const LOCALE_RE = /^[a-z]{2}$/;

/**
 * Public URL of the screenshot for (locale, slot), or null when none has been
 * added. `publicDir` is injectable for tests; the default is the landing's
 * public/ folder (the build and `next start` both run from landing/).
 */
export function installScreenshotSrc(
  locale: string,
  slot: InstallScreenshotSlot,
  publicDir: string = path.join(process.cwd(), "public"),
): string | null {
  if (!LOCALE_RE.test(locale)) return null;
  for (const ext of EXTENSIONS) {
    const relative = `install/${locale}/${slot}${ext}`;
    if (fs.existsSync(path.join(publicDir, relative))) return `/${relative}`;
  }
  return null;
}
