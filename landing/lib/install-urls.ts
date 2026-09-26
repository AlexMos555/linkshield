/**
 * Single source of truth for "where do I install Cleanway" URLs.
 *
 * When a listing goes live, flip `available: false → true` AND update `href`
 * to the actual listing URL. Every CTA across the site reads from here.
 *
 * Avoid hardcoding store URLs in components. Use the helpers below.
 */
export type Platform =
  | "chrome"
  | "firefox"
  | "edge"
  | "safari"
  | "ios"
  | "android"
  | "outlook";

export interface PlatformInfo {
  /** Display name shown on buttons. */
  label: string;
  /** Where the install button leads. When not yet live, this is a placeholder
   *  that will redirect to the marketing page rather than a dead store. */
  href: string;
  /** True when the link resolves to a real, useful install destination — a live
   *  store listing, or our own download page which states its own status. When
   *  false, UI renders a non-clickable status pill instead ("Coming soon").
   *
   *  Android is `true` because `/android` is a real page: it explains the app,
   *  walks through the unknown-sources step, and says plainly when the build is
   *  not published yet. Sending people to a page that tells the truth beats a
   *  greyed-out pill that hides it. */
  available: boolean;
  /** Which status pill to show when `available=false` — the text itself is
   *  localized (landing.install.status_<key>), never hard-coded here. */
  statusKey?: InstallStatus;
}

/** Status pills with a string in every locale (landing.install.status_*). */
export type InstallStatus = "coming_soon" | "appsource_pending";

export const PLATFORMS: Record<Platform, PlatformInfo> = {
  // Not in the Chrome Web Store yet. "Coming soon" and nothing more specific:
  // don't promise review windows we can't control.
  chrome: {
    label: "Chrome",
    href: "/dns",          // fallback while CWS review pending
    available: false,
    statusKey: "coming_soon",
  },
  firefox: {
    label: "Firefox",
    href: "/dns",
    available: false,
    statusKey: "coming_soon",
  },
  edge: {
    label: "Edge",
    href: "/dns",
    available: false,
    statusKey: "coming_soon",
  },
  safari: {
    label: "Safari",
    href: "/dns",
    available: false,
    statusKey: "coming_soon",
  },
  ios: {
    label: "iOS",
    href: "/dns",                   // DoH profile install works today
    available: false,
    statusKey: "coming_soon",
  },
  android: {
    // The Android CTA now leads to the download/install page (/android), the
    // front door of the Tele2 funnel. The page itself gates on whether the
    // signed APK is hosted yet (NEXT_PUBLIC_APK_URL) — so this is a real,
    // clickable destination even before the store listings exist.
    label: "Android",
    href: "/android",
    available: true,
  },
  outlook: {
    label: "Outlook",
    href: "/dns",
    available: false,
    statusKey: "appsource_pending",
  },
};

/** Where the primary install CTA points: `/dns` for desktop until a store
 *  listing is live (the DoH profile is the one install path that works today
 *  without any store account). Android visitors are redirected client-side to
 *  `PLATFORMS.android.href` by `PrimaryInstallLink` — strict Private DNS
 *  conflicts with the app's VPN shield, so /dns is the wrong door for them. */
export const PRIMARY_INSTALL_HREF = "/dns";

export function isLive(platform: Platform): boolean {
  return PLATFORMS[platform].available;
}

export function hrefFor(platform: Platform): string {
  return PLATFORMS[platform].href;
}
