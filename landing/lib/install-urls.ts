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
   *  false, UI renders a non-clickable status pill instead ("In review",
   *  "Coming soon").
   *
   *  Android is `true` because `/android` is a real page: it explains the app,
   *  walks through the unknown-sources step, and says plainly when the build is
   *  not published yet. Sending people to a page that tells the truth beats a
   *  greyed-out pill that hides it. */
  available: boolean;
  /** Short user-facing status when `available=false`. */
  status?: string;
}

export const PLATFORMS: Record<Platform, PlatformInfo> = {
  // Chrome Web Store submission scheduled 2026-07-03; honest status until
  // store listing is actually live. Don't promise approval windows we can't
  // control.
  chrome: {
    label: "Chrome",
    href: "/dns",          // fallback while CWS review pending
    available: false,
    status: "Submitting soon",
  },
  firefox: {
    label: "Firefox",
    href: "/dns",
    available: false,
    status: "Coming soon",
  },
  edge: {
    label: "Edge",
    href: "/dns",
    available: false,
    status: "Coming soon",
  },
  safari: {
    label: "Safari",
    href: "/dns",
    available: false,
    status: "Coming soon",
  },
  ios: {
    label: "iOS",
    href: "/dns",                   // DoH profile install works today
    available: false,
    status: "Native app after launch",
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
    status: "AppSource pending",
  },
};

/** Where the primary install CTA points until any listing is live.
 *  Set to `/dns` because the DoH profile install is the ONE install path
 *  that works today without any store account. */
export const PRIMARY_INSTALL_HREF = "/dns";

export function isLive(platform: Platform): boolean {
  return PLATFORMS[platform].available;
}

export function hrefFor(platform: Platform): string {
  return PLATFORMS[platform].href;
}
