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
  /** True when the store listing is live and the link resolves to a real
   *  install page. When false, UI should render the button as a status pill
   *  ("In review", "Coming soon") rather than a clickable CTA. */
  available: boolean;
  /** Short user-facing status when `available=false`. */
  status?: string;
}

export const PLATFORMS: Record<Platform, PlatformInfo> = {
  // Submitted Friday 2026-07-03; listing pending review.
  chrome: {
    label: "Chrome",
    href: "/dns#install",          // safe fallback while CWS review pending
    available: false,
    status: "In review",
  },
  firefox: {
    label: "Firefox",
    href: "/dns#install",
    available: false,
    status: "Coming this week",
  },
  edge: {
    label: "Edge",
    href: "/dns#install",
    available: false,
    status: "Coming this week",
  },
  safari: {
    label: "Safari",
    href: "/dns#install",
    available: false,
    status: "In review",
  },
  ios: {
    label: "iOS",
    href: "/dns",                   // DoH profile install works today
    available: false,
    status: "Native app after launch",
  },
  android: {
    label: "Android",
    href: "/dns",
    available: false,
    status: "Native app after launch",
  },
  outlook: {
    label: "Outlook",
    href: "/dns#install",
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
