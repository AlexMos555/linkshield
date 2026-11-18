"use client";

import { useSyncExternalStore, type AnchorHTMLAttributes, type ReactNode } from "react";

import { PLATFORMS, PRIMARY_INSTALL_HREF } from "@/lib/install-urls";

/** Android Chrome, WebView, Firefox, Samsung Internet — anything that can install the APK. */
const ANDROID_USER_AGENT = /Android/i;
/** iPhone, iPod touch, and iPad when it asks for the mobile site. */
const IOS_USER_AGENT = /iPhone|iPod|iPad/i;
/** iPadOS 13+ asks for the desktop site by default and then reports itself as a Mac. */
const MAC_USER_AGENT = /Macintosh/i;

/** The phones with an app to send people to; everyone else keeps PRIMARY_INSTALL_HREF. */
type AppPlatform = "android" | "ios";

type AnchorProps = Omit<AnchorHTMLAttributes<HTMLAnchorElement>, "href" | "children">;

export interface PrimaryInstallLinkProps extends AnchorProps {
  /** Label shown to Android visitors once hydration has detected the platform. */
  androidLabel: ReactNode;
  /** Label shown to iPhone and iPad visitors once hydration has detected the platform. */
  iosLabel: ReactNode;
  /** Label rendered on the server, on first paint, and for every other visitor. */
  children: ReactNode;
}

function detectAppPlatform(): AppPlatform | null {
  if (typeof navigator === "undefined") return null;
  const ua = navigator.userAgent;
  if (ANDROID_USER_AGENT.test(ua)) return "android";
  if (IOS_USER_AGENT.test(ua)) return "ios";
  // A "Macintosh" with a touchscreen is an iPad in desktop mode: no Mac has
  // touch, so maxTouchPoints is 0 on every real Mac.
  if (MAC_USER_AGENT.test(ua) && navigator.maxTouchPoints > 1) return "ios";
  return null;
}

/** The platform never changes during a page's lifetime, so there is nothing to subscribe to. */
function subscribeNever(): () => void {
  return () => {};
}

function serverSnapshot(): AppPlatform | null {
  return null;
}

/**
 * Site-wide primary install CTA.
 *
 * Server output is identical to a plain `<a href={PRIMARY_INSTALL_HREF}>`, so
 * static/CDN pages never change and hydration matches byte-for-byte. After
 * hydration, phone visitors are re-pointed at their app: Android at the app
 * page (sending them to /dns would teach strict Private DNS, which conflicts
 * with the app's VPN shield), iPhone and iPad at the App Store listing (the
 * app sets up the same DNS filter itself). Desktop keeps the DoH profile path.
 *
 * `useSyncExternalStore` hydrates with the server snapshot (`null`) and then
 * re-renders with the real value straight away — no hydration-mismatch
 * warning and no flash beyond the label swap itself.
 */
export function PrimaryInstallLink({ androidLabel, iosLabel, children, ...anchorProps }: PrimaryInstallLinkProps) {
  const platform = useSyncExternalStore(subscribeNever, detectAppPlatform, serverSnapshot);
  const label = platform === "android" ? androidLabel : platform === "ios" ? iosLabel : children;

  return (
    <a href={platform ? PLATFORMS[platform].href : PRIMARY_INSTALL_HREF} {...anchorProps}>
      {label}
    </a>
  );
}
