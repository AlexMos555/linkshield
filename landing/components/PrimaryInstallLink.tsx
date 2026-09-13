"use client";

import { useSyncExternalStore, type AnchorHTMLAttributes, type ReactNode } from "react";

import { PLATFORMS, PRIMARY_INSTALL_HREF } from "@/lib/install-urls";

/** Android Chrome, WebView, Firefox, Samsung Internet — anything that can install the APK. */
const ANDROID_USER_AGENT = /Android/i;

type AnchorProps = Omit<AnchorHTMLAttributes<HTMLAnchorElement>, "href" | "children">;

export interface PrimaryInstallLinkProps extends AnchorProps {
  /** Label shown to Android visitors once hydration has detected the platform. */
  androidLabel: ReactNode;
  /** Label rendered on the server, on first paint, and for every other visitor. */
  children: ReactNode;
}

function isAndroidVisitor(): boolean {
  return typeof navigator !== "undefined" && ANDROID_USER_AGENT.test(navigator.userAgent);
}

/** The platform never changes during a page's lifetime, so there is nothing to subscribe to. */
function subscribeNever(): () => void {
  return () => {};
}

function serverSnapshot(): boolean {
  return false;
}

/**
 * Site-wide primary install CTA.
 *
 * Server output is identical to a plain `<a href={PRIMARY_INSTALL_HREF}>`, so
 * static/CDN pages never change and hydration matches byte-for-byte. After
 * hydration, Android visitors are re-pointed at the app page: sending them to
 * /dns would teach strict Private DNS, which conflicts with the app's VPN
 * shield. Desktop and iOS keep the DoH profile path.
 *
 * `useSyncExternalStore` hydrates with the server snapshot (`false`) and then
 * re-renders with the real value straight away — no hydration-mismatch
 * warning and no flash beyond the label swap itself.
 */
export function PrimaryInstallLink({ androidLabel, children, ...anchorProps }: PrimaryInstallLinkProps) {
  const isAndroid = useSyncExternalStore(subscribeNever, isAndroidVisitor, serverSnapshot);

  return (
    <a href={isAndroid ? PLATFORMS.android.href : PRIMARY_INSTALL_HREF} {...anchorProps}>
      {isAndroid ? androidLabel : children}
    </a>
  );
}
