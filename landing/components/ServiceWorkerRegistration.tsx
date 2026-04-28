"use client";

import { useEffect } from "react";

/**
 * Registers /sw.js once the page has finished loading.
 *
 * Progressive enhancement: every failure path is silent so a user
 * with privacy extensions, an old browser, or sandboxed iframe sees
 * exactly the same site they always saw — just without the offline
 * + push capabilities.
 *
 * Mounted once at the locale layout level so the registration
 * happens for every page, but only fires once per session because
 * the browser deduplicates registrations by scope.
 */
export default function ServiceWorkerRegistration() {
  useEffect(() => {
    if (typeof window === "undefined") return;
    if (typeof navigator === "undefined" || !("serviceWorker" in navigator)) return;
    // Skip in dev (next dev) — hot-reload + a stale SW cache fight each
    // other in confusing ways. The production build is what users see.
    if (process.env.NODE_ENV !== "production") return;

    const register = () => {
      navigator.serviceWorker
        .register("/sw.js", { scope: "/" })
        .catch(() => {
          /* silent — SW is a progressive enhancement */
        });
    };

    if (document.readyState === "complete") {
      register();
    } else {
      window.addEventListener("load", register, { once: true });
    }
  }, []);

  return null;
}
