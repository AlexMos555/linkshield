/* eslint-disable no-restricted-globals */
/**
 * Cleanway service worker.
 *
 * Three jobs:
 *  1. Offline shell — pre-cache the homepage + critical assets so the
 *     site loads even when the network is gone (PWA promise).
 *  2. Runtime cache — speed up repeat visits with cache-first for
 *     immutable bundles + images, network-first for HTML.
 *  3. Push hook — ready to receive breach alerts, family-hub events,
 *     and weekly-report nudges once the backend wires push (future).
 *
 * Bump CACHE_VERSION on a deploy where you want to bust the cache —
 * the activate handler purges anything not on the current version.
 */

const CACHE_VERSION = "v1";
const STATIC_CACHE = `cleanway-static-${CACHE_VERSION}`;
const RUNTIME_CACHE = `cleanway-runtime-${CACHE_VERSION}`;

// Pre-cached on install — the smallest viable offline shell.
const PRECACHE = [
  "/",
  "/manifest.webmanifest",
  "/icon-192.png",
  "/apple-touch-icon.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(STATIC_CACHE)
      .then((cache) => cache.addAll(PRECACHE))
      .catch(() => {
        // Pre-cache is best-effort — don't fail install if a single
        // asset is 404 in some build.
      })
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    Promise.all([
      caches.keys().then((keys) =>
        Promise.all(
          keys
            .filter((k) => !k.endsWith(`-${CACHE_VERSION}`))
            .map((k) => caches.delete(k))
        )
      ),
      self.clients.claim(),
    ])
  );
});

// ─── Fetch routing ───────────────────────────────────────────────

self.addEventListener("fetch", (event) => {
  const { request } = event;
  if (request.method !== "GET") return;

  let url;
  try {
    url = new URL(request.url);
  } catch {
    return;
  }

  // Skip cross-origin entirely — let the browser handle them.
  if (url.origin !== self.location.origin) return;

  // /api/* — never cache. Scan results must be live.
  if (url.pathname.startsWith("/api/")) return;

  // Hashed Next.js bundles + static images — cache-first, immutable.
  if (
    url.pathname.startsWith("/_next/static/") ||
    /\.(png|jpg|jpeg|svg|webp|ico|woff2?)$/.test(url.pathname)
  ) {
    event.respondWith(cacheFirst(request));
    return;
  }

  // Everything else (HTML, JSON, SSG payloads) — network-first so a
  // deploy is visible immediately, with cache fallback for offline.
  event.respondWith(networkFirst(request));
});

async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) return cached;
  try {
    const fresh = await fetch(request);
    if (fresh && fresh.ok) {
      const cache = await caches.open(STATIC_CACHE);
      cache.put(request, fresh.clone());
    }
    return fresh;
  } catch {
    if (cached) return cached;
    return new Response("Offline", { status: 503, statusText: "Offline" });
  }
}

async function networkFirst(request) {
  try {
    const fresh = await fetch(request);
    if (fresh && fresh.ok && fresh.type === "basic") {
      const cache = await caches.open(RUNTIME_CACHE);
      cache.put(request, fresh.clone());
    }
    return fresh;
  } catch {
    const cached = await caches.match(request);
    if (cached) return cached;
    // Last-resort fallback: serve cached homepage if we have it.
    const home = await caches.match("/");
    if (home) return home;
    return new Response("Offline", { status: 503, statusText: "Offline" });
  }
}

// ─── Push notifications ──────────────────────────────────────────
//
// Wire is ready; backend can start delivering payloads of the shape
//   { title, body, url, tag?, renotify? }
// Once the push subscription endpoint is set up server-side, the user
// can opt in via the future "Notify me of new breaches" flow.

self.addEventListener("push", (event) => {
  if (!event.data) return;

  let payload;
  try {
    payload = event.data.json();
  } catch {
    payload = { title: "Cleanway", body: event.data.text() };
  }

  const title = payload.title || "Cleanway";
  const options = {
    body: payload.body || "",
    icon: "/icon-192.png",
    badge: "/icon-192.png",
    data: { url: payload.url || "/" },
    tag: payload.tag,
    renotify: !!payload.renotify,
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const targetUrl =
    (event.notification.data && event.notification.data.url) || "/";

  event.waitUntil(
    self.clients
      .matchAll({ type: "window", includeUncontrolled: true })
      .then((wins) => {
        // Focus an existing tab on the target URL if there is one.
        for (const win of wins) {
          if (win.url === targetUrl && "focus" in win) {
            return win.focus();
          }
        }
        // Otherwise open a fresh tab.
        if (self.clients.openWindow) {
          return self.clients.openWindow(targetUrl);
        }
        return null;
      })
  );
});

// ─── Message channel ─────────────────────────────────────────────
// Lets the page tell the SW to skip waiting on a fresh deploy without
// requiring a hard reload. Page calls:
//   navigator.serviceWorker.controller?.postMessage({ type: "SKIP_WAITING" });

self.addEventListener("message", (event) => {
  if (event.data && event.data.type === "SKIP_WAITING") {
    self.skipWaiting();
  }
});
