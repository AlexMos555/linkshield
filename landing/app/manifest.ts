import type { MetadataRoute } from "next";

/**
 * PWA web app manifest.
 *
 * Enables "Add to Home Screen" prompts on iOS Safari, Android Chrome,
 * and desktop Chromium. Once installed, Cleanway opens like a native
 * app (its own window, no browser chrome) which doubles as a passive
 * marketing surface — every install is one more permanent icon on a
 * user's home screen.
 *
 * No service worker is registered yet — modern browsers (Chrome 92+,
 * Edge, Safari 16.4+ on iOS, Firefox via add-on) prompt install based
 * on this manifest alone. Service worker is required only for offline
 * support and push notifications, both of which are future work.
 */
export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "Cleanway — Protection from scam links",
    short_name: "Cleanway",
    description:
      "Privacy-first protection from phishing and scam links. 9 threat sources, ML-powered, your browsing data stays on your device.",
    start_url: "/?utm_source=pwa",
    scope: "/",
    display: "standalone",
    orientation: "portrait",
    background_color: "#0f172a",
    theme_color: "#0f172a",
    lang: "en",
    dir: "auto",
    categories: ["security", "utilities", "productivity"],
    icons: [
      {
        src: "/icon-192.png",
        sizes: "192x192",
        type: "image/png",
        purpose: "any",
      },
      {
        src: "/icon-192.png",
        sizes: "192x192",
        type: "image/png",
        purpose: "maskable",
      },
      {
        src: "/apple-touch-icon.png",
        sizes: "180x180",
        type: "image/png",
        purpose: "any",
      },
    ],
    shortcuts: [
      {
        name: "Check a domain",
        short_name: "Check",
        description: "Run a safety check on any domain",
        url: "/check?utm_source=pwa_shortcut",
        icons: [{ src: "/icon-192.png", sizes: "192x192" }],
      },
      {
        name: "Pricing",
        short_name: "Pricing",
        url: "/pricing?utm_source=pwa_shortcut",
        icons: [{ src: "/icon-192.png", sizes: "192x192" }],
      },
    ],
  };
}
