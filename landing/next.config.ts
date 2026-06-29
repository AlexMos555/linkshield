import type { NextConfig } from "next";
import createNextIntlPlugin from "next-intl/plugin";
import { withSentryConfig } from "@sentry/nextjs";

const withNextIntl = createNextIntlPlugin("./i18n/request.ts");

/**
 * HTTP security headers — applied to every response.
 *
 * The landing previously shipped with zero security headers (audit
 * landing-security HIGH). Each missing header was its own risk class:
 *
 *   • CSP             — anything that ran on the page could be replaced
 *                       via XSS / supply-chain compromise of a third-party
 *                       script. Now scripts/connections/etc. are pinned
 *                       to a known origin set.
 *   • HSTS            — TLS-strip MITM on first visit was possible. Now
 *                       enforced for 1y + includeSubDomains + preload-ready.
 *   • X-Frame-Options — clickjacking via iframe was possible (no frame-
 *                       ancestors in CSP either, so this is the seatbelt).
 *   • X-Content-Type  — MIME-sniffing-based content injection.
 *   • Referrer-Policy — full URL leaked to every third-party request.
 *   • Permissions-Policy — apps could request mic/cam/geolocation. We
 *                       use NONE of these; disabling tightens the
 *                       supply-chain blast radius.
 *
 * CSP is the longest because it has to enumerate every external origin
 * the site actually loads from. Audit current site with /diagnostics
 * or DevTools → Network before extending the list.
 */
const CSP_DIRECTIVES = [
  "default-src 'self'",
  // 'unsafe-inline' for script-src is required for Next.js inline
  // bootstrap + next-intl runtime; 'unsafe-eval' kept off. When we
  // wire a CSP nonce middleware in a follow-up, the unsafe-inline
  // for scripts can be dropped.
  // Sentry JS is bundled via @sentry/nextjs (not loaded from browser.sentry-cdn.com),
  // so script-src does NOT need the Sentry CDN origin. *.ingest.sentry.io stays in
  // connect-src only (it's an XHR endpoint, never a <script src>).
  "script-src 'self' 'unsafe-inline' https://js.stripe.com",
  // 'unsafe-inline' on style-src is needed for the inline `style={...}`
  // attributes used throughout the App Router pages (success, restore,
  // pricing). Tailwind output is fine without it.
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: https:",
  "font-src 'self' data:",
  // API base (configurable per environment) + Supabase auth/realtime +
  // Stripe checkout + Sentry ingest. Wildcarding subdomains so the
  // staging slug works too.
  // Sentry ingest is fetch-only (no <script>), kept in connect-src.
  "connect-src 'self' https://api.cleanway.ai https://*.supabase.co https://*.supabase.in https://api.stripe.com https://*.ingest.sentry.io",
  // Stripe Checkout + the Outlook add-in iframe surface (addin domain
  // sits on the same Vercel deploy).
  "frame-src https://js.stripe.com https://hooks.stripe.com https://addin.cleanway.ai",
  "frame-ancestors 'none'",
  "form-action 'self' https://checkout.stripe.com",
  "base-uri 'self'",
  "object-src 'none'",
  "upgrade-insecure-requests",
].join("; ");

const SECURITY_HEADERS = [
  { key: "Content-Security-Policy", value: CSP_DIRECTIVES },
  {
    // 1 year, preload-eligible. cleanway.ai is HTTPS-only on Vercel.
    key: "Strict-Transport-Security",
    value: "max-age=31536000; includeSubDomains; preload",
  },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    // We collect NONE of these. Locking them down means a future
    // compromised dep can't quietly start prompting.
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=(self \"https://checkout.stripe.com\"), interest-cohort=()",
  },
];

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: "/:path*",
        headers: SECURITY_HEADERS,
      },
    ];
  },
};

// Sentry plugin: ALWAYS wrap. The previous `SENTRY_AUTH_TOKEN ? wrap : config`
// branch was the actual root cause of "Sentry not loading on the site" —
// withSentryConfig is what auto-imports `sentry.client.config.ts` into the
// browser bundle. Without it, the client SDK never reaches the page; the
// runtime DSN is harmless because nothing reads it; both
// `Sentry.captureMessage(...)` from DevTools AND the automatic
// onerror/onunhandledrejection handlers stay silent.
//
// Source-map upload IS still gated on SENTRY_AUTH_TOKEN (passing it as
// undefined makes the upload step a no-op). When we wire SENTRY_AUTH_TOKEN
// later we just get readable stack traces in the Sentry dashboard; until
// then the SDK is fully functional, we just see minified frames.
const withSentry = (config: NextConfig): NextConfig =>
  withSentryConfig(config, {
    org: process.env.SENTRY_ORG,
    project: process.env.SENTRY_PROJECT,
    authToken: process.env.SENTRY_AUTH_TOKEN,
    // Suppresses Sentry SDK logs during the build
    silent: true,
    // Privacy-first: don't expose source maps to the public after upload.
    sourcemaps: { disable: false, deleteSourcemapsAfterUpload: true },
    disableLogger: true,
  });

export default withSentry(withNextIntl(nextConfig));
