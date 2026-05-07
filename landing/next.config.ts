import type { NextConfig } from "next";
import createNextIntlPlugin from "next-intl/plugin";
import { withSentryConfig } from "@sentry/nextjs";

const withNextIntl = createNextIntlPlugin("./i18n/request.ts");

const nextConfig: NextConfig = {
  // Add any Next.js specific config here
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
