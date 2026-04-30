import type { NextConfig } from "next";
import createNextIntlPlugin from "next-intl/plugin";
import { withSentryConfig } from "@sentry/nextjs";

const withNextIntl = createNextIntlPlugin("./i18n/request.ts");

const nextConfig: NextConfig = {
  // Add any Next.js specific config here
};

// Sentry plugin: enabled when SENTRY_AUTH_TOKEN is present (used for
// release / source-map upload during the build). Without the token
// the wrapper still injects runtime SDK init from sentry.*.config.ts,
// it just doesn't upload source maps. CI deploys past the build either
// way — no DSN means SDK init is a no-op at runtime.
const withSentry = (config: NextConfig): NextConfig =>
  process.env.SENTRY_AUTH_TOKEN
    ? withSentryConfig(config, {
        org: process.env.SENTRY_ORG,
        project: process.env.SENTRY_PROJECT,
        authToken: process.env.SENTRY_AUTH_TOKEN,
        // Suppresses Sentry SDK logs during the build
        silent: true,
        // Privacy-first: don't expose source maps to the public after upload.
        sourcemaps: { disable: false, deleteSourcemapsAfterUpload: true },
        disableLogger: true,
      })
    : config;

export default withSentry(withNextIntl(nextConfig));
