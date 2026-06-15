/**
 * Sentry client-side config (browser).
 *
 * Activates automatically when NEXT_PUBLIC_SENTRY_DSN is set in Vercel
 * env. With no DSN, init() is a no-op — Sentry stays dormant, no
 * network calls, zero perf cost. That's deliberate: we don't want a
 * required external service for just running the site.
 *
 * tracesSampleRate: 0.1 (10% of transactions traced). At Cleanway's
 * scale that's plenty for finding regressions; we can dial up if we
 * have spare quota. Free tier allows 10K transactions/month per project.
 */
import * as Sentry from "@sentry/nextjs";

import { beforeBreadcrumbScrub, beforeSendScrub } from "./lib/sentry-scrub";

const dsn = process.env.NEXT_PUBLIC_SENTRY_DSN;

if (dsn) {
  Sentry.init({
    dsn,
    environment: process.env.NEXT_PUBLIC_VERCEL_ENV ?? "development",
    release: process.env.NEXT_PUBLIC_VERCEL_GIT_COMMIT_SHA,
    tracesSampleRate: 0.1,
    // PII scrubbing — drop emails / JWTs / Stripe IDs from every event
    // before Sentry sees it. Marketing copy says privacy-first; events
    // retain for 90 days and employees have read access.
    sendDefaultPii: false,
    beforeSend: beforeSendScrub,
    beforeBreadcrumb: beforeBreadcrumbScrub,
    // Replays only in production — they cost more quota.
    replaysSessionSampleRate: process.env.NEXT_PUBLIC_VERCEL_ENV === "production" ? 0.01 : 0,
    replaysOnErrorSampleRate: 1.0,
    // Privacy: never capture user input fields or text content
    // (we're a privacy-first product; behavior should match the
    // marketing copy).
    integrations: [
      Sentry.replayIntegration({
        maskAllText: true,
        maskAllInputs: true,
        blockAllMedia: true,
      }),
    ],
  });

  // Expose Sentry on `window` only in non-production builds.
  //
  // The audit (landing-security LOW "window.Sentry SDK exposed as a
  // global on every production page, enabling Sentry quota exhaustion")
  // flagged the earlier "always expose" code: any third-party script
  // running on the page (a future analytics tag, a typo'd CDN URL,
  // a compromised dependency) could call
  // window.Sentry.captureMessage(...) in a loop and burn through our
  // Sentry quota. In production we don't need DevTools debugging on
  // every page; the SDK's onerror handlers cover the real failure
  // path. In preview/dev we still expose it so engineers can verify
  // the SDK is loaded.
  const env = process.env.NEXT_PUBLIC_VERCEL_ENV;
  if (typeof window !== "undefined" && env !== "production") {
    (window as unknown as { Sentry: typeof Sentry }).Sentry = Sentry;
  }
}
