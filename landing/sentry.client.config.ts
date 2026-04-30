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

const dsn = process.env.NEXT_PUBLIC_SENTRY_DSN;

if (dsn) {
  Sentry.init({
    dsn,
    environment: process.env.NEXT_PUBLIC_VERCEL_ENV ?? "development",
    release: process.env.NEXT_PUBLIC_VERCEL_GIT_COMMIT_SHA,
    tracesSampleRate: 0.1,
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
}
