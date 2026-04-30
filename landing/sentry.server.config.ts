/**
 * Sentry server-side config (Node runtime / SSR).
 *
 * Activates only when SENTRY_DSN is set in Vercel env. Server errors
 * during SSR or Route Handlers (/api/*, /auth/callback) flow here.
 *
 * NEXT_PUBLIC_VERCEL_ENV is auto-populated by Vercel ("production" /
 * "preview" / "development"); release tag is the git commit SHA so a
 * regression points at the exact deploy.
 */
import * as Sentry from "@sentry/nextjs";

const dsn = process.env.SENTRY_DSN || process.env.NEXT_PUBLIC_SENTRY_DSN;

if (dsn) {
  Sentry.init({
    dsn,
    environment: process.env.VERCEL_ENV ?? process.env.NEXT_PUBLIC_VERCEL_ENV ?? "development",
    release: process.env.VERCEL_GIT_COMMIT_SHA ?? process.env.NEXT_PUBLIC_VERCEL_GIT_COMMIT_SHA,
    tracesSampleRate: 0.1,
  });
}
