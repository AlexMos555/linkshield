/**
 * Sentry client-side config (browser). withSentryConfig (next.config.ts)
 * injects this file into every page's client bundle.
 *
 * Activates only when NEXT_PUBLIC_SENTRY_DSN is set in Vercel env. With no
 * DSN nothing loads — Sentry stays dormant, no network calls, zero perf cost.
 *
 * The SDK itself is not imported here: it loads after the page is idle
 * (lib/sentry-lazy.ts — why, and how early errors are kept), and its settings
 * live in lib/sentry-init.ts.
 */
import { startSentryWhenIdle } from "./lib/sentry-lazy";

startSentryWhenIdle();
