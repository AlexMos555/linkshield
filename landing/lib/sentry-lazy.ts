/**
 * Browser error reporting without the SDK on the critical path.
 *
 * Imported eagerly, the Sentry browser SDK was 171 KB (gzip) of the 281 KB of
 * JavaScript every page shipped — more than React and Next together — and its
 * evaluation alone was the longest task before the page could respond on a
 * mid-range Android phone. Nothing on the page needs it to render, so it now
 * loads as its own chunk once the page has finished loading and the browser
 * is idle.
 *
 * Errors thrown before then are not lost: two plain listeners queue them from
 * the first script on, and they are reported as soon as the SDK is up.
 *
 * Kept free of any Sentry import so this file costs a few hundred bytes.
 */
import type { SentryModule } from "./sentry-init";

const DSN = process.env.NEXT_PUBLIC_SENTRY_DSN;

let loading: Promise<SentryModule | null> | null = null;

/** The initialized SDK, loading it now if it isn't yet; null without a DSN. */
export function loadSentry(): Promise<SentryModule | null> {
  if (!DSN || typeof window === "undefined") return Promise.resolve(null);
  loading ??= import("./sentry-init")
    .then(({ initSentry }) => initSentry(DSN))
    .catch(() => null);
  return loading;
}

/** Report an error, loading the SDK first if needed. Never throws. */
export function reportError(error: unknown, tags?: Record<string, string>): void {
  void loadSentry().then((sentry) => sentry?.captureException(error, tags ? { tags } : undefined));
}

/** Called once from sentry.client.config.ts, as the first client code runs. */
export function startSentryWhenIdle(): void {
  if (!DSN || typeof window === "undefined") return;

  const early: unknown[] = [];
  const onError = (event: ErrorEvent) => early.push(event.error ?? new Error(event.message));
  const onRejection = (event: PromiseRejectionEvent) => early.push(event.reason);
  window.addEventListener("error", onError);
  window.addEventListener("unhandledrejection", onRejection);

  const start = () => {
    void loadSentry().then((sentry) => {
      // From here on the SDK's own handlers report errors.
      window.removeEventListener("error", onError);
      window.removeEventListener("unhandledrejection", onRejection);
      if (sentry) for (const error of early.splice(0)) sentry.captureException(error);
    });
  };
  const whenIdle = () => {
    if ("requestIdleCallback" in window) window.requestIdleCallback(start, { timeout: 5000 });
    else setTimeout(start, 1500);
  };

  if (document.readyState === "complete") whenIdle();
  else window.addEventListener("load", whenIdle, { once: true });
}
