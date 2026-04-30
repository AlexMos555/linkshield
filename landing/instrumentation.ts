/**
 * Next.js instrumentation hook — wires Sentry into the right runtime
 * automatically. Required so server.config.ts and edge.config.ts run
 * at startup (Next 15 stopped auto-loading them in production).
 */
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    await import("./sentry.server.config");
  }
  if (process.env.NEXT_RUNTIME === "edge") {
    await import("./sentry.edge.config");
  }
}

export { captureRequestError as onRequestError } from "@sentry/nextjs";
