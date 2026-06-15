"use client";

/**
 * Per-route error boundary.
 *
 * Next 15 calls this component for any uncaught error inside a Server
 * Component, Route Handler, or layout. Without it, Next falls back to
 * the default "Application error: a client-side exception has occurred"
 * banner — terrible UX and zero Sentry breadcrumb context.
 *
 * Wired here at the App Router root so every locale and route uses it.
 * Sentry is auto-instrumented by @sentry/nextjs's withSentryConfig
 * wrapper in next.config.ts; the captureException call below adds a
 * scoped breadcrumb so the operator can correlate to the user's URL.
 *
 * Audit finding landing-ts MEDIUM "No error.tsx or global-error.tsx
 * anywhere in the App Router".
 */
import { useEffect } from "react";
import * as Sentry from "@sentry/nextjs";

export default function GlobalRouteError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Sentry's auto-instrumentation already captures unhandled errors,
    // but explicitly reporting here lets us attach the digest (Next's
    // server-rendered error id) for cross-correlation with server logs.
    Sentry.captureException(error, {
      tags: { digest: error.digest ?? "unknown" },
    });
  }, [error]);

  return (
    <html lang="en">
      <body
        style={{
          background: "#0f172a",
          color: "#e2e8f0",
          fontFamily:
            '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
          margin: 0,
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <main
          style={{
            maxWidth: 480,
            padding: "24px",
            textAlign: "center",
          }}
        >
          <div
            aria-hidden="true"
            style={{
              fontSize: 56,
              marginBottom: 16,
            }}
          >
            🛡️
          </div>
          <h1
            style={{
              fontSize: 28,
              fontWeight: 800,
              color: "#f8fafc",
              margin: "0 0 12px",
            }}
          >
            Something went wrong on our end
          </h1>
          <p
            style={{
              fontSize: 16,
              color: "#94a3b8",
              lineHeight: 1.6,
              margin: "0 0 24px",
            }}
          >
            We&apos;ve been notified. You can try again, or head back to
            the home page.
          </p>
          <div
            style={{
              display: "flex",
              gap: 10,
              justifyContent: "center",
              flexWrap: "wrap",
            }}
          >
            <button
              type="button"
              onClick={reset}
              style={{
                background: "#22c55e",
                color: "#052e16",
                border: "none",
                padding: "12px 24px",
                borderRadius: 10,
                fontWeight: 800,
                fontSize: 14,
                cursor: "pointer",
              }}
            >
              Try again
            </button>
            <a
              href="/"
              style={{
                background: "transparent",
                color: "#94a3b8",
                border: "1px solid #334155",
                padding: "12px 24px",
                borderRadius: 10,
                fontWeight: 700,
                fontSize: 14,
                textDecoration: "none",
              }}
            >
              Back home
            </a>
          </div>
          {error.digest && (
            <p
              style={{
                fontSize: 11,
                color: "#94a3b8",
                marginTop: 28,
                lineHeight: 1.5,
              }}
            >
              Reference:{" "}
              <code
                style={{
                  fontFamily:
                    "ui-monospace, SFMono-Regular, Menlo, monospace",
                }}
              >
                {error.digest}
              </code>
            </p>
          )}
        </main>
      </body>
    </html>
  );
}
