"use client";

import { useLocale, useTranslations } from "next-intl";
import { useState } from "react";

import { getSupabaseClient } from "@/lib/supabase/client";

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL || "https://api.cleanway.ai";

const DEFAULT_LOCALE = "en";

type RestoreState =
  | { kind: "idle" }
  | { kind: "restoring" }
  | { kind: "restored" }
  | { kind: "error"; messageKey: "error_auth" | "error_network" | "error_generic"; serverMessage?: string }
  | { kind: "no_session" };

interface RestoreClientProps {
  /** Why the user landed here. `"locked"` = auth gate caught a 410; `null` = arrived directly. */
  reason: string | null;
}

/**
 * Build a locale-prefixed path. With `localePrefix: "as-needed"`, the
 * default locale (en) is unprefixed; everything else gets `/{locale}`
 * baked in. We mirror that here so window.location.href redirects
 * don't drop the user out of their locale on restore success.
 */
function localePath(locale: string, path: string): string {
  if (locale === DEFAULT_LOCALE) return path;
  return `/${locale}${path}`;
}

/**
 * Restore-after-soft-delete UI.
 *
 * Flow:
 *   1. User clicked "delete my account" earlier → backend set
 *      `deletion_requested_at` + Redis SETEX `deleted:{uid}` with 30d TTL.
 *   2. Any subsequent authed request now returns 410 with
 *      `detail.restore_url = "/api/v1/user/account/restore"`.
 *   3. The auth callback / signup form / pricing checkout detects that 410
 *      and redirects here with `?reason=locked`. The user clicks
 *      "Restore my account", we POST to the restore endpoint (which uses
 *      the bypass dependency `get_current_user_including_deleted` so it
 *      is reachable while locked), Redis flag is cleared, and we send
 *      them home — keeping their current locale prefix intact.
 *
 * If no Supabase session is found we ask them to sign in first; the
 * restore endpoint requires JWT auth. All copy is sourced from the
 * `AccountRestore` next-intl namespace (17 keys × 10 locales).
 */
export default function RestoreClient({ reason }: RestoreClientProps) {
  const t = useTranslations("AccountRestore");
  const locale = useLocale();
  const [state, setState] = useState<RestoreState>({ kind: "idle" });

  async function handleRestore() {
    setState({ kind: "restoring" });

    let bearer: string | null = null;
    try {
      const supabase = getSupabaseClient();
      const {
        data: { session },
      } = await supabase.auth.getSession();
      bearer = session?.access_token ?? null;
    } catch {
      setState({ kind: "error", messageKey: "error_auth" });
      return;
    }

    if (!bearer) {
      setState({ kind: "no_session" });
      return;
    }

    let resp: Response;
    try {
      resp = await fetch(`${API_BASE}/api/v1/user/account/restore`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${bearer}`,
          "Content-Type": "application/json",
        },
      });
    } catch {
      setState({ kind: "error", messageKey: "error_network" });
      return;
    }

    if (resp.status === 200) {
      setState({ kind: "restored" });
      // Wait a moment so the user sees the success state, then send
      // them home — in their own locale, not "/" which would strip
      // /ru, /ar, etc. on `localePrefix: "as-needed"`.
      setTimeout(() => {
        window.location.href = localePath(locale, "/");
      }, 1500);
      return;
    }

    if (resp.status === 401) {
      // JWT was rejected (likely expired between getSession and POST).
      // Send them to /signup to re-auth, preserving locale.
      window.location.href = localePath(
        locale,
        "/signup?next=/account/restore",
      );
      return;
    }

    // Anything else (404, 5xx) — surface the server `detail` if present
    // so support can correlate, otherwise the localized generic.
    const body = await resp.json().catch(() => null);
    const serverMessage =
      body && typeof body === "object" && "detail" in body && typeof body.detail === "string"
        ? body.detail
        : undefined;
    setState({ kind: "error", messageKey: "error_generic", serverMessage });
  }

  if (state.kind === "restored") {
    return (
      // aria-live polite — screen readers announce success once the
      // state flips, without interrupting whatever they were reading.
      <div aria-live="polite">
        <h1
          style={{
            fontSize: 28,
            fontWeight: 800,
            color: "#22c55e",
            marginBottom: 12,
          }}
        >
          {t("restored_title")}
        </h1>
        <p
          style={{
            fontSize: 16,
            color: "#94a3b8",
            lineHeight: 1.6,
            marginBottom: 24,
          }}
        >
          {t("restored_body")}
        </p>
      </div>
    );
  }

  if (state.kind === "no_session") {
    return (
      <>
        <h1
          style={{
            fontSize: 28,
            fontWeight: 800,
            color: "#f8fafc",
            marginBottom: 12,
          }}
        >
          {t("no_session_title")}
        </h1>
        <p
          style={{
            fontSize: 16,
            color: "#94a3b8",
            lineHeight: 1.6,
            marginBottom: 32,
          }}
        >
          {t("no_session_body")}
        </p>
        <a
          href={localePath(locale, "/signup?next=/account/restore")}
          style={{
            display: "inline-block",
            background: "#22c55e",
            color: "#052e16",
            padding: "14px 32px",
            borderRadius: 10,
            fontWeight: 800,
            fontSize: 15,
            textDecoration: "none",
          }}
        >
          {t("no_session_cta")}
        </a>
      </>
    );
  }

  const errorMessage =
    state.kind === "error"
      ? state.serverMessage ?? t(state.messageKey)
      : null;

  return (
    <>
      <h1
        style={{
          fontSize: 28,
          fontWeight: 800,
          color: "#f8fafc",
          marginBottom: 12,
        }}
      >
        {reason === "locked" ? t("heading_locked") : t("heading_default")}
      </h1>
      <p
        style={{
          fontSize: 16,
          color: "#94a3b8",
          lineHeight: 1.6,
          marginBottom: 28,
        }}
      >
        {t("body")}
      </p>

      <button
        type="button"
        onClick={handleRestore}
        disabled={state.kind === "restoring"}
        aria-busy={state.kind === "restoring"}
        style={{
          background: state.kind === "restoring" ? "#16a34a" : "#22c55e",
          color: "#052e16",
          padding: "14px 32px",
          borderRadius: 10,
          fontWeight: 800,
          fontSize: 15,
          border: "none",
          cursor: state.kind === "restoring" ? "wait" : "pointer",
          minWidth: 220,
        }}
      >
        {state.kind === "restoring" ? t("restoring") : t("cta")}
      </button>

      {/* aria-live assertive on errors — they're actionable, the user
          needs to know immediately something went wrong. */}
      <div
        role="status"
        aria-live="assertive"
        style={{ minHeight: 1 }}
      >
        {errorMessage && (
          <div
            style={{
              marginTop: 20,
              padding: 14,
              background: "rgba(239,68,68,0.1)",
              border: "1px solid #ef4444",
              borderRadius: 8,
              color: "#fecaca",
              fontSize: 14,
              textAlign: "left",
            }}
          >
            {errorMessage}
          </div>
        )}
      </div>

      <p
        style={{
          fontSize: 13,
          color: "#94a3b8",
          marginTop: 32,
          lineHeight: 1.6,
        }}
      >
        {t("footer_note")}
      </p>
    </>
  );
}
