"use client";

import { useLocale, useTranslations } from "next-intl";
import { useCallback, useEffect, useRef, useState, type CSSProperties } from "react";

import { routing } from "@/i18n/routing";
import {
  MSG_CONNECT,
  MSG_FROM_EXTENSION,
  MSG_FROM_PAGE,
  MSG_HELLO,
  MSG_READY,
  MSG_RESULT,
  READY_TIMEOUT_MS,
  RESULT_TIMEOUT_MS,
  extensionErrorKey,
  isMintedSession,
  isValidConnectState,
  mintOutcome,
  signupForConnectPath,
  type ConnectErrorKey,
  type MintedSession,
} from "@/lib/extension-connect";
import { localePath } from "@/lib/locale-path";
import { getSupabaseClient, isAuthConfigured, supabasePublicConfig } from "@/lib/supabase/client";

type View =
  | { kind: "loading" }
  | { kind: "unavailable" }
  | { kind: "no_state" }
  | { kind: "ready"; email: string }
  | { kind: "connecting"; email: string }
  | { kind: "connected" }
  | { kind: "error"; key: ConnectErrorKey; email: string };

type ExtensionReply = { ok: boolean; error: string | null };

function apiBase(): string {
  return process.env.NEXT_PUBLIC_API_URL || "https://api.cleanway.ai";
}

/**
 * "Connect this browser to your Cleanway account".
 *
 * 1. No valid `state` → the page was not opened by the extension: say where
 *    to start. Not signed in → /signup, which brings the reader back here.
 * 2. Connect → POST /api/v1/auth/extension-session with the website's token:
 *    the API opens a separate session for the extension (lib/extension-connect.ts
 *    says why it can't share this one).
 * 3. That session and the state go to this window with postMessage, pinned to
 *    our own origin; the extension's content script relays it and answers.
 *    A refused session is ended right away so it does not linger unused.
 *
 * Tokens are never put in a URL, stored by this page, or logged.
 */
export default function ConnectClient({ state }: { state: string | null }) {
  const t = useTranslations("ExtensionConnect");
  const locale = useLocale();
  const [view, setView] = useState<View>({ kind: "loading" });
  const extensionReady = useRef(false);
  const readyWaiters = useRef<Array<() => void>>([]);
  const pendingResult = useRef<((reply: ExtensionReply | null) => void) | null>(null);
  const validState = isValidConnectState(state) ? state : null;
  const signupHref = validState ? signupForConnectPath(locale, validState, routing.defaultLocale) : localePath(locale, "/signup");

  // Hear the extension's content script — only from this window, this origin.
  useEffect(() => {
    const onMessage = (event: MessageEvent) => {
      if (event.source !== window || event.origin !== window.location.origin) return;
      const data = event.data as Record<string, unknown> | null;
      if (!data || typeof data !== "object" || data.source !== MSG_FROM_EXTENSION) return;
      if (data.type === MSG_READY) {
        extensionReady.current = true;
        readyWaiters.current.splice(0).forEach((resolve) => resolve());
      } else if (data.type === MSG_RESULT && pendingResult.current) {
        const resolve = pendingResult.current;
        pendingResult.current = null;
        resolve({ ok: data.ok === true, error: typeof data.error === "string" ? data.error : null });
      }
    };
    window.addEventListener("message", onMessage);
    window.postMessage({ source: MSG_FROM_PAGE, type: MSG_HELLO }, window.location.origin);
    return () => window.removeEventListener("message", onMessage);
  }, []);

  // Who is signed in here?
  useEffect(() => {
    if (!validState) {
      setView({ kind: "no_state" });
      return;
    }
    if (!isAuthConfigured()) {
      setView({ kind: "unavailable" });
      return;
    }
    let cancelled = false;
    const load = async () => {
      try {
        const {
          data: { session },
        } = await getSupabaseClient().auth.getSession();
        if (cancelled) return;
        if (!session) {
          window.location.replace(signupHref);
          return;
        }
        setView({ kind: "ready", email: session.user?.email ?? "" });
      } catch {
        if (!cancelled) setView({ kind: "error", key: "error_network", email: "" });
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, [validState, signupHref]);

  const waitForExtension = useCallback((): Promise<boolean> => {
    if (extensionReady.current) return Promise.resolve(true);
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve(false), READY_TIMEOUT_MS);
      readyWaiters.current.push(() => {
        clearTimeout(timer);
        resolve(true);
      });
      window.postMessage({ source: MSG_FROM_PAGE, type: MSG_HELLO }, window.location.origin);
    });
  }, []);

  const handOver = useCallback(
    (minted: MintedSession, connectState: string): Promise<ExtensionReply | null> =>
      new Promise((resolve) => {
        const timer = setTimeout(() => {
          pendingResult.current = null;
          resolve(null);
        }, RESULT_TIMEOUT_MS);
        pendingResult.current = (reply) => {
          clearTimeout(timer);
          resolve(reply);
        };
        window.postMessage(
          {
            source: MSG_FROM_PAGE,
            type: MSG_CONNECT,
            state: connectState,
            session: {
              access_token: minted.access_token,
              refresh_token: minted.refresh_token,
              expires_at: minted.expires_at,
              anon_key: supabasePublicConfig().anonKey,
            },
          },
          window.location.origin,
        );
      }),
    [],
  );

  const connect = async (email: string) => {
    if (!validState) return;
    setView({ kind: "connecting", email });
    // Ask first, mint second: never open a session nobody will receive.
    if (!(await waitForExtension())) {
      setView({ kind: "error", key: "error_no_extension", email });
      return;
    }

    let minted: MintedSession;
    try {
      const { data } = await getSupabaseClient().auth.getSession();
      const bearer = data.session?.access_token;
      if (!bearer) {
        window.location.replace(signupHref);
        return;
      }
      const resp = await fetch(`${apiBase()}/api/v1/auth/extension-session`, {
        method: "POST",
        headers: { Authorization: `Bearer ${bearer}` },
        cache: "no-store",
      });
      const outcome = mintOutcome(resp.status);
      if (outcome === "signin") {
        window.location.replace(signupHref);
        return;
      }
      const body: unknown = outcome === "ok" ? await resp.json().catch(() => null) : null;
      if (outcome !== "ok" || !isMintedSession(body)) {
        setView({ kind: "error", key: outcome === "ok" ? "error_failed" : outcome, email });
        return;
      }
      minted = body;
    } catch {
      setView({ kind: "error", key: "error_network", email });
      return;
    }

    const reply = await handOver(minted, validState);
    if (reply && reply.ok) {
      setView({ kind: "connected" });
      return;
    }
    void endSession(minted.access_token);
    setView({ kind: "error", key: reply ? extensionErrorKey(reply.error) : "error_no_extension", email });
  };

  const switchAccount = async () => {
    try {
      // "local": end only this website session, not the user's other devices.
      await getSupabaseClient().auth.signOut({ scope: "local" });
    } catch {
      // Already signed out or offline — the sign-in page works either way.
    }
    window.location.replace(signupHref);
  };

  if (view.kind === "loading") {
    return <p style={STYLES.lead} aria-live="polite">{t("loading")}</p>;
  }

  if (view.kind === "unavailable") {
    return <p role="alert" style={STYLES.alert}>{t("error_unavailable")}</p>;
  }

  if (view.kind === "no_state") {
    return (
      <section data-testid="connect-no-state">
        <h1 style={STYLES.h1}>{t("no_state_title")}</h1>
        <p style={STYLES.lead}>{t("no_state_body")}</p>
      </section>
    );
  }

  if (view.kind === "connected") {
    return (
      <section aria-live="polite" data-testid="connect-done">
        <h1 style={{ ...STYLES.h1, color: "#22c55e" }}>{t("connected_title")}</h1>
        <p style={STYLES.lead}>{t("connected_body")}</p>
      </section>
    );
  }

  const busy = view.kind === "connecting";
  return (
    <section data-testid="connect-ready">
      <h1 style={STYLES.h1}>{t("heading")}</h1>
      {view.email && (
        <p style={STYLES.account} data-testid="connect-email">
          {t("signed_in_as", { email: view.email })}
        </p>
      )}
      <p style={STYLES.lead}>{t("explain")}</p>

      {view.kind === "error" && (
        <div role="alert" style={STYLES.alert} data-testid="connect-error">
          {t(view.key)}
          {view.key === "error_locked" && (
            <>
              {" "}
              <a href={`${localePath(locale, "/account/restore")}?reason=locked`} style={{ color: "#fca5a5" }}>
                {t("restore_cta")}
              </a>
            </>
          )}
        </div>
      )}

      <button
        type="button"
        onClick={() => void connect(view.email)}
        disabled={busy}
        style={{ ...STYLES.button, background: busy ? "#0f5132" : "#22c55e", cursor: busy ? "wait" : "pointer" }}
      >
        {busy ? t("connecting") : t("connect")}
      </button>
      <button type="button" onClick={() => void switchAccount()} disabled={busy} style={STYLES.linkButton}>
        {t("other_account")}
      </button>
      <p style={STYLES.note}>{t("handover_note")}</p>
    </section>
  );
}

/** Best effort: end a session the extension did not take. */
async function endSession(accessToken: string): Promise<void> {
  const { url, anonKey } = supabasePublicConfig();
  if (!url || !anonKey) return;
  try {
    await fetch(`${url}/auth/v1/logout?scope=local`, {
      method: "POST",
      headers: { apikey: anonKey, Authorization: `Bearer ${accessToken}` },
    });
  } catch {
    // Offline: it expires unused.
  }
}

const STYLES: Record<string, CSSProperties> = {
  h1: { fontSize: 28, fontWeight: 800, color: "#f8fafc", margin: "0 0 12px", lineHeight: 1.25 },
  lead: { fontSize: 15, color: "#94a3b8", margin: "0 0 20px", lineHeight: 1.6 },
  account: {
    fontSize: 15,
    color: "#f8fafc",
    background: "#1e293b",
    border: "1px solid #334155",
    borderRadius: 10,
    padding: "12px 14px",
    margin: "0 0 16px",
    overflowWrap: "anywhere",
  },
  alert: {
    background: "#7f1d1d20",
    color: "#fca5a5",
    border: "1px solid #7f1d1d",
    borderRadius: 8,
    padding: "10px 12px",
    fontSize: 14,
    lineHeight: 1.5,
    margin: "0 0 16px",
  },
  button: {
    display: "block",
    width: "100%",
    minHeight: 48,
    color: "#052e16",
    border: "none",
    borderRadius: 10,
    padding: "13px 16px",
    fontSize: 16,
    fontWeight: 700,
  },
  linkButton: {
    display: "block",
    margin: "8px auto 0",
    minHeight: 44,
    background: "none",
    border: "none",
    color: "#60a5fa",
    fontSize: 14,
    padding: "8px 12px",
    cursor: "pointer",
  },
  note: { fontSize: 12, color: "#64748b", marginTop: 20, lineHeight: 1.5, textAlign: "center" },
};
