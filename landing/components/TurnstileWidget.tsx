"use client";

/**
 * Cloudflare Turnstile widget (explicit render) + a small token controller.
 *
 * Used on /signup (token goes into `signInWithOtp({ options: { captchaToken } })`)
 * and on /auth/captcha (token is handed back to the mobile app via deep link).
 * Sitekey / test-mode logic lives in lib/turnstile.ts so both surfaces can
 * never drift apart.
 *
 * Design rule: the widget must never be able to BLOCK a flow. It reports what
 * happened through callbacks; whether to wait, retry, or proceed without a
 * token is the caller's call. `useTurnstileToken` encodes the /signup policy:
 * wait briefly for a token, then carry on with whatever we have.
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  type CSSProperties,
} from "react";

import { TURNSTILE_SITE_KEY, loadTurnstile, type TurnstileApi } from "@/lib/turnstile";

/** Operator notices are for us, not for the person signing up. */
const SHOW_OPERATOR_NOTICE = process.env.NODE_ENV !== "production";

export interface TurnstileControls {
  /** Discard the current token and run the challenge again. */
  readonly reset: () => void;
}

export interface TurnstileWidgetProps {
  /** A fresh token. Single-use, valid for 300 s. */
  readonly onToken: (token: string) => void;
  /** The last token is no longer valid; Turnstile refreshes it and calls onToken again. */
  readonly onExpire?: () => void;
  /** The widget reported an error code. Retrying is the caller's decision (remount). */
  readonly onError?: (code: string) => void;
  /** api.js never loaded (offline, blocked CDN) — no token will ever arrive. */
  readonly onUnavailable?: (reason: string) => void;
  /** Widget rendered; receives controls for resetting after a token is spent. */
  readonly onReady?: (controls: TurnstileControls) => void;
  readonly theme?: "auto" | "light" | "dark";
  readonly size?: "normal" | "flexible" | "compact";
  readonly language?: string;
  readonly style?: CSSProperties;
  /**
   * With Cloudflare's always-pass TEST key in a production build, render no
   * widget at all and report "unavailable" at once. The test widget itself
   * prints "for testing only — tell the site owner" at the visitor, and its
   * token protects nothing. /signup opts in; the mobile /auth/captcha page
   * does not, because the app waits for a token from it.
   */
  readonly skipTestKeyInProduction?: boolean;
}

export default function TurnstileWidget(props: TurnstileWidgetProps) {
  const { theme = "dark", size = "normal", language = "auto", style } = props;
  const skip = props.skipTestKeyInProduction === true && TURNSTILE_SITE_KEY.testMode && !SHOW_OPERATOR_NOTICE;
  const containerRef = useRef<HTMLDivElement>(null);

  // Latest callbacks in a ref: the widget renders once per mount instead of
  // being torn down whenever a parent re-renders with new closures.
  const callbacks = useRef(props);
  useEffect(() => {
    callbacks.current = props;
  });

  useEffect(() => {
    if (skip) {
      callbacks.current.onUnavailable?.("test_key_in_production");
      return;
    }
    const container = containerRef.current;
    if (!container) return;
    let api: TurnstileApi | null = null;
    let widgetId: string | undefined;
    let cancelled = false;

    loadTurnstile()
      .then((loaded) => {
        if (cancelled) return;
        api = loaded;
        widgetId = loaded.render(container, {
          sitekey: TURNSTILE_SITE_KEY.key,
          theme,
          size,
          language,
          callback: (token) => callbacks.current.onToken(token),
          "expired-callback": () => callbacks.current.onExpire?.(),
          "error-callback": (code) => callbacks.current.onError?.(code),
          "timeout-callback": () => callbacks.current.onError?.("timeout"),
        });
        if (widgetId === undefined) {
          callbacks.current.onUnavailable?.("render_failed");
          return;
        }
        const id = widgetId;
        callbacks.current.onReady?.({ reset: () => loaded.reset(id) });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        callbacks.current.onUnavailable?.(err instanceof Error ? err.message : "load_failed");
      });

    return () => {
      cancelled = true;
      if (api && widgetId !== undefined) api.remove(widgetId);
    };
  }, [theme, size, language, skip]);

  if (skip) return <TurnstileTestModeNotice />;

  return (
    <div style={style}>
      <div ref={containerRef} />
      {TURNSTILE_SITE_KEY.testMode && <TurnstileTestModeNotice />}
    </div>
  );
}

/**
 * Rendered whenever the always-pass test sitekey is in use. Deliberately
 * un-translated and loud in development: it is an operator signal, not user
 * copy. In production it used to be loud too, and a Russian visitor on
 * /ru/signup saw "Turnstile test mode — NEXT_PUBLIC_TURNSTILE_SITE_KEY is not
 * set" in English (report #19). There it is now an invisible marker the
 * operator can still find: `curl -s https://cleanway.ai/signup | grep
 * data-turnstile-test-mode`.
 * Exported so /auth/captcha can keep it after the widget unmounts (the test
 * key passes in about a second, which would hide it otherwise).
 */
export function TurnstileTestModeNotice() {
  if (!SHOW_OPERATOR_NOTICE) {
    return <span data-turnstile-test-mode="true" hidden />;
  }
  return (
    <p
      role="status"
      style={{
        fontSize: 11,
        color: "#fbbf24",
        margin: "6px 0 0",
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
      }}
    >
      Turnstile test mode — NEXT_PUBLIC_TURNSTILE_SITE_KEY is not set
    </p>
  );
}

// ─── Token controller for form submits ────────────────────────────

type Waiter = (token: string | null) => void;

interface TokenState {
  readonly token: string | null;
  readonly unavailable: boolean;
  readonly reset: (() => void) | null;
  readonly waiters: readonly Waiter[];
}

const INITIAL_TOKEN_STATE: TokenState = {
  token: null,
  unavailable: false,
  reset: null,
  waiters: [],
};

export interface TurnstileTokenController {
  /** Spread onto <TurnstileWidget />. */
  readonly handlers: TurnstileWidgetProps;
  /**
   * Resolve with the current token, or wait up to `timeoutMs` for one. Resolves
   * null immediately when the widget is known to be unavailable — never blocks
   * a submit on a captcha that cannot complete.
   */
  readonly waitForToken: (timeoutMs: number) => Promise<string | null>;
  /** Call after a token was sent to the server (tokens are single-use). */
  readonly reset: () => void;
}

export function useTurnstileToken(): TurnstileTokenController {
  const state = useRef<TokenState>(INITIAL_TOKEN_STATE);

  const handlers = useMemo<TurnstileWidgetProps>(() => {
    const settle = (token: string | null) => {
      const { waiters } = state.current;
      state.current = { ...state.current, token, waiters: [] };
      waiters.forEach((notify) => notify(token));
    };
    return {
      onToken: (token) => settle(token),
      onExpire: () => {
        state.current = { ...state.current, token: null };
      },
      onError: () => {
        state.current = { ...state.current, token: null };
      },
      onUnavailable: () => {
        state.current = { ...state.current, unavailable: true };
        settle(null);
      },
      onReady: (controls) => {
        state.current = { ...state.current, reset: controls.reset };
      },
    };
  }, []);

  const waitForToken = useCallback(
    (timeoutMs: number) =>
      new Promise<string | null>((resolve) => {
        const current = state.current;
        if (current.token || current.unavailable) {
          resolve(current.token);
          return;
        }
        const waiter: Waiter = (token) => {
          clearTimeout(timer);
          resolve(token);
        };
        const timer = setTimeout(() => {
          state.current = {
            ...state.current,
            waiters: state.current.waiters.filter((w) => w !== waiter),
          };
          resolve(state.current.token);
        }, timeoutMs);
        state.current = { ...current, waiters: [...current.waiters, waiter] };
      }),
    [],
  );

  const reset = useCallback(() => {
    state.current = { ...state.current, token: null };
    state.current.reset?.();
  }, []);

  return { handlers, waitForToken, reset };
}
