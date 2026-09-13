"use client";

/**
 * Hosted captcha challenge for the mobile app — /auth/captcha?nonce=<32 hex>
 *
 * The app has no webview dependency, so it opens this page in the system
 * browser (mobile/src/services/captcha.ts) and waits for
 * `cleanway://captcha-return?nonce=<same>&token=<token>`
 * (mobile/app/captcha-return.tsx). The nonce is the app's proof that the
 * token answers ITS request; we echo it, never mint one.
 *
 * Self-contained on purpose: no locale segment (the app's configured URL has
 * none), so it renders its own <html>/<body> under the passthrough root
 * layout and carries EN + RU copy inline — next-intl is not mounted here.
 *
 * Everything security-relevant (nonce format, scheme allowlist, deep-link
 * assembly) is in lib/turnstile.ts and table-tested; this file is the UI.
 */

import { useCallback, useEffect, useState, type CSSProperties } from "react";

import TurnstileWidget, { TurnstileTestModeNotice } from "@/components/TurnstileWidget";
import {
  TURNSTILE_SITE_KEY,
  buildCaptchaReturnUrl,
  parseCaptchaRequest,
  type CaptchaRequest,
} from "@/lib/turnstile";

type Lang = "en" | "ru";

const COPY: Record<Lang, Record<string, string>> = {
  en: {
    title: "Quick security check",
    loading: "Loading the check…",
    lead: "Cleanway needs to confirm you're a person before it sends your sign-in code.",
    done: "Done. Returning you to the app…",
    open: "Open Cleanway",
    openHint: "If the app didn't open on its own, tap the button.",
    failed: "The check didn't finish.",
    retry: "Try again",
    invalid: "This page only works when opened from the Cleanway app. Go back to the app and tap Continue again.",
  },
  ru: {
    title: "Быстрая проверка безопасности",
    loading: "Загружаем проверку…",
    lead: "Cleanway нужно убедиться, что вы человек, прежде чем отправить код входа.",
    done: "Готово. Возвращаемся в приложение…",
    open: "Открыть Cleanway",
    openHint: "Если приложение не открылось само, нажмите кнопку.",
    failed: "Проверка не завершилась.",
    retry: "Попробовать снова",
    invalid: "Эта страница работает только при открытии из приложения Cleanway. Вернитесь в приложение и снова нажмите «Продолжить».",
  },
};

type OkRequest = Extract<CaptchaRequest, { ok: true }>;

type Phase =
  | { readonly kind: "loading" }
  | { readonly kind: "invalid" }
  | { readonly kind: "ready"; readonly request: OkRequest; readonly attempt: number }
  | { readonly kind: "failed"; readonly request: OkRequest; readonly attempt: number }
  | { readonly kind: "done"; readonly returnUrl: string };

function detectLang(): Lang {
  return navigator.language.toLowerCase().startsWith("ru") ? "ru" : "en";
}

export default function CaptchaPage() {
  // SSR renders English; the browser's language is only known after mount.
  const [lang, setLang] = useState<Lang>("en");
  const [phase, setPhase] = useState<Phase>({ kind: "loading" });
  const copy = COPY[lang];

  useEffect(() => {
    setLang(detectLang());
    const request = parseCaptchaRequest(window.location.search);
    setPhase(request.ok ? { kind: "ready", request, attempt: 0 } : { kind: "invalid" });
  }, []);

  const handleToken = useCallback((token: string) => {
    setPhase((current) => {
      if (current.kind !== "ready") return current;
      const { scheme, nonce } = current.request;
      const returnUrl = buildCaptchaReturnUrl(scheme, nonce, token);
      return returnUrl ? { kind: "done", returnUrl } : { kind: "invalid" };
    });
  }, []);

  const handleFailure = useCallback(() => {
    setPhase((current) =>
      current.kind === "ready" ? { ...current, kind: "failed" } : current,
    );
  }, []);

  const retry = () => {
    setPhase((current) =>
      current.kind === "failed"
        ? { kind: "ready", request: current.request, attempt: current.attempt + 1 }
        : current,
    );
  };

  useEffect(() => {
    if (phase.kind !== "done") return;
    // Best effort. Browsers may refuse a custom-scheme navigation that was not
    // started by a tap, which is why the button below carries the same link.
    window.location.replace(phase.returnUrl);
  }, [phase]);

  return (
    <html lang={lang}>
      <body style={STYLES.body}>
        <title>Cleanway — security check</title>
        <meta name="robots" content="noindex" />
        <main style={STYLES.card}>
          <div aria-hidden="true" style={STYLES.icon}>
            🛡️
          </div>
          <h1 style={STYLES.title}>{copy.title}</h1>

          {phase.kind === "loading" && <p style={STYLES.lead}>{copy.loading}</p>}
          {phase.kind === "invalid" && <p style={STYLES.lead}>{copy.invalid}</p>}

          {(phase.kind === "ready" || phase.kind === "failed") && (
            <>
              <p style={STYLES.lead}>{copy.lead}</p>
              {phase.kind === "ready" ? (
                <TurnstileWidget
                  key={phase.attempt}
                  onToken={handleToken}
                  onError={handleFailure}
                  onUnavailable={handleFailure}
                  theme="dark"
                  size="normal"
                  language="auto"
                  style={STYLES.widget}
                />
              ) : (
                <>
                  <p style={STYLES.error}>{copy.failed}</p>
                  <button type="button" onClick={retry} style={STYLES.button}>
                    {copy.retry}
                  </button>
                </>
              )}
            </>
          )}

          {phase.kind === "done" && (
            <>
              <p style={STYLES.lead}>{copy.done}</p>
              <a href={phase.returnUrl} style={STYLES.button}>
                {copy.open}
              </a>
              <p style={STYLES.hint}>{copy.openHint}</p>
            </>
          )}

          {/* The widget carries this notice itself while mounted; keep it
              visible in every other phase so a test key can't hide behind
              an instant auto-pass. */}
          {TURNSTILE_SITE_KEY.testMode && phase.kind !== "ready" && <TurnstileTestModeNotice />}
        </main>
      </body>
    </html>
  );
}

const STYLES: Record<string, CSSProperties> = {
  body: {
    background: "#0f172a",
    color: "#e2e8f0",
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    margin: 0,
    minHeight: "100vh",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
  },
  card: {
    maxWidth: 420,
    width: "100%",
    padding: 24,
    textAlign: "center",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    gap: 12,
  },
  icon: { fontSize: 44 },
  title: { fontSize: 24, fontWeight: 800, color: "#f8fafc", margin: 0 },
  lead: { fontSize: 15, color: "#94a3b8", lineHeight: 1.6, margin: 0 },
  hint: { fontSize: 13, color: "#94a3b8", lineHeight: 1.5, margin: 0 },
  error: { fontSize: 14, color: "#fca5a5", margin: 0 },
  widget: { display: "flex", flexDirection: "column", alignItems: "center", marginTop: 8 },
  button: {
    display: "inline-block",
    background: "#22c55e",
    color: "#052e16",
    border: "none",
    padding: "12px 24px",
    borderRadius: 10,
    fontWeight: 800,
    fontSize: 15,
    cursor: "pointer",
    textDecoration: "none",
    marginTop: 4,
  },
};
