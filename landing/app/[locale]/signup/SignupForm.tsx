"use client";

import { useLocale, useTranslations } from "next-intl";
import { useCallback, useEffect, useRef, useState, type CSSProperties } from "react";

import { getSupabaseClient, isAuthConfigured } from "@/lib/supabase/client";
import { PrimaryInstallLink } from "@/components/PrimaryInstallLink";
import TurnstileWidget, { useTurnstileToken } from "@/components/TurnstileWidget";
import { localePath } from "@/lib/locale-path";
import {
  OTP_CODE_LEN,
  OTP_VERIFY_TYPES,
  RESEND_COOLDOWN_S,
  isCompleteOtpCode,
  isTokenRejected,
  normalizeOtpInput,
  queryErrorKey,
  sendErrorKey,
  verifyErrorKey,
} from "@/lib/signup-flow";
import { SUPPORT_EMAIL, SUPPORT_EMAIL_LIVE } from "@/lib/support";

/**
 * How long Continue waits for a Turnstile token before sending the OTP
 * request without one. The managed widget normally resolves well under a
 * second; this only matters when someone clicks faster than that.
 */
const CAPTCHA_TOKEN_WAIT_MS = 5_000;

/** The soft-delete probe sits in the post-sign-in critical path; keep it short. */
const PROBE_TIMEOUT_MS = 3_000;

interface SignupFormProps {
  planFromQuery: string | null;
  intervalFromQuery: string | null;
  /** `?error=` left by /auth/callback when a magic link could not sign in. */
  errorFromQuery?: string | null;
  /**
   * `?next=`, already checked by safeSignupNext() on the server: the
   * extension's connect page or the restore page. Wins over the plan/home
   * default.
   */
  nextFromQuery?: string | null;
}

type Step = "email" | "code";

/**
 * Passwordless sign-in form via Supabase Auth — the same two steps as the app.
 *
 * Flow:
 *   1. Enter email → `signInWithOtp()`; Supabase emails a 6-digit code
 *      (the templates in docs/email-templates/ show the code and no link).
 *   2. Type the code → `verifyOtp()` sets the session cookie (@supabase/ssr),
 *      so /pricing's checkout sees the signed-in user → redirect to `next`.
 *
 * Why a typed code rather than a magic link: the code works on whichever
 * device the email is read, while a PKCE link only works in the browser that
 * asked for it. The /auth/callback route still handles recovery and
 * email-change links and sends a failed one back here with `?error=`.
 *
 * Captcha: a Cloudflare Turnstile token rides along as `options.captchaToken`.
 * Supabase validates it only while the project's CAPTCHA protection is on
 * (off today). The widget can never block a submit — if it failed to load or
 * is slow, the request goes out without a token. It stays mounted across both
 * steps (keyed slot below) so «Отправить ещё раз» can get a fresh token too.
 *
 * Fallback when NEXT_PUBLIC_SUPABASE_* env vars are absent: if the support
 * mailbox works, the form opens a mailto: so the lead isn't lost; if it
 * doesn't (lib/support.ts), it says plainly that signing in is unavailable.
 */
export default function SignupForm({ planFromQuery, intervalFromQuery, errorFromQuery, nextFromQuery }: SignupFormProps) {
  const t = useTranslations("Signup");
  const nav = useTranslations("Nav");
  const locale = useLocale();
  const [step, setStep] = useState<Step>("email");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cooldown, setCooldown] = useState(0);
  const captcha = useTurnstileToken();

  // Absolute deadline, not a tick counter: a background tab is throttled
  // exactly while the person reads the email, and a counter that stops there
  // would keep «Отправить ещё раз» disabled long after the server would accept.
  const cooldownUntil = useRef(0);
  const cooldownTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => () => {
    if (cooldownTimer.current) clearInterval(cooldownTimer.current);
  }, []);

  const startCooldown = useCallback(() => {
    cooldownUntil.current = Date.now() + RESEND_COOLDOWN_S * 1000;
    setCooldown(RESEND_COOLDOWN_S);
    if (cooldownTimer.current) clearInterval(cooldownTimer.current);
    cooldownTimer.current = setInterval(() => {
      const left = Math.ceil((cooldownUntil.current - Date.now()) / 1000);
      if (left <= 0) {
        if (cooldownTimer.current) clearInterval(cooldownTimer.current);
        cooldownTimer.current = null;
        setCooldown(0);
        return;
      }
      setCooldown(left);
    }, 1000);
  }, []);

  const nextPath = nextFromQuery
    ? nextFromQuery
    : planFromQuery
      ? `${localePath(locale, "/pricing")}?plan=${planFromQuery}${intervalFromQuery ? `&interval=${intervalFromQuery}` : ""}`
      : localePath(locale, "/");

  const queryError = queryErrorKey(errorFromQuery);

  /** Step 1 — ask Supabase to email a code (also used by «Отправить ещё раз»). */
  const requestCode = async (): Promise<void> => {
    setError(null);
    const cleanEmail = email.trim();
    if (!cleanEmail || !cleanEmail.includes("@")) {
      setError(t("error_invalid_email"));
      return;
    }

    setBusy(true);
    try {
      // ── Disposable-email gate ───────────────────────────────────
      // Hit our backend before kicking off Supabase Auth so an attacker
      // doesn't waste our send-rate budget on mailinator.com / 10minutemail.
      // Defense-in-depth: the backend is also rate-limited 60/hr/IP on this
      // endpoint, and Supabase rate-limits codes separately. Fail-OPEN on
      // network error: a Cleanway API blip shouldn't block legitimate signups.
      try {
        const dispResp = await fetch(`${apiBase()}/api/v1/auth/check-email`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: cleanEmail }),
        });
        if (dispResp.ok) {
          const { disposable, domain } = await dispResp.json();
          if (disposable) {
            setError(t("error_disposable", { domain: String(domain ?? "") }));
            return;
          }
        }
      } catch {
        // Network failure → fail-open, see comment above.
      }

      if (!isAuthConfigured()) {
        if (!SUPPORT_EMAIL_LIVE) {
          setError(t("error_unavailable"));
          return;
        }
        // Auth not wired yet but the mailbox works: capture the lead by email.
        const subject = encodeURIComponent("Signup interest — Cleanway");
        const planLine = planFromQuery
          ? `Plan: ${planFromQuery}${intervalFromQuery ? ` (${intervalFromQuery})` : ""}\n`
          : "";
        const body = encodeURIComponent(
          `Hi Cleanway team,\n\nI'd like to sign up.\n\n${planLine}Email: ${cleanEmail}\n\nPlease let me know when signup goes live.\n`
        );
        window.location.href = `mailto:${SUPPORT_EMAIL}?subject=${subject}&body=${body}`;
        return;
      }

      // The recovery / email-change links still land on /auth/callback; the
      // sign-in code needs no redirect, but the field is harmless and keeps
      // an old-template project (link only) working until the templates are
      // applied.
      const redirect = `${window.location.origin}/auth/callback?next=${encodeURIComponent(nextPath)}`;
      const supabase = getSupabaseClient();
      const captchaToken = await captcha.waitForToken(CAPTCHA_TOKEN_WAIT_MS);
      const { error: sendError } = await supabase.auth.signInWithOtp({
        email: cleanEmail,
        options: {
          emailRedirectTo: redirect,
          shouldCreateUser: true,
          captchaToken: captchaToken ?? undefined,
        },
      });
      // Tokens are single-use: whatever we just sent is spent, so the next
      // request (a resend or a retry) needs a fresh one either way.
      captcha.reset();
      if (sendError) {
        setError(t(sendErrorKey(sendError)));
        return;
      }
      setStep("code");
      setCode("");
      startCooldown();
    } catch {
      // signInWithOtp resolves with an error object for API failures; a throw
      // here means the request never got an answer.
      setError(t("error_network"));
    } finally {
      setBusy(false);
    }
  };

  /** Step 2 — exchange the typed code for a session, then leave. */
  const verifyCode = async (): Promise<void> => {
    setError(null);
    if (!isCompleteOtpCode(code)) {
      setError(t("error_code_incomplete"));
      return;
    }
    setBusy(true);
    try {
      const supabase = getSupabaseClient();
      const cleanEmail = email.trim();
      let accessToken: string | null = null;
      let lastError: { status?: number; code?: string } | null = null;
      // A brand-new address gets a signup token, an existing one a magic-link
      // token; current GoTrue accepts both as "email", older only as "signup".
      // Retry under the other type only when the TOKEN was rejected.
      for (const type of OTP_VERIFY_TYPES) {
        const { data, error: verifyError } = await supabase.auth.verifyOtp({ email: cleanEmail, token: code, type });
        if (!verifyError) {
          accessToken = data.session?.access_token ?? null;
          lastError = null;
          break;
        }
        lastError = verifyError;
        if (!isTokenRejected(verifyError)) break;
      }
      if (lastError) {
        setError(t(verifyErrorKey(lastError)));
        return;
      }
      window.location.assign(await afterSignIn(accessToken));
    } catch {
      setError(t("error_network"));
    } finally {
      setBusy(false);
    }
  };

  /**
   * Same courtesy + gate as /auth/callback: fire the (server-deduped) welcome
   * email without waiting, and send a soft-deleted account to its restore
   * page in the reader's locale instead of a generic 410 somewhere else.
   */
  const afterSignIn = async (accessToken: string | null): Promise<string> => {
    if (!accessToken) return nextPath;
    const headers = { Authorization: `Bearer ${accessToken}` };
    void fetch(`${apiBase()}/api/v1/user/welcome`, { method: "POST", headers, keepalive: true }).catch(() => {});
    try {
      const probe = await fetch(`${apiBase()}/api/v1/user/profile`, {
        headers,
        signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
      });
      if (probe.status === 410) return `${localePath(locale, "/account/restore")}?reason=locked`;
    } catch {
      // Fail open: the destination page catches a 410 on its first call.
    }
    return nextPath;
  };

  const changeEmail = () => {
    setError(null);
    setCode("");
    setStep("email");
  };

  const onSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    void (step === "email" ? requestCode() : verifyCode());
  };

  return (
    <form onSubmit={onSubmit} style={STYLES.form}>
      {step === "email" ? (
        <div key="email" style={STYLES.form}>
          {queryError && !error && (
            <div role="alert" style={STYLES.alert}>
              {t(queryError)}
            </div>
          )}
          <label style={STYLES.label}>
            <span style={STYLES.labelText}>{t("email_label")}</span>
            <input
              type="email"
              autoComplete="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder={t("email_placeholder")}
              disabled={busy}
              style={STYLES.input}
            />
          </label>
        </div>
      ) : (
        <div key="code" style={STYLES.form}>
          <h2 style={STYLES.heading}>{t("code_heading")}</h2>
          <p style={STYLES.lead}>
            {t.rich("code_sent_to", {
              email: email.trim(),
              strong: (chunks) => <strong style={{ color: "#f8fafc" }}>{chunks}</strong>,
            })}
          </p>
          <label style={STYLES.label}>
            <span style={STYLES.labelText}>{t("code_label")}</span>
            <input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]*"
              maxLength={OTP_CODE_LEN}
              placeholder="000000"
              value={code}
              onChange={(e) => setCode(normalizeOtpInput(e.target.value))}
              disabled={busy}
              autoFocus
              aria-label={t("code_label")}
              data-testid="otp-code"
              style={{ ...STYLES.input, ...STYLES.codeInput }}
            />
          </label>
          <p style={STYLES.hint}>
            {t("code_valid_for")} {t("code_spam_hint")}
          </p>
        </div>
      )}

      <TurnstileWidget key="captcha" {...captcha.handlers} theme="dark" size="flexible" skipTestKeyInProduction />

      {error && (
        <div role="alert" style={STYLES.alert}>
          {error}
        </div>
      )}

      <button type="submit" disabled={busy} style={{ ...STYLES.button, background: busy ? "#0f5132" : "#22c55e", cursor: busy ? "wait" : "pointer" }}>
        {step === "email"
          ? busy ? t("submitting") : planFromQuery ? t("submit_with_plan") : t("submit_no_plan")
          : busy ? t("code_submitting") : t("code_submit")}
      </button>

      {step === "code" && (
        <div style={STYLES.secondaryRow}>
          <button
            type="button"
            onClick={() => void requestCode()}
            disabled={busy || cooldown > 0}
            style={{ ...STYLES.linkButton, color: cooldown > 0 ? "#64748b" : "#60a5fa" }}
          >
            {cooldown > 0 ? t("code_resend_in", { seconds: cooldown }) : t("code_resend")}
          </button>
          <button type="button" onClick={changeEmail} disabled={busy} style={STYLES.linkButton}>
            {t("code_change_email")}
          </button>
        </div>
      )}

      {step === "email" && (
        <p style={STYLES.footer}>
          {t("footer_lead")} {t("footer_or")}{" "}
          <PrimaryInstallLink androidLabel={nav("install_android")} style={{ color: "#60a5fa" }}>
            {t("footer_install_cta")}
          </PrimaryInstallLink>{" "}
          {t("footer_install_tail")}
        </p>
      )}
    </form>
  );
}

function apiBase(): string {
  return process.env.NEXT_PUBLIC_API_URL || "https://api.cleanway.ai";
}

const STYLES: Record<string, CSSProperties> = {
  form: { display: "flex", flexDirection: "column", gap: 12 },
  heading: { fontSize: 20, fontWeight: 700, color: "#f8fafc", margin: 0 },
  lead: { fontSize: 15, color: "#94a3b8", margin: 0, lineHeight: 1.6 },
  label: { display: "flex", flexDirection: "column", gap: 6 },
  labelText: { fontSize: 13, color: "#94a3b8", fontWeight: 500 },
  input: {
    background: "#0f172a",
    color: "#e2e8f0",
    border: "1px solid #334155",
    borderRadius: 10,
    padding: "12px 14px",
    fontSize: 15,
    outline: "none",
  },
  codeInput: { fontSize: 30, fontWeight: 700, letterSpacing: 10, textAlign: "center", fontVariantNumeric: "tabular-nums" },
  hint: { fontSize: 14, color: "#94a3b8", margin: 0, lineHeight: 1.6 },
  alert: {
    background: "#7f1d1d20",
    color: "#fca5a5",
    border: "1px solid #7f1d1d",
    borderRadius: 8,
    padding: "8px 12px",
    fontSize: 14,
    lineHeight: 1.5,
  },
  button: {
    color: "#052e16",
    border: "none",
    borderRadius: 10,
    padding: "13px 16px",
    fontSize: 15,
    fontWeight: 700,
    marginTop: 4,
  },
  secondaryRow: { display: "flex", flexDirection: "column", gap: 4, alignItems: "center" },
  linkButton: {
    background: "none",
    border: "none",
    color: "#94a3b8",
    fontSize: 14,
    padding: 8,
    cursor: "pointer",
  },
  footer: { fontSize: 12, color: "#94a3b8", marginTop: 8, lineHeight: 1.5 },
};
