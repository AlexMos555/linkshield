"use client";

import { useLocale, useTranslations } from "next-intl";
import { useState } from "react";

import { getSupabaseClient, isAuthConfigured } from "@/lib/supabase/client";
import { PrimaryInstallLink } from "@/components/PrimaryInstallLink";
import TurnstileWidget, { useTurnstileToken } from "@/components/TurnstileWidget";
import { localePath } from "@/lib/locale-path";
import { SUPPORT_EMAIL, SUPPORT_EMAIL_LIVE } from "@/lib/support";

/**
 * How long Continue waits for a Turnstile token before sending the OTP
 * request without one. The managed widget normally resolves well under a
 * second; this only matters when someone clicks faster than that.
 */
const CAPTCHA_TOKEN_WAIT_MS = 5_000;

interface SignupFormProps {
  planFromQuery: string | null;
  intervalFromQuery: string | null;
}

/** Which plain-language message to show for a failed OTP request. */
type SignupErrorKey = "error_rate_limited" | "error_send_failed";

/**
 * Supabase reports throttling as HTTP 429 or an `over_*_rate_limit` code; that
 * one deserves "wait a few minutes". Everything else gets the generic "try
 * later" — the raw provider message ("Error sending magic link email") is
 * English jargon that tells a person nothing they can act on.
 */
function signupErrorKey(error: { status?: number; code?: string }): SignupErrorKey {
  if (error.status === 429 || (error.code ?? "").includes("rate_limit")) return "error_rate_limited";
  return "error_send_failed";
}

/**
 * Magic-link signup form via Supabase Auth.
 *
 * Flow:
 *   1. User enters email + clicks Continue.
 *   2. supabase.auth.signInWithOtp() fires; Supabase sends the user a
 *      magic-link email (one-time login URL).
 *   3. User clicks the link → lands on /auth/callback which exchanges
 *      the URL hash for a session → redirects back to /pricing or
 *      wherever they came from.
 *   4. After session is set, /payments/checkout works because the user
 *      is now authenticated.
 *
 * This avoids password storage entirely — a single-factor passwordless
 * login that's good enough for a privacy-first product. Adding password
 * support is a one-line swap to signInWithPassword later.
 *
 * Captcha: a Cloudflare Turnstile token rides along as
 * `options.captchaToken`. Supabase validates it only while the project's
 * CAPTCHA protection is switched on (off today); auth-js already sends
 * `gotrue_meta_security.captcha_token` on every OTP request, so with it
 * off the field is simply ignored. The widget can never block a submit —
 * if it failed to load or is slow, the request goes out without a token,
 * exactly as before.
 *
 * Fallback when NEXT_PUBLIC_SUPABASE_* env vars are absent: if the support
 * mailbox works, the form opens a mailto: so the lead isn't lost; if it
 * doesn't (lib/support.ts), it says plainly that signing in is unavailable
 * rather than handing the person an email that goes nowhere.
 */
export default function SignupForm({ planFromQuery, intervalFromQuery }: SignupFormProps) {
  const t = useTranslations("Signup");
  const nav = useTranslations("Nav");
  const locale = useLocale();
  const [email, setEmail] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState(false);
  const captcha = useTurnstileToken();

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);
    if (!email || !email.includes("@")) {
      setError(t("error_invalid_email"));
      return;
    }

    setSubmitting(true);
    try {
      // ── Disposable-email gate ───────────────────────────────────
      // Hit our backend before kicking off Supabase Auth so an
      // attacker doesn't waste our magic-link send-rate budget on
      // mailinator.com / 10minutemail.com / etc. Defense-in-depth:
      // the backend is also rate-limited 60/hr/IP on this endpoint,
      // and Supabase Auth itself rate-limits magic links separately.
      // We fail-OPEN here on network error: a Cleanway API blip
      // shouldn't block legitimate signups.
      try {
        const apiBase = process.env.NEXT_PUBLIC_API_URL || "https://api.cleanway.ai";
        const dispResp = await fetch(`${apiBase}/api/v1/auth/check-email`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email }),
        });
        if (dispResp.ok) {
          const { disposable, domain } = await dispResp.json();
          if (disposable) {
            setError(t("error_disposable", { domain: String(domain ?? "") }));
            return;
          }
        }
        // 4xx (e.g., 422 malformed) or 5xx → silent fail-open.
        // The basic format check above + Supabase's own validation
        // will catch obvious garbage; legit signups go through.
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
          `Hi Cleanway team,\n\nI'd like to sign up.\n\n${planLine}Email: ${email}\n\nPlease let me know when signup goes live.\n`
        );
        window.location.href = `mailto:${SUPPORT_EMAIL}?subject=${subject}&body=${body}`;
        return;
      }

      // Build the redirect URL: after the magic link is clicked, Supabase
      // bounces back here with #access_token=... in the URL hash. The
      // callback route exchanges it for a session cookie.
      const next = planFromQuery
        ? `${localePath(locale, "/pricing")}?plan=${planFromQuery}${intervalFromQuery ? `&interval=${intervalFromQuery}` : ""}`
        : localePath(locale, "/");
      const redirect = `${window.location.origin}/auth/callback?next=${encodeURIComponent(next)}`;

      const supabase = getSupabaseClient();
      const captchaToken = await captcha.waitForToken(CAPTCHA_TOKEN_WAIT_MS);
      const { error: signInError } = await supabase.auth.signInWithOtp({
        email,
        options: {
          emailRedirectTo: redirect,
          shouldCreateUser: true,
          captchaToken: captchaToken ?? undefined,
        },
      });
      if (signInError) {
        // Tokens are single-use: whatever we just sent is spent, so the
        // next attempt needs a fresh one.
        captcha.reset();
        setError(t(signupErrorKey(signInError)));
        return;
      }
      setSent(true);
    } catch {
      // signInWithOtp resolves with an error object for API failures; a throw
      // here means the request never got an answer.
      setError(t("error_network"));
    } finally {
      setSubmitting(false);
    }
  };

  if (sent) {
    return (
      <div
        style={{
          background: "#1e293b",
          border: "1px solid #22c55e40",
          borderRadius: 12,
          padding: 24,
          textAlign: "center",
        }}
      >
        <div style={{ fontSize: 40, marginBottom: 12 }}>📩</div>
        <h2 style={{ fontSize: 18, fontWeight: 700, color: "#f8fafc", margin: "0 0 8px" }}>
          {t("check_inbox")}
        </h2>
        <p style={{ fontSize: 14, color: "#94a3b8", margin: "0 0 6px", lineHeight: 1.6 }}>
          {t.rich("magic_link_sent", {
            email,
            strong: (chunks) => <strong style={{ color: "#f8fafc" }}>{chunks}</strong>,
          })}
        </p>
        <p style={{ fontSize: 13, color: "#94a3b8", margin: 0 }}>
          {t("magic_link_followup")}
        </p>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        <span style={{ fontSize: 13, color: "#94a3b8", fontWeight: 500 }}>{t("email_label")}</span>
        <input
          type="email"
          autoComplete="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder={t("email_placeholder")}
          style={{
            background: "#0f172a",
            color: "#e2e8f0",
            border: "1px solid #334155",
            borderRadius: 10,
            padding: "12px 14px",
            fontSize: 15,
            outline: "none",
          }}
        />
      </label>

      <TurnstileWidget {...captcha.handlers} theme="dark" size="flexible" skipTestKeyInProduction />

      {error && (
        <div role="alert" style={{ background: "#7f1d1d20", color: "#fca5a5", border: "1px solid #7f1d1d", borderRadius: 8, padding: "8px 12px", fontSize: 13 }}>
          {error}
        </div>
      )}

      <button
        type="submit"
        disabled={submitting}
        style={{
          background: submitting ? "#0f5132" : "#22c55e",
          color: "#052e16",
          border: "none",
          borderRadius: 10,
          padding: "13px 16px",
          fontSize: 15,
          fontWeight: 700,
          cursor: submitting ? "wait" : "pointer",
          marginTop: 4,
        }}
      >
        {submitting
          ? t("submitting")
          : planFromQuery
          ? t("submit_with_plan")
          : t("submit_no_plan")}
      </button>

      <p style={{ fontSize: 12, color: "#94a3b8", marginTop: 8, lineHeight: 1.5 }}>
        {t("footer_lead")} {t("footer_or")}{" "}
        <PrimaryInstallLink androidLabel={nav("install_android")} style={{ color: "#60a5fa" }}>
          {t("footer_install_cta")}
        </PrimaryInstallLink>{" "}
        {t("footer_install_tail")}
      </p>
    </form>
  );
}
