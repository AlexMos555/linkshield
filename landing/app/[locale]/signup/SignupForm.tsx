"use client";

import { useState } from "react";

import { getSupabaseClient, isAuthConfigured } from "@/lib/supabase/client";

interface SignupFormProps {
  planFromQuery: string | null;
  intervalFromQuery: string | null;
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
 * Fallback when NEXT_PUBLIC_SUPABASE_* env vars are absent: the form
 * sends a mailto: with the user's intent so leads aren't dropped while
 * Supabase Auth is being wired in Vercel/Railway.
 */
export default function SignupForm({ planFromQuery, intervalFromQuery }: SignupFormProps) {
  const [email, setEmail] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState(false);

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);
    if (!email || !email.includes("@")) {
      setError("Please enter a valid email address.");
      return;
    }

    setSubmitting(true);
    try {
      // No env config → fall back to mailto so leads are still captured.
      if (!isAuthConfigured()) {
        const subject = encodeURIComponent("Signup interest — Cleanway");
        const planLine = planFromQuery
          ? `Plan: ${planFromQuery}${intervalFromQuery ? ` (${intervalFromQuery})` : ""}\n`
          : "";
        const body = encodeURIComponent(
          `Hi Cleanway team,\n\nI'd like to sign up.\n\n${planLine}Email: ${email}\n\nPlease let me know when signup goes live.\n`
        );
        window.location.href = `mailto:support@cleanway.ai?subject=${subject}&body=${body}`;
        return;
      }

      // Build the redirect URL: after the magic link is clicked, Supabase
      // bounces back here with #access_token=... in the URL hash. The
      // callback route exchanges it for a session cookie.
      const next = planFromQuery
        ? `/pricing?plan=${planFromQuery}${intervalFromQuery ? `&interval=${intervalFromQuery}` : ""}`
        : "/";
      const redirect = `${window.location.origin}/auth/callback?next=${encodeURIComponent(next)}`;

      const supabase = getSupabaseClient();
      const { error: signInError } = await supabase.auth.signInWithOtp({
        email,
        options: {
          emailRedirectTo: redirect,
          shouldCreateUser: true,
        },
      });
      if (signInError) {
        setError(signInError.message);
        return;
      }
      setSent(true);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setError(`Couldn't send the magic link: ${msg}`);
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
          Check your inbox
        </h2>
        <p style={{ fontSize: 14, color: "#94a3b8", margin: "0 0 6px", lineHeight: 1.6 }}>
          We sent a magic-link sign-in to <strong style={{ color: "#f8fafc" }}>{email}</strong>.
        </p>
        <p style={{ fontSize: 13, color: "#64748b", margin: 0 }}>
          Click the link to finish signing in. The page will continue automatically.
        </p>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <label style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        <span style={{ fontSize: 13, color: "#94a3b8", fontWeight: 500 }}>Email</span>
        <input
          type="email"
          autoComplete="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@example.com"
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

      {error && (
        <div style={{ background: "#7f1d1d20", color: "#fca5a5", border: "1px solid #7f1d1d", borderRadius: 8, padding: "8px 12px", fontSize: 13 }}>
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
        {submitting ? "Sending magic link…" : planFromQuery ? "Email me a sign-in link" : "Continue"}
      </button>

      <p style={{ fontSize: 12, color: "#64748b", marginTop: 8, lineHeight: 1.5 }}>
        We&apos;ll email you a one-time sign-in link. No password to remember. Or{" "}
        <a href="https://chrome.google.com/webstore" style={{ color: "#60a5fa" }}>install the extension free</a>{" "}
        — blocking always works without an account.
      </p>
    </form>
  );
}
