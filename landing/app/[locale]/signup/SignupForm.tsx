"use client";

import { useState } from "react";

interface SignupFormProps {
  planFromQuery: string | null;
  intervalFromQuery: string | null;
}

/**
 * Skeleton signup form.
 *
 * No real auth wired yet — this is the stub that exists so /pricing's
 * 401-redirect lands on a sensible page rather than a 404. Two paths:
 *
 * 1. Email + password (the default fields below) — the form posts to
 *    /api/v1/auth/signup once that endpoint exists. Until then,
 *    submitting opens a mailto: with the user's intent so we can
 *    capture leads via support@cleanway.ai inbox.
 *
 * 2. Magic-link button — same backend path will accept email-only.
 *
 * When the auth backend lands, the form action wires up automatically;
 * the UI here doesn't need to change beyond removing the mailto fallback.
 */
export default function SignupForm({ planFromQuery, intervalFromQuery }: SignupFormProps) {
  const [email, setEmail] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);
    if (!email || !email.includes("@")) {
      setError("Please enter a valid email address.");
      return;
    }

    setSubmitting(true);
    try {
      // Once the auth backend lands, swap this for:
      //   POST /api/v1/auth/signup (or magic-link / OAuth flow)
      // and chain into checkout. For now we capture the lead via mailto
      // so an interested user is never lost.
      const subject = encodeURIComponent("Signup interest — Cleanway");
      const planLine = planFromQuery
        ? `Plan: ${planFromQuery}${intervalFromQuery ? ` (${intervalFromQuery})` : ""}\n`
        : "";
      const body = encodeURIComponent(
        `Hi Cleanway team,\n\nI'd like to sign up.\n\n${planLine}Email: ${email}\n\nPlease let me know when signup goes live.\n`
      );
      window.location.href = `mailto:support@cleanway.ai?subject=${subject}&body=${body}`;
    } catch {
      setError("Something went wrong. Please email support@cleanway.ai directly.");
    } finally {
      setSubmitting(false);
    }
  };

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
        {submitting ? "Sending…" : planFromQuery ? "Continue to checkout" : "Continue"}
      </button>

      <p style={{ fontSize: 12, color: "#64748b", marginTop: 8, lineHeight: 1.5 }}>
        Signup is rolling out. We&apos;ll email you when it goes live for your account, or you can{" "}
        <a href="https://chrome.google.com/webstore" style={{ color: "#60a5fa" }}>install the extension free</a>{" "}
        right now — blocking always works without an account.
      </p>
    </form>
  );
}
