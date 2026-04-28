import type { Metadata } from "next";

import { routing, type Locale } from "@/i18n/routing";
import SignupForm from "./SignupForm";

const SITE_URL = "https://cleanway.ai";

function urlFor(locale: Locale | string): string {
  return locale === routing.defaultLocale ? `${SITE_URL}/signup` : `${SITE_URL}/${locale}/signup`;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const { locale } = await params;
  const isLocaleKnown = (routing.locales as readonly string[]).includes(locale);
  const safeLocale: Locale = isLocaleKnown ? (locale as Locale) : routing.defaultLocale;

  const languages: Record<string, string> = {};
  for (const loc of routing.locales) languages[loc] = urlFor(loc as Locale);
  languages["x-default"] = urlFor(routing.defaultLocale);

  return {
    title: "Sign up — Cleanway",
    description:
      "Create your Cleanway account. Privacy-first phishing protection — your browsing data lives only on your device.",
    metadataBase: new URL(SITE_URL),
    alternates: { canonical: urlFor(safeLocale), languages },
    // Signup conversion pages benefit from being indexable so SEO from
    // /pricing benefits both pages. follow=true lets PageRank flow back.
    robots: { index: true, follow: true },
  };
}

type Props = {
  searchParams: Promise<{ plan?: string; interval?: string }>;
};

const VALID_PLANS = new Set(["personal", "family", "business"]);
const VALID_INTERVALS = new Set(["monthly", "yearly"]);

const PLAN_LABELS: Record<string, string> = {
  personal: "Personal",
  family: "Family",
  business: "Business",
};

export default async function SignupPage({ searchParams }: Props) {
  const sp = await searchParams;
  const plan = sp.plan && VALID_PLANS.has(sp.plan) ? sp.plan : null;
  const interval = sp.interval && VALID_INTERVALS.has(sp.interval) ? sp.interval : null;

  return (
    <div
      style={{
        background: "#0f172a",
        color: "#e2e8f0",
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        minHeight: "100vh",
      }}
    >
      <nav style={{ background: "#0f172af0", borderBottom: "1px solid #1e293b", padding: "14px 24px" }}>
        <div style={{ maxWidth: 800, margin: "0 auto", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <a href="/" style={{ color: "#f8fafc", textDecoration: "none", fontWeight: 800, fontSize: 20 }}>
            Cleanway
          </a>
          <a href="/pricing" style={{ color: "#94a3b8", textDecoration: "none", fontSize: 14 }}>
            ← Back to pricing
          </a>
        </div>
      </nav>

      <div style={{ maxWidth: 480, margin: "0 auto", padding: "60px 24px" }}>
        <h1 style={{ fontSize: 30, fontWeight: 800, color: "#f8fafc", marginBottom: 8 }}>
          Create your account
        </h1>
        <p style={{ fontSize: 15, color: "#94a3b8", marginBottom: 32, lineHeight: 1.6 }}>
          Privacy-first by design. Your browsing data stays on your device — our servers never see what you visit.
        </p>

        {/* Plan context — only shown when arrived from /pricing */}
        {plan && (
          <div
            style={{
              background: "#1e293b",
              borderRadius: 12,
              padding: "14px 18px",
              marginBottom: 24,
              border: "1px solid #22c55e40",
              display: "flex",
              alignItems: "center",
              gap: 12,
            }}
          >
            <div style={{ width: 32, height: 32, borderRadius: "50%", background: "#22c55e20", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16 }}>
              ✓
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 14, fontWeight: 600, color: "#f8fafc" }}>
                {PLAN_LABELS[plan] || plan} plan{interval ? ` · ${interval}` : ""}
              </div>
              <div style={{ fontSize: 12, color: "#94a3b8" }}>
                After signup we&apos;ll take you to checkout.
              </div>
            </div>
          </div>
        )}

        <SignupForm planFromQuery={plan} intervalFromQuery={interval} />

        {/* Privacy reassurance */}
        <div style={{ marginTop: 28, padding: "16px 18px", background: "#1e293b80", borderRadius: 10, border: "1px solid #1e293b" }}>
          <div style={{ fontSize: 12, color: "#64748b", textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 8 }}>
            What we store
          </div>
          <ul style={{ margin: 0, padding: "0 0 0 18px", fontSize: 13, color: "#94a3b8", lineHeight: 1.7 }}>
            <li>Your email + subscription status</li>
            <li>Anonymous device hashes (for sync)</li>
            <li>Weekly counters (numbers only — no URLs)</li>
          </ul>
          <div style={{ marginTop: 10, fontSize: 12, color: "#64748b" }}>
            Browsing history, full URLs, audit details:{" "}
            <strong style={{ color: "#22c55e" }}>never sent to us</strong>.{" "}
            <a href="/privacy-policy" style={{ color: "#60a5fa" }}>Read more</a>
          </div>
        </div>
      </div>
    </div>
  );
}
