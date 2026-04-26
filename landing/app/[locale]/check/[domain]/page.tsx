import type { Metadata } from "next";

import ShareScanButton from "@/components/ShareScanButton";
import { routing, type Locale } from "@/i18n/routing";

const SITE_URL = "https://cleanway.ai";

type Props = { params: Promise<{ domain: string; locale: string }> };

type ScanResult = {
  level?: "safe" | "caution" | "dangerous";
  score?: number;
  verdict?: string;
  signals?: string[];
  confidence?: string;
};

/**
 * Build the locale-prefixed path. With `localePrefix: "as-needed"`,
 * the default locale (en) lives at /check/{domain}; the rest at
 * /{locale}/check/{domain}.
 */
function pathFor(locale: Locale, domain: string): string {
  const slug = `check/${domain}`;
  return locale === routing.defaultLocale ? `/${slug}` : `/${locale}/${slug}`;
}

function urlFor(locale: Locale, domain: string): string {
  return `${SITE_URL}${pathFor(locale, domain)}`;
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { domain, locale } = await params;
  const decoded = decodeURIComponent(domain);
  const isLocaleKnown = (routing.locales as readonly string[]).includes(locale);
  const safeLocale: Locale = isLocaleKnown ? (locale as Locale) : routing.defaultLocale;

  const canonical = urlFor(safeLocale, domain);

  // hreflang map — every locale plus an x-default pointing at English
  const languages: Record<string, string> = {};
  for (const loc of routing.locales) {
    languages[loc] = urlFor(loc as Locale, domain);
  }
  languages["x-default"] = urlFor(routing.defaultLocale as Locale, domain);

  const title = `Is ${decoded} safe? — Cleanway Safety Check`;
  const description = `Check if ${decoded} is a phishing or scam website. Free safety analysis with 42+ detection signals and 9 threat intelligence sources.`;

  return {
    title,
    description,
    metadataBase: new URL(SITE_URL),
    alternates: {
      canonical,
      languages,
    },
    openGraph: {
      title: `Is ${decoded} safe?`,
      description: `Cleanway safety report for ${decoded}`,
      url: canonical,
      siteName: "Cleanway",
      type: "article",
      // OG image is generated automatically from sibling opengraph-image.tsx
    },
    twitter: {
      card: "summary_large_image",
      title: `Is ${decoded} safe?`,
      description: `Cleanway safety report for ${decoded}`,
      site: "@cleanwayai",
    },
    robots: {
      index: true,
      follow: true,
      googleBot: { index: true, follow: true, "max-image-preview": "large" },
    },
  };
}

async function fetchScan(domain: string): Promise<ScanResult> {
  try {
    const apiBase =
      process.env.NEXT_PUBLIC_API_URL ||
      process.env.API_URL ||
      "https://api.cleanway.ai";
    const resp = await fetch(`${apiBase}/api/v1/public/check/${domain}`, {
      next: { revalidate: 3600 },
    });
    if (!resp.ok) return {};
    return (await resp.json()) as ScanResult;
  } catch {
    return {};
  }
}

export default async function CheckPage({ params }: Props) {
  const { domain, locale } = await params;
  const decodedDomain = decodeURIComponent(domain);
  const isLocaleKnown = (routing.locales as readonly string[]).includes(locale);
  const safeLocale: Locale = isLocaleKnown ? (locale as Locale) : routing.defaultLocale;
  const result = await fetchScan(decodedDomain);

  type Level = "safe" | "caution" | "dangerous";
  const levelColors: Record<Level, string> = {
    safe: "#22c55e",
    caution: "#f59e0b",
    dangerous: "#ef4444",
  };

  const levelIcons: Record<Level, string> = {
    safe: "✅",
    caution: "⚠️",
    dangerous: "❌",
  };

  const levelLabels: Record<Level, string> = {
    safe: "Safe",
    caution: "Caution",
    dangerous: "Dangerous",
  };

  const level: Level = (result?.level && ["safe", "caution", "dangerous"].includes(result.level)
    ? result.level
    : "caution") as Level;
  const score = result?.score ?? "?";
  const color = levelColors[level] || "#64748b";
  const canonical = urlFor(safeLocale, domain);

  // ── JSON-LD: rich structured data ──────────────────────────────
  // Two-graph: WebPage describing the report itself, plus Review on the
  // domain as a SoftwareApplication target so search engines understand
  // we're rating the site, not just describing one. Best ratings are 100,
  // worst is 0 — explicit so Google can show the score chip in SERPs.
  const numericScore = typeof score === "number" ? score : null;
  const ratingValue = numericScore ?? (level === "safe" ? 90 : level === "dangerous" ? 15 : 50);
  const reviewBody =
    result?.verdict ?? `Cleanway analyzed ${decodedDomain} against 9 threat intelligence sources and ML detection.`;
  const jsonLd = {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "WebPage",
        "@id": `${canonical}#webpage`,
        url: canonical,
        name: `Is ${decodedDomain} safe? — Cleanway`,
        description: `Safety check for ${decodedDomain}. Score ${score}/100.`,
        inLanguage: safeLocale,
        isPartOf: { "@id": `${SITE_URL}#website` },
        primaryImageOfPage: { "@id": `${canonical}#og-image` },
      },
      {
        "@type": "Review",
        "@id": `${canonical}#review`,
        url: canonical,
        author: { "@type": "Organization", name: "Cleanway", url: SITE_URL },
        publisher: { "@type": "Organization", name: "Cleanway", url: SITE_URL },
        itemReviewed: {
          "@type": "WebSite",
          name: decodedDomain,
          url: `https://${decodedDomain}`,
        },
        reviewBody,
        reviewRating: {
          "@type": "Rating",
          ratingValue,
          bestRating: 100,
          worstRating: 0,
        },
      },
      {
        "@type": "WebSite",
        "@id": `${SITE_URL}#website`,
        url: SITE_URL,
        name: "Cleanway",
        description: "Privacy-first protection from phishing and scam sites.",
        publisher: { "@type": "Organization", name: "Cleanway" },
      },
    ],
  };

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
          <a
            href="https://chrome.google.com/webstore"
            style={{
              background: "#22c55e",
              color: "#052e16",
              padding: "8px 18px",
              borderRadius: 8,
              fontWeight: 700,
              fontSize: 13,
              textDecoration: "none",
            }}
          >
            Add to Chrome
          </a>
        </div>
      </nav>

      <div style={{ maxWidth: 800, margin: "0 auto", padding: "48px 24px" }}>
        {/* Main Result Card */}
        <div
          style={{
            background: "#1e293b",
            borderRadius: 16,
            padding: "32px",
            border: `1px solid ${color}40`,
            marginBottom: 24,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 20 }}>
            <div
              style={{
                width: 64,
                height: 64,
                borderRadius: "50%",
                background: `${color}20`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: 32,
              }}
            >
              {levelIcons[level]}
            </div>
            <div>
              <h1 style={{ fontSize: 28, fontWeight: 800, color: "#f8fafc", margin: 0 }}>Is {decodedDomain} safe?</h1>
              <p style={{ fontSize: 18, color, fontWeight: 600, margin: "4px 0 0" }}>
                {levelLabels[level]} &mdash; Score: {score}/100
              </p>
            </div>
          </div>

          {result?.verdict && (
            <p style={{ fontSize: 16, color: "#94a3b8", lineHeight: 1.6, marginBottom: 20 }}>{result.verdict}</p>
          )}

          {result?.signals && result.signals.length > 0 && (
            <div style={{ marginBottom: 20 }}>
              <h3 style={{ fontSize: 14, color: "#64748b", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 8 }}>
                Detection Signals
              </h3>
              {result.signals.map((s: string, i: number) => (
                <div key={i} style={{ display: "flex", gap: 8, padding: "6px 0", fontSize: 14, color: "#94a3b8" }}>
                  <span style={{ color }}>&#x2022;</span>
                  <span>{s}</span>
                </div>
              ))}
            </div>
          )}

          {result?.confidence === "low" && (
            <p style={{ fontSize: 13, color: "#f59e0b", fontStyle: "italic", marginBottom: 20 }}>
              This is a basic analysis. Install Cleanway for real-time protection with 9 threat intelligence sources.
            </p>
          )}

          <ShareScanButton domain={decodedDomain} level={level} score={score} url={canonical} />
        </div>

        {/* CTA */}
        <div style={{ background: "#1e293b", borderRadius: 16, padding: 24, textAlign: "center" }}>
          <h2 style={{ fontSize: 22, fontWeight: 700, color: "#f8fafc", marginBottom: 8 }}>Get real-time protection</h2>
          <p style={{ fontSize: 14, color: "#94a3b8", marginBottom: 16 }}>
            Cleanway checks every link automatically. 9 threat sources, ML-powered, zero data stored.
          </p>
          <a
            href="https://chrome.google.com/webstore"
            style={{
              display: "inline-block",
              background: "#22c55e",
              color: "#052e16",
              padding: "12px 28px",
              borderRadius: 10,
              fontWeight: 700,
              fontSize: 15,
              textDecoration: "none",
            }}
          >
            Add to Chrome &mdash; Free
          </a>
        </div>

        {/* SEO: Structured Data */}
        <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />

        {/* Check Another */}
        <div style={{ marginTop: 32, textAlign: "center" }}>
          <p style={{ color: "#64748b", fontSize: 14, marginBottom: 12 }}>Check another domain:</p>
          <form action="/check" method="get" style={{ display: "flex", gap: 8, maxWidth: 400, margin: "0 auto" }}>
            <input
              name="q"
              placeholder="Enter domain..."
              style={{
                flex: 1,
                padding: "10px 14px",
                borderRadius: 8,
                border: "1px solid #334155",
                background: "#0f172a",
                color: "#e2e8f0",
                fontSize: 14,
                outline: "none",
              }}
            />
            <button
              type="submit"
              style={{
                background: "#3b82f6",
                color: "white",
                border: "none",
                padding: "10px 20px",
                borderRadius: 8,
                fontWeight: 600,
                cursor: "pointer",
              }}
            >
              Check
            </button>
          </form>
        </div>

        <p style={{ textAlign: "center", fontSize: 12, color: "#475569", marginTop: 32 }}>
          Data from 9 threat intelligence sources. Updated in real-time.{" "}
          <a href="/privacy-policy" style={{ color: "#60a5fa" }}>
            Privacy Policy
          </a>
        </p>
      </div>
    </div>
  );
}
