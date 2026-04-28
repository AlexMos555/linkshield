import type { Metadata } from "next";
import { notFound } from "next/navigation";

import ShareScanButton from "@/components/ShareScanButton";
import { routing, type Locale } from "@/i18n/routing";

const SITE_URL = "https://cleanway.ai";

// Privacy-grade letter scale (Privacy Badger / EFF convention).
const VALID_LETTERS = ["A", "B", "C", "D", "F"] as const;
type GradeLetter = (typeof VALID_LETTERS)[number];

const GRADE_INFO: Record<
  GradeLetter,
  { color: string; glow: string; label: string; description: string }
> = {
  A: {
    color: "#22c55e",
    glow: "rgba(34,197,94,0.25)",
    label: "Excellent privacy",
    description: "Minimal tracking. No fingerprinting. Few or no third-party trackers detected.",
  },
  B: {
    color: "#84cc16",
    glow: "rgba(132,204,22,0.25)",
    label: "Good privacy",
    description: "Some tracking, but mostly first-party. Manageable footprint for everyday use.",
  },
  C: {
    color: "#eab308",
    glow: "rgba(234,179,8,0.25)",
    label: "Average privacy",
    description: "Moderate tracker count. Common analytics + ads stack. Worth reviewing what's collected.",
  },
  D: {
    color: "#f97316",
    glow: "rgba(249,115,22,0.25)",
    label: "Heavy tracking",
    description: "Many third-party trackers. Fingerprinting attempts likely. Limit personal data here.",
  },
  F: {
    color: "#ef4444",
    glow: "rgba(239,68,68,0.25)",
    label: "Poor privacy",
    description: "Aggressive tracking, fingerprinting, or data collection patterns detected.",
  },
};

type Props = {
  params: Promise<{ domain: string; letter: string; locale: string }>;
};

function pathFor(locale: Locale, domain: string, letter: string): string {
  const slug = `audit/${domain}/grade/${letter}`;
  return locale === routing.defaultLocale ? `/${slug}` : `/${locale}/${slug}`;
}

function urlFor(locale: Locale, domain: string, letter: string): string {
  return `${SITE_URL}${pathFor(locale, domain, letter)}`;
}

function normalizeLetter(raw: string): GradeLetter | null {
  const upper = raw.toUpperCase();
  return (VALID_LETTERS as readonly string[]).includes(upper)
    ? (upper as GradeLetter)
    : null;
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { domain, letter, locale } = await params;
  const grade = normalizeLetter(letter);
  if (!grade) {
    // Returning empty metadata is fine — page itself will 404.
    return { title: "Privacy Audit — Cleanway" };
  }
  const decoded = decodeURIComponent(domain);
  const isLocaleKnown = (routing.locales as readonly string[]).includes(locale);
  const safeLocale: Locale = isLocaleKnown ? (locale as Locale) : routing.defaultLocale;
  const canonical = urlFor(safeLocale, domain, grade);

  const languages: Record<string, string> = {};
  for (const loc of routing.locales) languages[loc] = urlFor(loc as Locale, domain, grade);
  languages["x-default"] = urlFor(routing.defaultLocale as Locale, domain, grade);

  const info = GRADE_INFO[grade];
  const title = `${decoded} — Privacy Grade ${grade} · Cleanway`;
  const description = `${decoded} got a privacy grade of ${grade}. ${info.label}. ${info.description}`;

  return {
    title,
    description,
    metadataBase: new URL(SITE_URL),
    alternates: { canonical, languages },
    openGraph: {
      title: `Grade ${grade}: ${decoded}`,
      description,
      url: canonical,
      siteName: "Cleanway",
      type: "article",
      locale: safeLocale,
    },
    twitter: {
      card: "summary_large_image",
      title: `Grade ${grade}: ${decoded}`,
      description,
      site: "@cleanwayai",
    },
    robots: {
      index: true,
      follow: true,
      googleBot: { index: true, follow: true, "max-image-preview": "large" },
    },
  };
}

export default async function GradePage({ params }: Props) {
  const { domain, letter, locale } = await params;
  const grade = normalizeLetter(letter);
  if (!grade) notFound();

  const decoded = decodeURIComponent(domain);
  const isLocaleKnown = (routing.locales as readonly string[]).includes(locale);
  const safeLocale: Locale = isLocaleKnown ? (locale as Locale) : routing.defaultLocale;
  const canonical = urlFor(safeLocale, domain, grade);
  const info = GRADE_INFO[grade];

  // JSON-LD Review with the grade as ratingValue. Schema.org accepts
  // string ratings, but Google prefers numeric — map A=5, B=4, ..., F=1.
  const ratingMap: Record<GradeLetter, number> = { A: 5, B: 4, C: 3, D: 2, F: 1 };
  const jsonLd = {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "WebPage",
        "@id": `${canonical}#webpage`,
        url: canonical,
        name: `${decoded} — Privacy Grade ${grade}`,
        description: info.description,
        inLanguage: safeLocale,
        isPartOf: { "@id": `${SITE_URL}#website` },
      },
      {
        "@type": "Review",
        "@id": `${canonical}#review`,
        url: canonical,
        author: { "@type": "Organization", name: "Cleanway", url: SITE_URL },
        publisher: { "@type": "Organization", name: "Cleanway", url: SITE_URL },
        itemReviewed: {
          "@type": "WebSite",
          name: decoded,
          url: `https://${decoded}`,
        },
        reviewBody: info.description,
        reviewRating: {
          "@type": "Rating",
          ratingValue: ratingMap[grade],
          bestRating: 5,
          worstRating: 1,
          alternateName: `Grade ${grade}`,
        },
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

      <div style={{ maxWidth: 720, margin: "0 auto", padding: "60px 24px" }}>
        {/* Hero card with the grade */}
        <div
          style={{
            background: "#1e293b",
            borderRadius: 20,
            padding: "40px 32px",
            border: `1px solid ${info.color}40`,
            textAlign: "center",
            marginBottom: 24,
          }}
        >
          <div style={{ fontSize: 14, color: "#94a3b8", textTransform: "uppercase", letterSpacing: 2, marginBottom: 16 }}>
            Privacy Audit
          </div>
          <div
            style={{
              width: 200,
              height: 200,
              borderRadius: "50%",
              background: info.glow,
              border: `8px solid ${info.color}`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: 110,
              fontWeight: 900,
              color: info.color,
              lineHeight: 1,
              margin: "0 auto 24px",
            }}
          >
            {grade}
          </div>
          <h1 style={{ fontSize: 28, fontWeight: 800, color: "#f8fafc", margin: "0 0 8px", wordBreak: "break-all" }}>
            {decoded}
          </h1>
          <p style={{ fontSize: 18, color: info.color, fontWeight: 700, margin: "0 0 16px" }}>
            {info.label}
          </p>
          <p style={{ fontSize: 15, color: "#94a3b8", lineHeight: 1.6, maxWidth: 480, margin: "0 auto 24px" }}>
            {info.description}
          </p>

          <ShareScanButton
            domain={decoded}
            level={grade === "A" || grade === "B" ? "safe" : grade === "F" ? "dangerous" : "caution"}
            score={grade}
            url={canonical}
          />
        </div>

        {/* "Get your own grade" install CTA */}
        <div
          style={{
            background: "#1e293b",
            borderRadius: 16,
            padding: "28px 24px",
            textAlign: "center",
            border: "1px solid #334155",
          }}
        >
          <h2 style={{ fontSize: 20, fontWeight: 700, color: "#f8fafc", margin: "0 0 8px" }}>
            Want to grade any site?
          </h2>
          <p style={{ fontSize: 14, color: "#94a3b8", margin: "0 0 20px", lineHeight: 1.6 }}>
            Install Cleanway to run Privacy Audit on any page. The grade is computed entirely on your device — your browsing data never reaches our servers.
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
            Add to Chrome — Free
          </a>
        </div>

        {/* Grade scale legend */}
        <div style={{ marginTop: 32, padding: "20px", background: "#1e293b80", borderRadius: 12, border: "1px solid #1e293b" }}>
          <div style={{ fontSize: 12, color: "#64748b", textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 12 }}>
            How grades work
          </div>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            {VALID_LETTERS.map((g) => {
              const i = GRADE_INFO[g];
              return (
                <div
                  key={g}
                  style={{
                    flex: "1 1 100px",
                    minWidth: 100,
                    padding: "10px 8px",
                    borderRadius: 8,
                    background: g === grade ? `${i.color}20` : "#0f172a",
                    border: `1px solid ${g === grade ? i.color : "#334155"}`,
                    textAlign: "center",
                  }}
                >
                  <div style={{ fontSize: 22, fontWeight: 800, color: i.color, lineHeight: 1 }}>{g}</div>
                  <div style={{ fontSize: 10, color: "#94a3b8", marginTop: 4 }}>{i.label}</div>
                </div>
              );
            })}
          </div>
        </div>

        <p style={{ textAlign: "center", fontSize: 12, color: "#475569", marginTop: 32 }}>
          Privacy Audit runs 100% on your device. We see only the domain name you scanned, never the page content.{" "}
          <a href="/privacy-policy" style={{ color: "#60a5fa" }}>Privacy Policy</a>
        </p>

        <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />
      </div>
    </div>
  );
}
