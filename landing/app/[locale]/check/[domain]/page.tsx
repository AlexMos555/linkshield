import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";

import { InstallButtons } from "@/components/InstallButtons";
import { PrimaryInstallLink } from "@/components/PrimaryInstallLink";
import ShareScanButton from "@/components/ShareScanButton";
import { routing, type Locale } from "@/i18n/routing";
import { localePath } from "@/lib/locale-path";
import { reasonLabelKey } from "@/lib/reason-label";

const SITE_URL = "https://cleanway.ai";

type Props = { params: Promise<{ domain: string; locale: string }> };

type Level = "safe" | "caution" | "dangerous";

type ScanResult = {
  level?: Level;
  score?: number;
  verdict?: string;
  signals?: string[];
  // Machine-readable code per signal, positionally aligned with `signals`.
  reason_codes?: string[];
  confidence?: string;
  // Strategy doc #12 — numeric confidence band 50..99.
  confidence_pct?: number;
};

const LEVELS: readonly Level[] = ["safe", "caution", "dangerous"];

const LEVEL_COLORS: Record<Level, string> = {
  safe: "#22c55e",
  caution: "#f59e0b",
  dangerous: "#ef4444",
};

const LEVEL_ICONS: Record<Level, string> = {
  safe: "✅",
  caution: "⚠️",
  dangerous: "❌",
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

function resolveLocale(locale: string): Locale {
  return (routing.locales as readonly string[]).includes(locale) ? (locale as Locale) : routing.defaultLocale;
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { domain, locale } = await params;
  const decoded = decodeURIComponent(domain);
  const safeLocale = resolveLocale(locale);
  const t = await getTranslations({ locale: safeLocale, namespace: "Check" });

  const canonical = urlFor(safeLocale, domain);

  // hreflang map — every locale plus an x-default pointing at English
  const languages: Record<string, string> = {};
  for (const loc of routing.locales) {
    languages[loc] = urlFor(loc as Locale, domain);
  }
  languages["x-default"] = urlFor(routing.defaultLocale as Locale, domain);

  const title = t("meta_title", { domain: decoded });
  const description = t("meta_description", { domain: decoded });
  const ogTitle = t("heading", { domain: decoded });
  const ogDescription = t("og_description", { domain: decoded });

  return {
    title,
    description,
    metadataBase: new URL(SITE_URL),
    alternates: {
      canonical,
      languages,
    },
    openGraph: {
      title: ogTitle,
      description: ogDescription,
      url: canonical,
      siteName: "Cleanway",
      type: "article",
      // OG image is generated automatically from sibling opengraph-image.tsx
    },
    twitter: {
      card: "summary_large_image",
      title: ogTitle,
      description: ogDescription,
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

function isLevel(value: unknown): value is Level {
  return typeof value === "string" && (LEVELS as readonly string[]).includes(value);
}

/**
 * Plain-language reason labels in the page's language. The API sends an
 * English `detail` per reason plus a code; a known code gets the app's label,
 * anything else keeps the API's wording rather than disappearing.
 */
function reasonLabels(result: ScanResult, label: (key: string) => string): string[] {
  const signals = result.signals ?? [];
  return signals.map((detail, i) => {
    const key = reasonLabelKey(result.reason_codes?.[i]);
    return key ? label(key) : detail;
  });
}

export default async function CheckPage({ params }: Props) {
  const { domain, locale } = await params;
  const decodedDomain = decodeURIComponent(domain);
  const safeLocale = resolveLocale(locale);
  const t = await getTranslations({ locale: safeLocale, namespace: "Check" });
  // Android-only labels for the primary install CTA (see PrimaryInstallLink).
  const nav = await getTranslations({ locale: safeLocale, namespace: "Nav" });
  const hero = await getTranslations({ locale: safeLocale, namespace: "Hero" });
  const reasons = await getTranslations({ locale: safeLocale, namespace: "Reasons" });
  const result = await fetchScan(decodedDomain);

  // No verdict (API down, timed out, rate-limited): say so. Showing a yellow
  // "Caution — Score ?/100" for a check that never ran is a verdict we never made.
  const level: Level | null = isLevel(result.level) ? result.level : null;
  const score = typeof result.score === "number" ? result.score : null;
  const color = level ? LEVEL_COLORS[level] : "#64748b";
  const canonical = urlFor(safeLocale, domain);
  const signals = level ? reasonLabels(result, (key) => reasons(key)) : [];
  const href = (path: string) => localePath(safeLocale, path);

  // ── JSON-LD: rich structured data ──────────────────────────────
  // Only when there is a verdict: a Review with no rating would be invented.
  const jsonLd = level
    ? {
        "@context": "https://schema.org",
        "@graph": [
          {
            "@type": "WebPage",
            "@id": `${canonical}#webpage`,
            url: canonical,
            name: t("heading", { domain: decodedDomain }),
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
              name: decodedDomain,
              url: `https://${decodedDomain}`,
            },
            reviewBody: t(`verdict_${level}`, { domain: decodedDomain }),
            // Our score is a risk score (0 = no risk); the rating is its inverse.
            ...(score !== null && {
              reviewRating: {
                "@type": "Rating",
                ratingValue: 100 - score,
                bestRating: 100,
                worstRating: 0,
              },
            }),
          },
        ],
      }
    : null;

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
          <a href={href("/")} style={{ color: "#f8fafc", textDecoration: "none", fontWeight: 800, fontSize: 20 }}>
            Cleanway
          </a>
          <PrimaryInstallLink
            androidLabel={nav("install_android")}
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
            {nav("install")}
          </PrimaryInstallLink>
        </div>
      </nav>

      <div style={{ maxWidth: 800, margin: "0 auto", padding: "48px 24px" }}>
        {/* Main Result Card */}
        <div
          data-testid="check-result"
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
                flexShrink: 0,
              }}
            >
              {level ? LEVEL_ICONS[level] : "…"}
            </div>
            <div style={{ minWidth: 0 }}>
              <h1 style={{ fontSize: 28, fontWeight: 800, color: "#f8fafc", margin: 0, overflowWrap: "anywhere" }}>
                {t("heading", { domain: decodedDomain })}
              </h1>
              {level && (
                <p style={{ fontSize: 18, color, fontWeight: 600, margin: "4px 0 0" }}>
                  {t(`level_${level}`)}
                  {score !== null && <> &mdash; {t("risk_score", { score })}</>}
                </p>
              )}
              {/* Strategy doc #12: numeric confidence band chip. The
                  number is sourced from the API's calculate_confidence_pct
                  output, which blends data coverage × signal margin. */}
              {level && typeof result.confidence_pct === "number" && (
                <p
                  style={{ fontSize: 13, color: "#94a3b8", margin: "4px 0 0", fontWeight: 500 }}
                  title={t("confidence_hint")}
                >
                  {t("confidence", { pct: result.confidence_pct })} &middot;{" "}
                  <a href={href("/transparency/methodology")} style={{ color: "#60a5fa", textDecoration: "underline" }}>
                    {t("how_we_measure")}
                  </a>
                </p>
              )}
            </div>
          </div>

          <p style={{ fontSize: 16, color: "#94a3b8", lineHeight: 1.6, marginBottom: 20 }}>
            {level ? t(`verdict_${level}`, { domain: decodedDomain }) : t("check_failed", { domain: decodedDomain })}
          </p>

          {signals.length > 0 && (
            <div style={{ marginBottom: 20 }}>
              <h2 style={{ fontSize: 14, color: "#64748b", textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 8 }}>
                {t("signals_heading")}
              </h2>
              {signals.map((s, i) => (
                <div key={i} style={{ display: "flex", gap: 8, padding: "6px 0", fontSize: 14, color: "#94a3b8" }}>
                  <span style={{ color }}>&#x2022;</span>
                  <span>{s}</span>
                </div>
              ))}
            </div>
          )}

          {level && result.confidence === "low" && (
            <p style={{ fontSize: 13, color: "#f59e0b", fontStyle: "italic", marginBottom: 20 }}>
              {t("low_confidence")}
            </p>
          )}

          {level && (
            <ShareScanButton
              domain={decodedDomain}
              verdict={t(`level_${level}`)}
              score={score ?? "?"}
              url={canonical}
            />
          )}
        </div>

        {/* CTA */}
        <div style={{ background: "#1e293b", borderRadius: 16, padding: 24, textAlign: "center" }}>
          <h2 style={{ fontSize: 22, fontWeight: 700, color: "#f8fafc", marginBottom: 8 }}>{t("cta_title")}</h2>
          <p style={{ fontSize: 14, color: "#94a3b8", marginBottom: 16 }}>{t("cta_body")}</p>
          <PrimaryInstallLink
            androidLabel={hero("cta_android")}
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
            {hero("cta_primary")}
          </PrimaryInstallLink>
          <div style={{ marginTop: 20 }}>
            <InstallButtons platforms={["android", "ios"]} size="sm" />
          </div>
          <div style={{ marginTop: 12 }}>
            <InstallButtons platforms={["chrome", "firefox", "edge", "safari"]} size="sm" />
          </div>
        </div>

        {/* SEO: Structured Data */}
        {jsonLd && <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />}

        {/* Check Another */}
        <div style={{ marginTop: 32, textAlign: "center" }}>
          <p style={{ color: "#64748b", fontSize: 14, marginBottom: 12 }}>{t("another")}</p>
          <form action={href("/check")} method="get" style={{ display: "flex", gap: 8, maxWidth: 400, margin: "0 auto" }}>
            {/* aria-label provides an accessible name for the input.
                Placeholder text alone disappears on focus + isn't read
                by some screen readers. (Audit landing-a11y MEDIUM
                "Domain search form in check/[domain]/page.tsx has no
                accessible label — placeholder only".) */}
            <input
              name="q"
              placeholder={t("input_placeholder")}
              aria-label={t("input_label")}
              style={{
                flex: 1,
                minWidth: 0,
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
              {t("submit")}
            </button>
          </form>
        </div>

        <p style={{ textAlign: "center", fontSize: 12, color: "#475569", marginTop: 32 }}>
          {t("footer_note")}{" "}
          <a href={href("/transparency/methodology")} style={{ color: "#60a5fa" }}>
            {t("how_we_measure")}
          </a>{" "}&middot;{" "}
          <a href={href("/privacy-policy")} style={{ color: "#60a5fa" }}>
            {t("privacy_link")}
          </a>
        </p>
      </div>
    </div>
  );
}
