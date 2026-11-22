import type { Metadata } from "next";
import { notFound, redirect } from "next/navigation";
import { getMessages, getTranslations } from "next-intl/server";

import CheckForm from "@/components/CheckForm";
import CheckResultCard from "@/components/CheckResultCard";
import { InstallButtons } from "@/components/InstallButtons";
import LiveCheckResult from "@/components/LiveCheckResult";
import { PrimaryInstallLink } from "@/components/PrimaryInstallLink";
import { routing, type Locale } from "@/i18n/routing";
import { checkCardProps, isLevel, restsOnGoogle, type AdvisoryStrings, type Level, type ScanResult } from "@/lib/check-card";
import { hostFromSegment } from "@/lib/check-host";
import { displayHost } from "@/lib/display-host";
import { localePath } from "@/lib/locale-path";
import { safeJsonLd } from "@/lib/json-ld";
import { isIndexedCheckHost } from "@/lib/seo-domains";

const SITE_URL = "https://cleanway.ai";

type Props = { params: Promise<{ domain: string; locale: string }> };

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

/**
 * Rendered on first request, then served from the CDN for an hour (the same
 * hour the API verdict is cached for in fetchScan). It used to render on every
 * request — `private, no-store`, a cold serverless start on the first visit
 * — for a page whose content changes at most hourly. No site is prebuilt.
 * A verdict resting on Google's lists never goes into this cached render: the
 * browser fetches it live (components/LiveCheckResult.tsx) — Web Risk allows
 * such a warning only while Google's answer is valid, and a page regenerated
 * in the background can be served at any age.
 */
export const revalidate = 3600;

export function generateStaticParams(): Array<{ domain: string }> {
  return [];
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { domain, locale } = await params;
  // Not a site name: the page redirects or 404s; keep it out of the index.
  const decoded = hostFromSegment(domain);
  if (!decoded) return { robots: { index: false, follow: false } };
  const safeLocale = resolveLocale(locale);
  const t = await getTranslations({ locale: safeLocale, namespace: "Check" });

  const canonical = urlFor(safeLocale, decoded);

  // hreflang map — every locale plus an x-default pointing at English
  const languages: Record<string, string> = {};
  for (const loc of routing.locales) {
    languages[loc] = urlFor(loc as Locale, decoded);
  }
  languages["x-default"] = urlFor(routing.defaultLocale as Locale, decoded);

  // /check/<anything> is an infinite URL space: only the curated sites are
  // search landing pages (lib/seo-domains.ts), and only while the check has a
  // verdict — "we couldn't check this right now" is not a page to rank. Same
  // fetch as the page body, so Next serves both from one request.
  const indexable = isIndexedCheckHost(decoded) && isLevel((await fetchScan(decoded)).level);

  const shown = displayHost(decoded);
  const title = t("meta_title", { domain: shown });
  const description = t("meta_description", { domain: shown });
  const ogTitle = t("heading", { domain: shown });
  const ogDescription = t("og_description", { domain: shown });

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
      locale: safeLocale,
      // OG image is generated automatically from sibling opengraph-image.tsx
    },
    twitter: {
      card: "summary_large_image",
      title: ogTitle,
      description: ogDescription,
      site: "@cleanwayai",
    },
    robots: indexable
      ? { index: true, follow: true, googleBot: { index: true, follow: true, "max-image-preview": "large" } }
      : { index: false, follow: true },
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

/** The Reasons namespace as plain strings, for the live check in the browser. */
async function reasonMessages(locale: Locale): Promise<Record<string, string>> {
  const all = (await getMessages({ locale })) as Record<string, unknown>;
  const reasons = all.Reasons;
  if (!reasons || typeof reasons !== "object") return {};
  return Object.fromEntries(Object.entries(reasons).filter((e): e is [string, string] => typeof e[1] === "string"));
}

/** The API as the visitor's browser reaches it (the live check). */
function browserApiBase(): string {
  return process.env.NEXT_PUBLIC_API_URL || "https://api.cleanway.ai";
}

export default async function CheckPage({ params }: Props) {
  const { domain, locale } = await params;
  const safeLocale = resolveLocale(locale);
  // Only a site name is ever looked up. A pasted link that reached this route
  // (/check/bank.ru%2Fconfirm%3Femail%3D...) is cut down to its host before
  // anything is fetched; something with no host in it is not a check.
  const decodedDomain = hostFromSegment(domain);
  if (!decodedDomain) notFound();
  if (decodedDomain !== domain) redirect(pathFor(safeLocale, decodedDomain));
  // What people read: президент.рф, not xn--d1abbgf6aiiy.xn--p1ai (lib/display-host.ts).
  const shownDomain = displayHost(decodedDomain);
  const t = await getTranslations({ locale: safeLocale, namespace: "Check" });
  // Android- and iPhone-only labels for the primary install CTA (see PrimaryInstallLink).
  const nav = await getTranslations({ locale: safeLocale, namespace: "Nav" });
  const hero = await getTranslations({ locale: safeLocale, namespace: "Hero" });
  const reasons = await getTranslations({ locale: safeLocale, namespace: "Reasons" });
  const advisory = await getTranslations({ locale: safeLocale, namespace: "Advisory" });
  const result = await fetchScan(decodedDomain);

  // No verdict (API down, timed out, rate-limited): the card says so
  // (lib/check-card.ts) — never a yellow "Caution — Score ?/100" for a check
  // that never ran. One of the reasons is Google's (Web Risk): the browser
  // checks live (LiveCheckResult), and nothing of this answer goes into the
  // cached page — not the card, not the JSON-LD.
  const google = restsOnGoogle(result);
  const level: Level | null = isLevel(result.level) ? result.level : null;
  const score = typeof result.score === "number" ? result.score : null;
  const canonical = urlFor(safeLocale, decodedDomain);
  const href = (path: string) => localePath(safeLocale, path);
  const methodologyHref = href("/transparency/methodology");
  const advisoryStrings: AdvisoryStrings = {
    google: advisory("google"),
    learn_more: advisory("learn_more"),
    learn_phishing: advisory("learn_phishing"),
    learn_malware: advisory("learn_malware"),
    learn_unwanted: advisory("learn_unwanted"),
  };
  // The live check's reason labels: only on a page that needs them.
  const liveReasons = google ? await reasonMessages(safeLocale) : {};

  // ── JSON-LD: rich structured data ──────────────────────────────
  // Only when there is a verdict: a Review with no rating would be invented —
  // and never a Google verdict, which must not outlive Google's answer.
  const jsonLd = level && !google
    ? {
        "@context": "https://schema.org",
        "@graph": [
          {
            "@type": "WebPage",
            "@id": `${canonical}#webpage`,
            url: canonical,
            name: t("heading", { domain: shownDomain }),
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
              name: shownDomain,
              url: `https://${decodedDomain}`,
            },
            reviewBody: t(`verdict_${level}`, { domain: shownDomain }),
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
            iosLabel={nav("install_ios")}
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

      <main style={{ maxWidth: 800, margin: "0 auto", padding: "48px 24px" }}>
        {/* Main Result Card */}
        {google ? (
          <LiveCheckResult
            domain={decodedDomain}
            shownDomain={shownDomain}
            canonical={canonical}
            methodologyHref={methodologyHref}
            apiBase={browserApiBase()}
            reasons={liveReasons}
            advisory={advisoryStrings}
          />
        ) : (
          <CheckResultCard
            {...checkCardProps({
              result,
              shownDomain,
              canonical,
              methodologyHref,
              t: (key, values) => t(key, values),
              reason: (key) => reasons(key),
              advisory: advisoryStrings,
            })}
          />
        )}

        {/* CTA */}
        <div style={{ background: "#1e293b", borderRadius: 16, padding: 24, textAlign: "center" }}>
          <h2 style={{ fontSize: 22, fontWeight: 700, color: "#f8fafc", marginBottom: 8 }}>{t("cta_title")}</h2>
          <p style={{ fontSize: 14, color: "#94a3b8", marginBottom: 16 }}>{t("cta_body")}</p>
          <PrimaryInstallLink
            androidLabel={hero("cta_android")}
            iosLabel={nav("install_ios")}
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
        {jsonLd && <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd(jsonLd) }} />}

        {/* Check Another */}
        <div style={{ marginTop: 32, textAlign: "center" }}>
          <p style={{ color: "#8796ab", fontSize: 14, marginBottom: 12 }}>{t("another")}</p>
          <CheckForm
            locale={safeLocale}
            placeholder={t("input_placeholder")}
            label={t("input_label")}
            submit={t("submit")}
            invalid={t("invalid_input")}
            variant="compact"
          />
        </div>

        <p style={{ textAlign: "center", fontSize: 12, color: "#8796ab", marginTop: 32 }}>
          {t("footer_note")}{" "}
          <a href={methodologyHref} style={{ color: "#60a5fa", textDecoration: "underline" }}>
            {t("how_we_measure")}
          </a>{" "}&middot;{" "}
          <a href={href("/privacy-policy")} style={{ color: "#60a5fa", textDecoration: "underline" }}>
            {t("privacy_link")}
          </a>
        </p>
      </main>
    </div>
  );
}
