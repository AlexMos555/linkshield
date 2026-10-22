import type { Metadata } from "next";
import { notFound, redirect } from "next/navigation";
import { getTranslations } from "next-intl/server";

import { InstallButtons } from "@/components/InstallButtons";
import { PrimaryInstallLink } from "@/components/PrimaryInstallLink";
import { routing, type Locale } from "@/i18n/routing";
import { hostFromSegment } from "@/lib/check-host";
import { displayHost } from "@/lib/display-host";
import { safeJsonLd } from "@/lib/json-ld";
import { localePath } from "@/lib/locale-path";

const SITE_URL = "https://cleanway.ai";

type Props = { params: Promise<{ domain: string; locale: string }> };

function pathFor(locale: Locale, domain: string): string {
  const slug = `audit/${domain}`;
  return locale === routing.defaultLocale ? `/${slug}` : `/${locale}/${slug}`;
}

function urlFor(locale: Locale, domain: string): string {
  return `${SITE_URL}${pathFor(locale, domain)}`;
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { domain, locale } = await params;
  // Not a site name: the page redirects or 404s; keep it out of the index.
  const host = hostFromSegment(domain);
  if (!host) return { robots: { index: false, follow: false } };
  const decoded = displayHost(host);
  const isLocaleKnown = (routing.locales as readonly string[]).includes(locale);
  const safeLocale: Locale = isLocaleKnown ? (locale as Locale) : routing.defaultLocale;

  const canonical = urlFor(safeLocale, host);
  const languages: Record<string, string> = {};
  for (const loc of routing.locales) languages[loc] = urlFor(loc as Locale, host);
  languages["x-default"] = urlFor(routing.defaultLocale as Locale, host);

  const t = await getTranslations({ locale: safeLocale, namespace: "Audit" });
  const title = t("meta_title", { domain: decoded });
  const description = t("meta_description", { domain: decoded });
  const ogTitle = t("og_title", { domain: decoded });
  const ogDescription = t("og_description", { domain: decoded });

  return {
    title,
    description,
    metadataBase: new URL(SITE_URL),
    alternates: { canonical, languages },
    openGraph: {
      title: ogTitle,
      description: ogDescription,
      url: canonical,
      siteName: "Cleanway",
      type: "article",
      locale: safeLocale,
    },
    twitter: {
      card: "summary_large_image",
      title: ogTitle,
      description: ogDescription,
      site: "@cleanwayai",
    },
    // Never indexed: the page is a teaser (no grade until the extension
    // ships) with the same text for every site — thousands of thin,
    // near-duplicate pages. Links on it are still followed.
    robots: { index: false, follow: true },
  };
}

export default async function AuditPage({ params }: Props) {
  const { domain, locale } = await params;
  const isLocaleKnown = (routing.locales as readonly string[]).includes(locale);
  const safeLocale: Locale = isLocaleKnown ? (locale as Locale) : routing.defaultLocale;
  // The segment is URL text: only a site name gets a page (same parser as
  // /check). Anything else used to be echoed into the JSON-LD and the HTML.
  const host = hostFromSegment(domain);
  if (!host) notFound();
  if (host !== domain) redirect(pathFor(safeLocale, host));
  const d = displayHost(host);
  const canonical = urlFor(safeLocale, host);
  // Android-only label for the primary install CTA (see PrimaryInstallLink).
  const nav = await getTranslations({ locale: safeLocale, namespace: "Nav" });
  const hero = await getTranslations({ locale: safeLocale, namespace: "Hero" });
  const t = await getTranslations({ locale: safeLocale, namespace: "Audit" });

  // JSON-LD: WebPage describing the audit + the Cleanway WebSite
  const jsonLd = {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "WebPage",
        "@id": `${canonical}#webpage`,
        url: canonical,
        name: t("meta_title", { domain: d }),
        description: t("og_description", { domain: d }),
        inLanguage: safeLocale,
        isPartOf: { "@id": `${SITE_URL}#website` },
      },
      {
        "@type": "WebSite",
        "@id": `${SITE_URL}#website`,
        url: SITE_URL,
        name: "Cleanway",
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
          <a href={localePath(safeLocale, "/")} style={{ color: "#f8fafc", textDecoration: "none", fontWeight: 800, fontSize: 20 }}>
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

      <main style={{ maxWidth: 600, margin: "0 auto", padding: "48px 24px", textAlign: "center" }}>
        <h1 style={{ fontSize: 28, fontWeight: 800, color: "#f8fafc", marginBottom: 8, wordBreak: "break-word" }}>
          {t("heading", { domain: d })}
        </h1>
        {/* The audit lives in the browser extension, and no extension is
            published yet (lib/install-urls.ts): say so, instead of "install
            Cleanway to see the full report" next to a button that leads to
            the DNS page or the Android app, neither of which has it. */}
        <p style={{ color: "#94a3b8", marginBottom: 32 }}>{t("intro")}</p>

        {/* Teaser Card */}
        <div style={{ background: "#1e293b", borderRadius: 16, padding: 32, marginBottom: 24, border: "1px solid #334155" }}>
          <div aria-hidden="true" style={{ fontSize: 64, fontWeight: 800, color: "#8796ab", marginBottom: 8 }}>?</div>
          <p style={{ fontSize: 18, color: "#f8fafc", fontWeight: 600, marginBottom: 4 }}>{t("grade_hidden")}</p>
          <p style={{ fontSize: 14, color: "#94a3b8" }}>{t("teaser_body", { domain: d })}</p>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginTop: 20 }}>
            {[
              { label: t("label_trackers"), value: "?" },
              { label: t("label_cookies"), value: "?" },
              { label: t("label_fields"), value: "?" },
              { label: t("label_fingerprinting"), value: "?" },
            ].map((item, i) => (
              <div key={i} style={{ background: "#111827", borderRadius: 10, padding: 12, textAlign: "center" }}>
                <div style={{ fontSize: 24, fontWeight: 800, color: "#8796ab" }}>{item.value}</div>
                <div style={{ fontSize: 11, color: "#8796ab" }}>{item.label}</div>
              </div>
            ))}
          </div>
        </div>

        <PrimaryInstallLink
          androidLabel={hero("cta_android")}
          style={{
            display: "inline-block",
            background: "#22c55e",
            color: "#052e16",
            padding: "14px 32px",
            borderRadius: 10,
            fontWeight: 700,
            fontSize: 16,
            textDecoration: "none",
          }}
        >
          {hero("cta_primary")}
        </PrimaryInstallLink>

        <div style={{ marginTop: 24 }}>
          <InstallButtons platforms={["chrome", "firefox", "edge", "safari"]} size="sm" />
        </div>
        <div style={{ marginTop: 12 }}>
          <InstallButtons platforms={["ios", "android"]} size="sm" />
        </div>

        <p style={{ fontSize: 12, color: "#8796ab", marginTop: 20 }}>{t("on_device_note")}</p>

        <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: safeJsonLd(jsonLd) }} />
      </main>
    </div>
  );
}
