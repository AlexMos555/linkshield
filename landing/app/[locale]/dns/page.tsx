/**
 * One-tap DNS install — Strategy doc Top-20 #6.
 *
 * Server-rendered landing for the "Cleanway DNS without the app"
 * flow. The same page works for iOS (one-tap .mobileconfig
 * download), Android (paste hostname into Private DNS),
 * macOS Big Sur+ (same .mobileconfig as iOS), and Windows 11
 * (DoH server URL in Settings → Network).
 *
 * The page deliberately does NOT use platform detection on the
 * server — Cloudflare Workers and CDNs cache the page across
 * platforms. Instead we render ALL the install paths and let
 * progressive enhancement on the client hide the irrelevant
 * ones. Defensive default: if JS is off, every flow is visible.
 */
import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { routing, type Locale } from "@/i18n/routing";

const SITE_URL = "https://cleanway.ai";
const DEFAULT_API_URL = "https://api.cleanway.ai";
const DNS_HOST = "dns.cleanway.ai";
const DOH_URL = "https://dns.cleanway.ai/dns-query";

function urlFor(locale: Locale | string): string {
  return locale === routing.defaultLocale
    ? `${SITE_URL}/dns`
    : `${SITE_URL}/${locale}/dns`;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const { locale } = await params;
  const isLocaleKnown = (routing.locales as readonly string[]).includes(locale);
  const safeLocale: Locale = isLocaleKnown
    ? (locale as Locale)
    : routing.defaultLocale;
  const t = await getTranslations({ locale: safeLocale, namespace: "Dns" });

  const canonical = urlFor(safeLocale);
  const languages: Record<string, string> = {};
  for (const loc of routing.locales) languages[loc] = urlFor(loc as Locale);
  languages["x-default"] = urlFor(routing.defaultLocale);

  return {
    title: `${t("page_title")} — Cleanway`,
    description: t("page_description"),
    metadataBase: new URL(SITE_URL),
    alternates: { canonical, languages },
    openGraph: {
      title: t("page_title"),
      description: t("page_description"),
      url: canonical,
      siteName: "Cleanway",
      type: "article",
      locale: safeLocale,
    },
    robots: { index: true, follow: true },
  };
}

export default async function DnsPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale } = await params;
  const isLocaleKnown = (routing.locales as readonly string[]).includes(locale);
  const safeLocale: Locale = isLocaleKnown
    ? (locale as Locale)
    : routing.defaultLocale;
  const t = await getTranslations({ locale: safeLocale, namespace: "Dns" });

  const apiBase = process.env.NEXT_PUBLIC_API_URL || DEFAULT_API_URL;
  const mobileconfigUrl = `${apiBase}/api/v1/mobileconfig?locale=${safeLocale}`;

  return (
    <main
      style={{
        maxWidth: 880,
        margin: "40px auto",
        padding: "0 24px",
        color: "#cbd5e1",
        lineHeight: 1.6,
        fontFamily: '-apple-system, system-ui, sans-serif',
      }}
    >
      <header style={{ marginBottom: 40 }}>
        <h1 style={{ color: "#f8fafc", fontSize: 38, marginBottom: 12 }}>
          {t("hero_title")}
        </h1>
        <p style={{ color: "#94a3b8", fontSize: 17 }}>{t("hero_subtitle")}</p>
        <p style={{ color: "#64748b", fontSize: 13, marginTop: 16 }}>
          {t("hero_meta")}
        </p>
      </header>

      {/* iOS / iPadOS / macOS one-tap profile install */}
      <section style={_sectionStyle("#0ea5e9")}>
        <h2 style={_h2Style}>📱 iOS, iPadOS &amp; macOS</h2>
        <p style={{ marginBottom: 12 }}>{t("ios_intro")}</p>
        <ol style={{ paddingLeft: 22, marginBottom: 16 }}>
          <li>{t("ios_step1")}</li>
          <li>{t("ios_step2")}</li>
          <li>{t("ios_step3")}</li>
        </ol>
        <a
          href={mobileconfigUrl}
          download="cleanway-dns.mobileconfig"
          style={{
            display: "inline-block",
            background: "#0ea5e9",
            color: "#082f49",
            padding: "12px 24px",
            borderRadius: 10,
            fontWeight: 800,
            fontSize: 15,
            textDecoration: "none",
          }}
        >
          {t("ios_cta")}
        </a>
        <p style={{ fontSize: 13, color: "#64748b", marginTop: 12 }}>
          {t("ios_unsigned_note")}
        </p>
      </section>

      {/* Android Private DNS — copy & paste the hostname */}
      <section style={_sectionStyle("#22c55e")}>
        <h2 style={_h2Style}>🤖 Android (9.0+)</h2>
        <p style={{ marginBottom: 12 }}>{t("android_intro")}</p>
        <ol style={{ paddingLeft: 22, marginBottom: 16 }}>
          <li>{t("android_step1")}</li>
          <li>{t("android_step2")}</li>
          <li>
            {t("android_step3")}{" "}
            <code style={_codeStyle}>{DNS_HOST}</code>
          </li>
          <li>{t("android_step4")}</li>
        </ol>
        <div style={{ marginBottom: 12 }}>
          <code style={{ ..._codeStyle, padding: "10px 14px", fontSize: 16 }}>
            {DNS_HOST}
          </code>
        </div>
        <p style={{ fontSize: 13, color: "#64748b", marginTop: 12 }}>
          {t("android_compat_note")}
        </p>
      </section>

      {/* Windows 11 — DoH server in network settings */}
      <section style={_sectionStyle("#a855f7")}>
        <h2 style={_h2Style}>🪟 Windows 11</h2>
        <p style={{ marginBottom: 12 }}>{t("win_intro")}</p>
        <ol style={{ paddingLeft: 22, marginBottom: 16 }}>
          <li>{t("win_step1")}</li>
          <li>{t("win_step2")}</li>
          <li>
            {t("win_step3")} <code style={_codeStyle}>{DOH_URL}</code>
          </li>
        </ol>
      </section>

      {/* What this protects you from */}
      <section style={{ marginBottom: 40 }}>
        <h2 style={{ color: "#f8fafc", fontSize: 22, marginBottom: 14 }}>
          {t("benefits_heading")}
        </h2>
        <ul style={{ paddingLeft: 22 }}>
          <li style={{ marginBottom: 6 }}>{t("benefit_1")}</li>
          <li style={{ marginBottom: 6 }}>{t("benefit_2")}</li>
          <li style={{ marginBottom: 6 }}>{t("benefit_3")}</li>
          <li style={{ marginBottom: 6 }}>{t("benefit_4")}</li>
        </ul>
      </section>

      {/* Privacy — preempt the "are you logging?" question */}
      <section style={{ marginBottom: 40 }}>
        <h2 style={{ color: "#f8fafc", fontSize: 22, marginBottom: 14 }}>
          {t("privacy_heading")}
        </h2>
        <p style={{ marginBottom: 8 }}>{t("privacy_body")}</p>
        <p style={{ marginBottom: 8 }}>{t("privacy_logs")}</p>
        <p>
          {t("privacy_more")}{" "}
          <a href="/transparency" style={{ color: "#60a5fa" }}>
            {t("transparency_link")}
          </a>
          .
        </p>
      </section>

      <p style={{ textAlign: "center", fontSize: 12, color: "#475569", marginTop: 32 }}>
        <a href="/privacy-policy" style={{ color: "#60a5fa" }}>
          {t("privacy_policy_link")}
        </a>
      </p>
    </main>
  );
}

const _h2Style: React.CSSProperties = {
  color: "#f8fafc",
  fontSize: 22,
  marginBottom: 12,
};

function _sectionStyle(accent: string): React.CSSProperties {
  return {
    background: "#1e293b",
    padding: "24px",
    borderRadius: 12,
    border: `1px solid ${accent}33`,
    borderLeft: `4px solid ${accent}`,
    marginBottom: 24,
  };
}

const _codeStyle: React.CSSProperties = {
  background: "#0f172a",
  color: "#e2e8f0",
  padding: "4px 10px",
  borderRadius: 6,
  fontFamily: "ui-monospace, SF Mono, Menlo, monospace",
  fontSize: 14,
  display: "inline-block",
};
