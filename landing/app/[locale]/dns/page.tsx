/**
 * One-tap DNS install — Strategy doc Top-20 #6.
 *
 * Server-rendered landing for the "Cleanway DNS without the app"
 * flow. The same page works for iOS (one-tap .mobileconfig
 * download), macOS Big Sur+ (same .mobileconfig as iOS), and Windows
 * through the browser's own Secure DNS (Chrome, Edge, Firefox). Android is
 * sent to the app: its Private DNS needs DNS-over-TLS on port 853, which
 * dns.cleanway.ai does not serve, and a strict Private DNS host that never
 * answers takes the whole phone offline.
 *
 * Not Windows' system-wide DoH: it pairs a server IP with the template, and
 * dns.cleanway.ai is a CNAME to Railway with no stable IP of its own. The old
 * steps paired 1.1.1.1 with our template, so Windows sent our DoH request to
 * Cloudflare, which answers 403 — no DNS, or a silent fallback to unfiltered
 * 1.1.1.1. System-wide Windows DoH waits for a fixed resolver IP.
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
import { localePath } from "@/lib/locale-path";
import { DEFAULT_OG_IMAGE } from "@/lib/seo";

const SITE_URL = "https://cleanway.ai";
const DEFAULT_API_URL = "https://api.cleanway.ai";
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
      images: [DEFAULT_OG_IMAGE],
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
  const androidUrl = localePath(safeLocale, "/android");

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
        <p style={{ color: "#8796ab", fontSize: 13, marginTop: 16 }}>
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
        <p style={{ fontSize: 13, color: "#8796ab", marginTop: 12 }}>
          {t("ios_unsigned_note")}
        </p>
      </section>

      {/* Android — the app, never Private DNS (no DoT on :853 yet) */}
      <section style={_sectionStyle("#22c55e")}>
        <h2 style={_h2Style}>🤖 Android</h2>
        <p style={{ marginBottom: 16 }}>{t("android_app_intro")}</p>
        <a
          href={androidUrl}
          style={{
            display: "inline-block",
            background: "#22c55e",
            color: "#052e16",
            padding: "12px 22px",
            borderRadius: 10,
            fontWeight: 600,
            fontSize: 15,
            textDecoration: "none",
          }}
        >
          {t("android_app_cta")}
        </a>
        <div style={_undoStyle}>
          <p style={{ color: "#fbbf24", fontWeight: 600, marginBottom: 6 }}>
            {t("android_undo_title")}
          </p>
          <p style={{ fontSize: 14 }}>{t("android_undo_body")}</p>
        </div>
      </section>

      {/* Windows — the browser's Secure DNS (the header says why not
          Windows' own DoH setting), plus the way back for anyone who
          followed the old network-settings steps. */}
      <section style={_sectionStyle("#a855f7")} data-testid="dns-windows">
        <h2 style={_h2Style}>🪟 {t("win_heading")}</h2>
        <p style={{ marginBottom: 12 }}>{t("win_intro")}</p>
        <ul style={{ paddingInlineStart: 22, marginBottom: 16 }}>
          <li style={{ marginBottom: 6 }}>{t("win_chrome")}</li>
          <li style={{ marginBottom: 6 }}>{t("win_edge")}</li>
          <li style={{ marginBottom: 6 }}>{t("win_firefox")}</li>
        </ul>
        <p>
          {t("win_address")} <code style={_codeStyle}>{DOH_URL}</code>
        </p>
        <div style={_undoStyle}>
          <p style={{ color: "#fbbf24", fontWeight: 600, marginBottom: 6 }}>
            {t("win_undo_title")}
          </p>
          <p style={{ fontSize: 14 }}>{t("win_undo_body")}</p>
        </div>
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

      {/* Where DNS fits — honest layering. Sets accurate expectations (wide
          but shallow) and differentiates from generic DNS filters. The deeper
          layer that ships today is the Android app; the browser extension is
          named as coming soon (lib/install-urls.ts: no listing is live), so
          the link goes to /android, not to install pills that all say
          "Coming soon". */}
      <section
        style={{
          marginBottom: 40,
          background: "rgba(30, 41, 59, 0.5)",
          border: "1px solid #334155",
          borderRadius: 14,
          padding: "22px 24px",
        }}
      >
        <h2 style={{ color: "#f8fafc", fontSize: 22, marginBottom: 14 }}>
          {t("layer_heading")}
        </h2>
        <p style={{ marginBottom: 10 }}>{t("layer_body")}</p>
        <p style={{ marginBottom: 10 }}>{t("layer_extension")}</p>
        <p style={{ marginBottom: 10 }}>
          <a href={androidUrl} style={{ color: "#60a5fa", fontWeight: 600 }}>
            {t("layer_app_cta")}
          </a>
        </p>
        <p style={{ color: "#94a3b8", fontSize: 14 }}>{t("layer_generic")}</p>
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
          <a href={localePath(safeLocale, "/transparency")} style={{ color: "#60a5fa", textDecoration: "underline" }}>
            {t("transparency_link")}
          </a>
          .
        </p>
      </section>

      <p style={{ textAlign: "center", fontSize: 12, color: "#8796ab", marginTop: 32 }}>
        <a href={localePath(safeLocale, "/privacy-policy")} style={{ color: "#60a5fa", textDecoration: "underline" }}>
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

const _undoStyle: React.CSSProperties = {
  marginTop: 20,
  padding: "12px 16px",
  borderRadius: 10,
  border: "1px solid #f59e0b",
  background: "rgba(245, 158, 11, 0.08)",
};

const _codeStyle: React.CSSProperties = {
  background: "#0f172a",
  color: "#e2e8f0",
  padding: "4px 10px",
  borderRadius: 6,
  fontFamily: "ui-monospace, SF Mono, Menlo, monospace",
  fontSize: 14,
  display: "inline-block",
};
