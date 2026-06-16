/**
 * Public transparency report — Strategy doc Top-20 #16.
 *
 * Server-rendered so the published numbers ship in HTML for SEO
 * (and so Google's snippet pulls our FP rate, not a competitor's
 * unsourced "industry-low" claim). Data comes from the backend
 * /api/v1/transparency/latest endpoint, which is itself sourced
 * from a JSON file in docs/transparency/ — checked into git so
 * the audit trail is permanent.
 *
 * The page is intentionally boring. The point isn't beautiful
 * design — it's that the numbers are PUBLISHED at all. Every
 * competitor publishes glossy threat reports without their FP
 * rate. We publish ours.
 */
import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { routing, type Locale } from "@/i18n/routing";

const SITE_URL = "https://cleanway.ai";
const DEFAULT_API_URL = "https://api.cleanway.ai";

type Report = {
  id: string;
  period: string;
  published_at: string;
  checks: { total: number; free_tier: number; paid_tier: number };
  verdicts: { safe_count: number; caution_count: number; dangerous_count: number };
  false_positive_rate: { value: number; denominator: number; note: string };
  latency_ms: { p50: number; p95: number; p99: number };
  intel_sources_active: string[];
  top_blocked_categories: { category: string; share: number }[];
  incidents: { date: string; summary: string }[];
  data_requests_received: { government: number; court_orders: number; note: string };
  methodology_url?: string;
};

function urlFor(locale: Locale | string): string {
  return locale === routing.defaultLocale
    ? `${SITE_URL}/transparency`
    : `${SITE_URL}/${locale}/transparency`;
}

async function fetchReport(): Promise<Report | null> {
  const base = process.env.NEXT_PUBLIC_API_URL || DEFAULT_API_URL;
  try {
    const resp = await fetch(`${base}/api/v1/transparency/latest`, {
      // Reports update once a quarter — daily revalidation is fine.
      next: { revalidate: 60 * 60 * 24 },
    });
    if (!resp.ok) return null;
    return (await resp.json()) as Report;
  } catch {
    return null;
  }
}

function fmt(n: number, locale: string): string {
  return new Intl.NumberFormat(locale).format(n);
}

function pct(value: number, locale: string, digits: number = 4): string {
  return new Intl.NumberFormat(locale, {
    style: "percent",
    maximumFractionDigits: digits,
  }).format(value);
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const { locale } = await params;
  const isLocaleKnown = (routing.locales as readonly string[]).includes(locale);
  const safeLocale: Locale = isLocaleKnown ? (locale as Locale) : routing.defaultLocale;
  const t = await getTranslations({ locale: safeLocale, namespace: "Transparency" });

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
    robots: {
      index: true,
      follow: true,
    },
  };
}

export default async function TransparencyPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale } = await params;
  const isLocaleKnown = (routing.locales as readonly string[]).includes(locale);
  const safeLocale: Locale = isLocaleKnown ? (locale as Locale) : routing.defaultLocale;
  const t = await getTranslations({ locale: safeLocale, namespace: "Transparency" });
  const report = await fetchReport();

  if (!report) {
    return (
      <main style={{ maxWidth: 720, margin: "40px auto", padding: "0 24px", color: "#cbd5e1" }}>
        <h1 style={{ color: "#f8fafc" }}>{t("page_title")}</h1>
        <p>{t("error_unavailable")}</p>
      </main>
    );
  }

  return (
    <main style={{ maxWidth: 880, margin: "40px auto", padding: "0 24px", color: "#cbd5e1", lineHeight: 1.6 }}>
      <header style={{ marginBottom: 32 }}>
        <h1 style={{ color: "#f8fafc", fontSize: 36, marginBottom: 8 }}>
          {t("page_title")}
        </h1>
        <p style={{ color: "#94a3b8", fontSize: 16 }}>
          {t("hero_subtitle", { period: report.period })}
        </p>
        <p style={{ color: "#64748b", fontSize: 13 }}>
          {t("published_at", { date: report.published_at })}
        </p>
      </header>

      <section style={{ marginBottom: 40 }}>
        <h2 style={{ color: "#f8fafc", fontSize: 22, marginBottom: 16 }}>
          {t("section_volume")}
        </h2>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 16 }}>
          <div style={{ background: "#1e293b", padding: 16, borderRadius: 8 }}>
            <div style={{ color: "#94a3b8", fontSize: 13 }}>{t("metric_total_checks")}</div>
            <div style={{ color: "#f8fafc", fontSize: 26, fontWeight: 600 }}>
              {fmt(report.checks.total, safeLocale)}
            </div>
          </div>
          <div style={{ background: "#1e293b", padding: 16, borderRadius: 8 }}>
            <div style={{ color: "#94a3b8", fontSize: 13 }}>{t("metric_dangerous")}</div>
            <div style={{ color: "#f8fafc", fontSize: 26, fontWeight: 600 }}>
              {fmt(report.verdicts.dangerous_count, safeLocale)}
            </div>
          </div>
          <div style={{ background: "#1e293b", padding: 16, borderRadius: 8 }}>
            <div style={{ color: "#94a3b8", fontSize: 13 }}>{t("metric_fp_rate")}</div>
            <div style={{ color: "#86efac", fontSize: 26, fontWeight: 600 }}>
              {pct(report.false_positive_rate.value, safeLocale)}
            </div>
          </div>
        </div>
        <p style={{ color: "#64748b", fontSize: 13, marginTop: 12 }}>
          {report.false_positive_rate.note}
        </p>
      </section>

      <section style={{ marginBottom: 40 }}>
        <h2 style={{ color: "#f8fafc", fontSize: 22, marginBottom: 16 }}>
          {t("section_latency")}
        </h2>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <tbody>
            <tr style={{ borderBottom: "1px solid #334155" }}>
              <td style={{ padding: "8px 0", color: "#94a3b8" }}>p50</td>
              <td style={{ padding: "8px 0", textAlign: "right", color: "#f8fafc" }}>{report.latency_ms.p50} ms</td>
            </tr>
            <tr style={{ borderBottom: "1px solid #334155" }}>
              <td style={{ padding: "8px 0", color: "#94a3b8" }}>p95</td>
              <td style={{ padding: "8px 0", textAlign: "right", color: "#f8fafc" }}>{report.latency_ms.p95} ms</td>
            </tr>
            <tr>
              <td style={{ padding: "8px 0", color: "#94a3b8" }}>p99</td>
              <td style={{ padding: "8px 0", textAlign: "right", color: "#f8fafc" }}>{report.latency_ms.p99} ms</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section style={{ marginBottom: 40 }}>
        <h2 style={{ color: "#f8fafc", fontSize: 22, marginBottom: 16 }}>
          {t("section_sources")}
        </h2>
        <ul style={{ listStyle: "disc", paddingLeft: 24 }}>
          {report.intel_sources_active.map((src) => (
            <li key={src} style={{ marginBottom: 4 }}>{src}</li>
          ))}
        </ul>
      </section>

      <section style={{ marginBottom: 40 }}>
        <h2 style={{ color: "#f8fafc", fontSize: 22, marginBottom: 16 }}>
          {t("section_categories")}
        </h2>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <tbody>
            {report.top_blocked_categories.map((c) => (
              <tr key={c.category} style={{ borderBottom: "1px solid #334155" }}>
                <td style={{ padding: "8px 0", color: "#cbd5e1" }}>{c.category}</td>
                <td style={{ padding: "8px 0", textAlign: "right", color: "#f8fafc" }}>
                  {pct(c.share, safeLocale, 0)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section style={{ marginBottom: 40 }}>
        <h2 style={{ color: "#f8fafc", fontSize: 22, marginBottom: 16 }}>
          {t("section_government")}
        </h2>
        <p>
          {t("gov_requests", { count: report.data_requests_received.government })}
          {" · "}
          {t("court_orders", { count: report.data_requests_received.court_orders })}
        </p>
        <p style={{ color: "#94a3b8", fontSize: 14, marginTop: 8 }}>
          {report.data_requests_received.note}
        </p>
      </section>
    </main>
  );
}
