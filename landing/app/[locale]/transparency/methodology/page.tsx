/**
 * Public benchmark methodology page.
 *
 * Reads docs/benchmarks/latest.json (moved forward by
 * .github/workflows/weekly-benchmark.yml only when a run clears the script's
 * quality gate) and renders the head-to-head tables: Cleanway vs Cloudflare
 * 1.1.1.1 for Families vs Google Safe Browsing vs PhishTank vs VirusTotal.
 *
 * The tables appear only when the snapshot clears the same gate the site uses
 * everywhere (lib/benchmark.ts). Otherwise the page says how small the last
 * run was and links to every raw weekly result, instead of printing a
 * percentage from 24 links under "Snapshot: $DATE$" (report #12).
 */
import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { routing, type Locale } from "@/i18n/routing";
import {
  MIN_PHISHING_CLASSIFIED,
  MIN_PHISHING_SAMPLE,
  falsePositiveRateIsPublishable,
  loadLatestBenchmark,
  recallIsPublishable,
  type BenchmarkSnapshot,
  type ResolverStats,
} from "@/lib/benchmark";
import { localePath } from "@/lib/locale-path";

const SITE_URL = "https://cleanway.ai";
const REPO_URL = "https://github.com/AlexMos555/linkshield";

const RESOLVER_LABELS: Record<string, string> = {
  cleanway: "Cleanway",
  cleanway_local: "Cleanway (full local)",
  gsb: "Google Safe Browsing",
  phishtank: "PhishTank",
  cloudflare_families: "Cloudflare 1.1.1.1 for Families",
  virustotal: "VirusTotal",
};

type Translate = (key: string, values?: Record<string, string | number>) => string;

function urlFor(locale: Locale | string): string {
  return locale === routing.defaultLocale
    ? `${SITE_URL}/transparency/methodology`
    : `${SITE_URL}/${locale}/transparency/methodology`;
}

function resolveLocale(locale: string): Locale {
  return (routing.locales as readonly string[]).includes(locale) ? (locale as Locale) : routing.defaultLocale;
}

function pct(x: number | null, locale: string, digits: number = 1): string {
  if (x === null || x === undefined || Number.isNaN(x)) return "—";
  return new Intl.NumberFormat(locale, { style: "percent", maximumFractionDigits: digits }).format(x);
}

function ms(x: number | null): string {
  if (x === null || x === undefined) return "—";
  return `${Math.round(x)} ms`;
}

function day(iso: string, locale: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? iso
    : new Intl.DateTimeFormat(locale, { dateStyle: "long", timeZone: "UTC" }).format(date);
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const safeLocale = resolveLocale((await params).locale);
  const t = await getTranslations({ locale: safeLocale, namespace: "Methodology" });

  const canonical = urlFor(safeLocale);
  const languages: Record<string, string> = {};
  for (const loc of routing.locales) languages[loc] = urlFor(loc as Locale);
  languages["x-default"] = urlFor(routing.defaultLocale);

  return {
    title: `${t("page_title")} — Cleanway`,
    description: t("page_description"),
    metadataBase: new URL(SITE_URL),
    alternates: { canonical, languages },
    robots: { index: true, follow: true },
  };
}

function rowStyle(name: string): React.CSSProperties {
  return name.startsWith("cleanway") ? { background: "#0c4a6e1a" } : {};
}

function PhishingTable({ data, t, locale }: { data: BenchmarkSnapshot; t: Translate; locale: string }) {
  return (
    <div style={{ overflowX: "auto", marginBottom: 24 }}>
      <table style={_table}>
        <thead>
          <tr>
            <th style={_th}>{t("col_service")}</th>
            <th style={_thNum}>{t("col_recall")}</th>
            <th style={_thNum}>{t("col_precision")}</th>
            <th style={_thNum}>{t("col_f1")}</th>
            <th style={_thNum}>{t("col_tp")}</th>
            <th style={_thNum}>{t("col_fn")}</th>
            <th style={_thNum}>{t("col_unknown")}</th>
            <th style={_thNum}>{t("col_latency")}</th>
          </tr>
        </thead>
        <tbody>
          {Object.entries(data.phishing).map(([name, m]: [string, ResolverStats]) => (
            <tr key={name} style={rowStyle(name)}>
              <td style={_td}><strong>{RESOLVER_LABELS[name] || name}</strong></td>
              <td style={_tdNum}>{pct(m.recall, locale)}</td>
              <td style={_tdNum}>{pct(m.precision, locale)}</td>
              <td style={_tdNum}>{pct(m.f1, locale)}</td>
              <td style={_tdNum}>{m.tp}</td>
              <td style={_tdNum}>{m.fn}</td>
              <td style={_tdNum}>{m.unknown}</td>
              <td style={_tdNum}>{ms(m.latency_p50_ms)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SafeTable({ data, t, locale }: { data: BenchmarkSnapshot; t: Translate; locale: string }) {
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={_table}>
        <thead>
          <tr>
            <th style={_th}>{t("col_service")}</th>
            <th style={_thNum}>{t("col_fpr")}</th>
            <th style={_thNum}>{t("col_fp")}</th>
            <th style={_thNum}>{t("col_tn")}</th>
            <th style={_thNum}>{t("col_unknown")}</th>
            <th style={_thNum}>{t("col_latency")}</th>
          </tr>
        </thead>
        <tbody>
          {Object.entries(data.safe).map(([name, m]: [string, ResolverStats]) => (
            <tr key={name} style={rowStyle(name)}>
              <td style={_td}><strong>{RESOLVER_LABELS[name] || name}</strong></td>
              <td style={_tdNum}>{pct(m.fpr, locale, 2)}</td>
              <td style={_tdNum}>{m.fp}</td>
              <td style={_tdNum}>{m.tn}</td>
              <td style={_tdNum}>{m.unknown}</td>
              <td style={_tdNum}>{ms(m.latency_p50_ms)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Results({ data, t, locale }: { data: BenchmarkSnapshot | null; t: Translate; locale: string }) {
  if (!data) {
    return <p style={{ color: "#f59e0b" }}>{t("results_unavailable")}</p>;
  }
  const ours = data.phishing?.cleanway;
  if (!recallIsPublishable(data)) {
    return (
      <p data-testid="methodology-not-publishable" style={{ color: "#fbbf24" }}>
        {t("results_not_publishable", {
          date: day(data.ts, locale),
          phishing: data.n_phishing,
          classified: (ours?.tp ?? 0) + (ours?.fn ?? 0),
          min_phishing: MIN_PHISHING_SAMPLE,
          min_classified: MIN_PHISHING_CLASSIFIED,
        })}
      </p>
    );
  }
  return (
    <>
      <p style={{ color: "#94a3b8", fontSize: 14, marginBottom: 16 }}>
        {t("results_snapshot", { date: day(data.ts, locale), phishing: data.n_phishing, legit: data.n_safe })}
      </p>
      <h3 style={_h3}>{t("phishing_table_heading")}</h3>
      <PhishingTable data={data} t={t} locale={locale} />
      <h3 style={_h3}>{t("safe_table_heading")}</h3>
      {falsePositiveRateIsPublishable(data) ? (
        <SafeTable data={data} t={t} locale={locale} />
      ) : (
        <p style={{ color: "#fbbf24" }}>{t("fp_not_measured")}</p>
      )}
    </>
  );
}

export default async function MethodologyPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const safeLocale = resolveLocale((await params).locale);
  const t = await getTranslations({ locale: safeLocale, namespace: "Methodology" });
  const data = await loadLatestBenchmark();
  const transparencyHref = localePath(safeLocale, "/transparency");
  const caveats = [
    t("caveat_endpoint"),
    t("caveat_allowlist"),
    t("caveat_rate_limit"),
    t("caveat_phishtank"),
    t("caveat_gsb"),
    t("caveat_nxdomain"),
    t("caveat_latency"),
  ];

  return (
    <main
      style={{
        maxWidth: 980,
        margin: "40px auto",
        padding: "0 24px",
        color: "#cbd5e1",
        lineHeight: 1.65,
        fontFamily: "-apple-system, system-ui, sans-serif",
      }}
    >
      <header style={{ marginBottom: 36 }}>
        <p style={{ color: "#94a3b8", fontSize: 13, marginBottom: 4 }}>
          <a href={transparencyHref} style={{ color: "#60a5fa" }}>
            ← {t("back_to_transparency")}
          </a>
        </p>
        <h1
          style={{
            color: "#f8fafc",
            fontSize: 38,
            marginBottom: 12,
            lineHeight: 1.2,
          }}
        >
          {t("hero_title")}
        </h1>
        <p style={{ color: "#94a3b8", fontSize: 17 }}>{t("hero_subtitle")}</p>
      </header>

      {/* Why this page exists */}
      <section style={{ marginBottom: 36 }}>
        <h2 style={_h2}>{t("why_heading")}</h2>
        <p>{t("why_p1")}</p>
        <p>{t("why_p2")}</p>
      </section>

      {/* Results from latest.json — only when the sample means something */}
      <section style={{ marginBottom: 36 }}>
        <h2 style={_h2}>{t("results_heading")}</h2>
        <Results data={data} t={t} locale={safeLocale} />
        <p style={{ marginTop: 12 }}>
          <a href={`${REPO_URL}/tree/main/docs/benchmarks`} style={{ color: "#60a5fa" }}>
            {t("all_runs_link")}
          </a>
        </p>
      </section>

      {/* Datasets */}
      <section style={{ marginBottom: 36 }}>
        <h2 style={_h2}>{t("datasets_heading")}</h2>
        <ul style={_ul}>
          <li>
            <strong>{t("dataset_phishing")}</strong>: {t("dataset_phishing_desc")}
          </li>
          <li>
            <strong>{t("dataset_safe")}</strong>: {t("dataset_safe_desc")}
          </li>
        </ul>
      </section>

      {/* Resolver mappings */}
      <section style={{ marginBottom: 36 }}>
        <h2 style={_h2}>{t("verdict_mapping_heading")}</h2>
        <p>{t("verdict_mapping_p1")}</p>
        <ul style={_ul}>
          <li>{t("mapping_cleanway")}</li>
          <li>{t("mapping_cloudflare")}</li>
          <li>{t("mapping_virustotal")}</li>
        </ul>
      </section>

      {/* How to reproduce */}
      <section style={{ marginBottom: 36 }}>
        <h2 style={_h2}>{t("reproduce_heading")}</h2>
        <p>{t("reproduce_p1")}</p>
        <pre style={_codeblock}>
          {`git clone ${REPO_URL}\ncd linkshield\npython3 scripts/eval_fresh_urls.py --sample 100`}
        </pre>
        <p style={{ marginTop: 12 }}>
          {t("reproduce_note")}{" "}
          <a
            href={`${REPO_URL}/blob/main/scripts/eval_fresh_urls.py`}
            style={{ color: "#60a5fa" }}
          >
            scripts/eval_fresh_urls.py
          </a>
        </p>
      </section>

      {/* Cadence + automation */}
      <section style={{ marginBottom: 36 }}>
        <h2 style={_h2}>{t("cadence_heading")}</h2>
        <p>{t("cadence_p1")}</p>
        <p>
          {t("cadence_p2")}{" "}
          <a
            href={`${REPO_URL}/blob/main/.github/workflows/weekly-benchmark.yml`}
            style={{ color: "#60a5fa" }}
          >
            .github/workflows/weekly-benchmark.yml
          </a>
        </p>
      </section>

      {/* Caveats */}
      <section style={{ marginBottom: 36 }}>
        <h2 style={_h2}>{t("caveats_heading")}</h2>
        <ul style={_ul}>
          {caveats.map((caveat) => <li key={caveat}>{caveat}</li>)}
        </ul>
      </section>

      <p
        style={{
          textAlign: "center",
          fontSize: 12,
          color: "#475569",
          marginTop: 32,
          paddingBottom: 40,
        }}
      >
        <a href={transparencyHref} style={{ color: "#60a5fa" }}>
          {t("back_to_transparency")}
        </a>
      </p>
    </main>
  );
}

const _h2: React.CSSProperties = {
  color: "#f8fafc",
  fontSize: 24,
  marginBottom: 14,
  marginTop: 0,
};

const _h3: React.CSSProperties = {
  color: "#e2e8f0",
  fontSize: 18,
  marginBottom: 10,
  marginTop: 16,
};

const _ul: React.CSSProperties = {
  paddingInlineStart: 22,
};

const _table: React.CSSProperties = {
  width: "100%",
  borderCollapse: "collapse",
  fontSize: 14,
};

const _th: React.CSSProperties = {
  textAlign: "start",
  padding: "10px 12px",
  borderBottom: "1px solid #334155",
  color: "#94a3b8",
  fontWeight: 600,
};

const _thNum: React.CSSProperties = {
  ..._th,
  textAlign: "end",
};

const _td: React.CSSProperties = {
  padding: "10px 12px",
  borderBottom: "1px solid #1e293b",
};

const _tdNum: React.CSSProperties = {
  ..._td,
  textAlign: "end",
  fontVariantNumeric: "tabular-nums",
};

const _codeblock: React.CSSProperties = {
  background: "#0f172a",
  color: "#e2e8f0",
  padding: 16,
  borderRadius: 8,
  fontFamily: "ui-monospace, SF Mono, Menlo, monospace",
  fontSize: 13,
  overflowX: "auto",
  border: "1px solid #1e293b",
  direction: "ltr",
};
