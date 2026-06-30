/**
 * Public benchmark methodology page — credibility moat.
 *
 * Reads docs/benchmarks/latest.json (auto-published weekly by
 * .github/workflows/weekly-benchmark.yml) and renders the live
 * head-to-head table: Cleanway vs Cloudflare 1.1.1.1 for Families
 * vs Google Safe Browsing vs PhishTank vs VirusTotal aggregate.
 *
 * Every recall claim on the landing page resolves here with the exact
 * dataset, the exact script, and a link to GitHub so anyone can reproduce
 * the number. The hero badge reads the same `latest.json` via
 * `lib/live-recall.ts` — when this page shows an updated benchmark, the
 * badge updates too on the next deploy.
 *
 * No competitor publishes this. It's the single biggest credibility
 * signal we can ship for go-to-market.
 */
import type { Metadata } from "next";
import fs from "node:fs/promises";
import path from "node:path";
import { getTranslations } from "next-intl/server";
import { routing, type Locale } from "@/i18n/routing";

const SITE_URL = "https://cleanway.ai";
const REPO_URL = "https://github.com/AlexMos555/linkshield";

type ResolverStats = {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  unknown: number;
  recall: number | null;
  fpr: number | null;
  precision: number | null;
  f1: number | null;
  latency_p50_ms: number | null;
};

type Benchmark = {
  ts: string;
  n_phishing: number;
  n_safe: number;
  sources: Record<string, string>;
  phishing: Record<string, ResolverStats>;
  safe: Record<string, ResolverStats>;
};

const RESOLVER_LABELS: Record<string, string> = {
  cleanway: "Cleanway (public)",
  cleanway_local: "Cleanway (full local)",
  gsb: "Google Safe Browsing",
  phishtank: "PhishTank",
  cloudflare_families: "Cloudflare 1.1.1.1 for Families",
  virustotal: "VirusTotal (70+ vendors)",
};

function urlFor(locale: Locale | string): string {
  return locale === routing.defaultLocale
    ? `${SITE_URL}/transparency/methodology`
    : `${SITE_URL}/${locale}/transparency/methodology`;
}

async function loadBenchmark(): Promise<Benchmark | null> {
  // Read the committed JSON from this repo. SSR'd, so no client
  // fetch — the page ships the snapshot at build time. Weekly
  // re-deploy refreshes it.
  const candidates = [
    path.join(process.cwd(), "..", "docs", "benchmarks", "latest.json"),
    path.join(process.cwd(), "docs", "benchmarks", "latest.json"),
  ];
  for (const p of candidates) {
    try {
      const raw = await fs.readFile(p, "utf-8");
      return JSON.parse(raw);
    } catch {
      continue;
    }
  }
  return null;
}

function pct(x: number | null, digits: number = 1): string {
  if (x === null || x === undefined || Number.isNaN(x)) return "—";
  return `${(x * 100).toFixed(digits)}%`;
}

function ms(x: number | null): string {
  if (x === null || x === undefined) return "—";
  return `${Math.round(x)} ms`;
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
  const t = await getTranslations({
    locale: safeLocale,
    namespace: "Methodology",
  });

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

export default async function MethodologyPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale } = await params;
  const isLocaleKnown = (routing.locales as readonly string[]).includes(locale);
  const safeLocale: Locale = isLocaleKnown
    ? (locale as Locale)
    : routing.defaultLocale;
  const t = await getTranslations({
    locale: safeLocale,
    namespace: "Methodology",
  });

  const data = await loadBenchmark();

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
          <a href="/transparency" style={{ color: "#60a5fa" }}>
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

      {/* Live results from latest.json */}
      <section style={{ marginBottom: 36 }}>
        <h2 style={_h2}>{t("results_heading")}</h2>
        {!data ? (
          <p style={{ color: "#f59e0b" }}>{t("results_unavailable")}</p>
        ) : (
          <>
            <p style={{ color: "#94a3b8", fontSize: 14, marginBottom: 16 }}>
              {t("results_meta", {
                date: data.ts,
                phishing: data.n_phishing,
                legit: data.n_safe,
              })}
            </p>

            <h3 style={_h3}>{t("phishing_table_heading")}</h3>
            <div style={{ overflowX: "auto", marginBottom: 24 }}>
              <table style={_table}>
                <thead>
                  <tr>
                    <th style={_th}>Resolver</th>
                    <th style={_thNum}>Recall</th>
                    <th style={_thNum}>Precision</th>
                    <th style={_thNum}>F1</th>
                    <th style={_thNum}>TP</th>
                    <th style={_thNum}>FN</th>
                    <th style={_thNum}>?</th>
                    <th style={_thNum}>p50</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(data.phishing).map(([name, m]) => (
                    <tr
                      key={name}
                      style={
                        name.startsWith("cleanway")
                          ? { background: "#0c4a6e1a" }
                          : {}
                      }
                    >
                      <td style={_td}>
                        <strong>{RESOLVER_LABELS[name] || name}</strong>
                      </td>
                      <td style={_tdNum}>{pct(m.recall)}</td>
                      <td style={_tdNum}>{pct(m.precision)}</td>
                      <td style={_tdNum}>{pct(m.f1)}</td>
                      <td style={_tdNum}>{m.tp}</td>
                      <td style={_tdNum}>{m.fn}</td>
                      <td style={_tdNum}>{m.unknown}</td>
                      <td style={_tdNum}>{ms(m.latency_p50_ms)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <h3 style={_h3}>{t("safe_table_heading")}</h3>
            <div style={{ overflowX: "auto" }}>
              <table style={_table}>
                <thead>
                  <tr>
                    <th style={_th}>Resolver</th>
                    <th style={_thNum}>FPR</th>
                    <th style={_thNum}>FP</th>
                    <th style={_thNum}>TN</th>
                    <th style={_thNum}>?</th>
                    <th style={_thNum}>p50</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(data.safe).map(([name, m]) => (
                    <tr
                      key={name}
                      style={
                        name.startsWith("cleanway")
                          ? { background: "#0c4a6e1a" }
                          : {}
                      }
                    >
                      <td style={_td}>
                        <strong>{RESOLVER_LABELS[name] || name}</strong>
                      </td>
                      <td style={_tdNum}>{pct(m.fpr, 2)}</td>
                      <td style={_tdNum}>{m.fp}</td>
                      <td style={_tdNum}>{m.tn}</td>
                      <td style={_tdNum}>{m.unknown}</td>
                      <td style={_tdNum}>{ms(m.latency_p50_ms)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </section>

      {/* Datasets */}
      <section style={{ marginBottom: 36 }}>
        <h2 style={_h2}>{t("datasets_heading")}</h2>
        <ul style={_ul}>
          <li>
            <strong>{t("dataset_phishing")}</strong>: URLhaus daily feed +
            PhishTank online-valid dump. Both freshly fetched at each run,
            deduplicated by registrable domain.
          </li>
          <li>
            <strong>{t("dataset_safe")}</strong>: random Tranco top-1M
            domains, rank 100-100,000 (skipping the top-100 to avoid
            'too easy' baseline). Random seed 42 for reproducibility.
          </li>
        </ul>
      </section>

      {/* Resolver mappings */}
      <section style={{ marginBottom: 36 }}>
        <h2 style={_h2}>{t("verdict_mapping_heading")}</h2>
        <p>{t("verdict_mapping_p1")}</p>
        <ul style={_ul}>
          <li>
            <strong>Cleanway</strong>: `level=dangerous` → dangerous,
            `level=safe` → safe, anything else (`caution`) → unknown.
          </li>
          <li>
            <strong>Cloudflare 1.1.1.1 for Families</strong>: NXDOMAIN or
            sinkhole 0.0.0.0 / :: → dangerous. Normal A-record answer → safe.
          </li>
          <li>
            <strong>VirusTotal aggregate</strong>: ≥2 of the 70+ vendors
            flagging the URL → dangerous. Single-vendor flags are
            ignored — too noisy.
          </li>
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
          .
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
          .
        </p>
      </section>

      {/* Caveats */}
      <section style={{ marginBottom: 36 }}>
        <h2 style={_h2}>{t("caveats_heading")}</h2>
        <ul style={_ul}>
          <li>{t("caveat_1")}</li>
          <li>{t("caveat_2")}</li>
          <li>{t("caveat_3")}</li>
          <li>{t("caveat_4")}</li>
        </ul>
      </section>

      <p
        style={{
          textAlign: "center",
          fontSize: 12,
          color: "#475569",
          marginTop: 32,
        }}
      >
        <a href="/transparency" style={{ color: "#60a5fa" }}>
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
  paddingLeft: 22,
};

const _table: React.CSSProperties = {
  width: "100%",
  borderCollapse: "collapse",
  fontSize: 14,
};

const _th: React.CSSProperties = {
  textAlign: "left",
  padding: "10px 12px",
  borderBottom: "1px solid #334155",
  color: "#94a3b8",
  fontWeight: 600,
};

const _thNum: React.CSSProperties = {
  ..._th,
  textAlign: "right",
};

const _td: React.CSSProperties = {
  padding: "10px 12px",
  borderBottom: "1px solid #1e293b",
};

const _tdNum: React.CSSProperties = {
  ..._td,
  textAlign: "right",
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
};
