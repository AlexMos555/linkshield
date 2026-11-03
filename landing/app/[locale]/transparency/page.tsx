/**
 * Transparency report — only numbers we actually measured.
 *
 * This page used to render the backend's /api/v1/transparency/latest, a
 * hand-written pre-launch fixture ("1,842,630 checks", "0.08% false
 * positives, verified by the analyst team") with literal $PERIOD$ / $DATE$
 * placeholders on top (report #12). None of those numbers came from a
 * measurement. Now the page reads the committed weekly benchmark
 * (docs/benchmarks/latest.json) and shows a figure only when the report is
 * made by the current method and clears the quality gate in lib/benchmark.ts
 * (detectionFigures, falseAlarmFigures); otherwise it says, in plain words,
 * that there is no trustworthy number yet.
 *
 * Both figures are the same pair over the answered rows: called dangerous,
 * and warned at all (a caution included). The false-alarm one used to be the
 * old fpr of a method-1 report ("0% of 137 legitimate sites" on 2026-11-01),
 * which left out the other 63 of its 200 real sites, every caution among them.
 */
import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";

import { routing, type Locale } from "@/i18n/routing";
import {
  MIN_PHISHING_SAMPLE,
  MIN_SAFE_CLASSIFIED,
  detectionFigures,
  falseAlarmFigures,
  loadLatestBenchmark,
  type BenchmarkSnapshot,
} from "@/lib/benchmark";
import { DATA_SOURCES_ANCHOR } from "@/lib/data-sources";
import { answeredMessageArgs, detectionMessageArgs } from "@/lib/detection-copy";
import { localePath } from "@/lib/locale-path";
import { DEFAULT_OG_IMAGE } from "@/lib/seo";

const SITE_URL = "https://cleanway.ai";

function urlFor(locale: Locale | string): string {
  return locale === routing.defaultLocale
    ? `${SITE_URL}/transparency`
    : `${SITE_URL}/${locale}/transparency`;
}

function resolveLocale(locale: string): Locale {
  return (routing.locales as readonly string[]).includes(locale) ? (locale as Locale) : routing.defaultLocale;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const safeLocale = resolveLocale((await params).locale);
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
      images: [DEFAULT_OG_IMAGE],
    },
    robots: {
      index: true,
      follow: true,
    },
  };
}

type Translate = (key: string, values?: Record<string, string | number>) => string;

function detectionText(t: Translate, snapshot: BenchmarkSnapshot | null, locale: string): string {
  const figures = detectionFigures(snapshot);
  if (!figures) return t("recall_not_yet", { min: MIN_PHISHING_SAMPLE });
  return t("recall_measured", detectionMessageArgs(figures, locale));
}

function falseAlarmText(t: Translate, snapshot: BenchmarkSnapshot | null, locale: string): string {
  const figures = falseAlarmFigures(snapshot);
  if (!figures) return t("fp_not_yet", { min: MIN_SAFE_CLASSIFIED });
  return t("fp_measured", answeredMessageArgs(figures, locale));
}

const section: React.CSSProperties = { marginBottom: 36 };
const h2: React.CSSProperties = { color: "#f8fafc", fontSize: 22, marginBottom: 12 };

export default async function TransparencyPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const safeLocale = resolveLocale((await params).locale);
  const t = await getTranslations({ locale: safeLocale, namespace: "Transparency" });
  const snapshot = await loadLatestBenchmark();

  return (
    <main style={{ maxWidth: 760, margin: "40px auto", padding: "0 24px 80px", color: "#cbd5e1", lineHeight: 1.65 }}>
      <header style={{ marginBottom: 32 }}>
        <h1 style={{ color: "#f8fafc", fontSize: 36, marginBottom: 12 }}>{t("page_title")}</h1>
        <p style={{ color: "#94a3b8", fontSize: 16 }}>{t("intro")}</p>
      </header>

      <section style={section} data-testid="transparency-recall">
        <h2 style={h2}>{t("section_accuracy")}</h2>
        <p>{detectionText(t, snapshot, safeLocale)}</p>
      </section>

      <section style={section} data-testid="transparency-fp">
        <h2 style={h2}>{t("section_fp")}</h2>
        <p>{falseAlarmText(t, snapshot, safeLocale)}</p>
      </section>

      <section style={section}>
        <h2 style={h2}>{t("section_how")}</h2>
        <p>
          {t("how_body")}{" "}
          <a href={localePath(safeLocale, "/transparency/methodology")} style={{ color: "#60a5fa", textDecoration: "underline" }}>
            {t("methodology_link")}
          </a>
        </p>
        <p>
          <a
            href={`${localePath(safeLocale, "/transparency/methodology")}#${DATA_SOURCES_ANCHOR}`}
            style={{ color: "#60a5fa", textDecoration: "underline" }}
          >
            {t("sources_link")}
          </a>
        </p>
      </section>
    </main>
  );
}
