/**
 * Transparency report — only numbers we actually measured.
 *
 * This page used to render the backend's /api/v1/transparency/latest, a
 * hand-written pre-launch fixture ("1,842,630 checks", "0.08% false
 * positives, verified by the analyst team") with literal $PERIOD$ / $DATE$
 * placeholders on top (report #12). None of those numbers came from a
 * measurement. Now the page reads the committed weekly benchmark
 * (docs/benchmarks/latest.json) and shows a figure only when the sample clears
 * the quality gate in lib/benchmark.ts; otherwise it says, in plain words,
 * that there is no trustworthy number yet.
 */
import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";

import { routing, type Locale } from "@/i18n/routing";
import {
  MIN_PHISHING_SAMPLE,
  falsePositiveRateIsPublishable,
  loadLatestBenchmark,
  recallIsPublishable,
  type BenchmarkSnapshot,
} from "@/lib/benchmark";
import { localePath } from "@/lib/locale-path";

const SITE_URL = "https://cleanway.ai";

function urlFor(locale: Locale | string): string {
  return locale === routing.defaultLocale
    ? `${SITE_URL}/transparency`
    : `${SITE_URL}/${locale}/transparency`;
}

function resolveLocale(locale: string): Locale {
  return (routing.locales as readonly string[]).includes(locale) ? (locale as Locale) : routing.defaultLocale;
}

function percent(fraction: number, locale: string): string {
  return new Intl.NumberFormat(locale, { maximumFractionDigits: 1 }).format(fraction * 100);
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

type Translate = (key: string, values?: Record<string, string | number>) => string;

function recallText(t: Translate, snapshot: BenchmarkSnapshot | null, locale: string): string {
  if (!snapshot || !recallIsPublishable(snapshot)) {
    return t("recall_not_yet", { min: MIN_PHISHING_SAMPLE });
  }
  const ours = snapshot.phishing.cleanway;
  return t("recall_measured", {
    date: day(snapshot.ts, locale),
    recall: percent(ours.recall ?? 0, locale),
    classified: ours.tp + ours.fn,
  });
}

function falseAlarmText(t: Translate, snapshot: BenchmarkSnapshot | null, locale: string): string {
  if (!snapshot || !falsePositiveRateIsPublishable(snapshot)) return t("fp_not_yet");
  const ours = snapshot.safe.cleanway;
  return t("fp_measured", {
    date: day(snapshot.ts, locale),
    fpr: percent(ours.fpr ?? 0, locale),
    count: ours.tn + ours.fp,
  });
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
        <p>{recallText(t, snapshot, safeLocale)}</p>
      </section>

      <section style={section} data-testid="transparency-fp">
        <h2 style={h2}>{t("section_fp")}</h2>
        <p>{falseAlarmText(t, snapshot, safeLocale)}</p>
      </section>

      <section style={section}>
        <h2 style={h2}>{t("section_how")}</h2>
        <p>
          {t("how_body")}{" "}
          <a href={localePath(safeLocale, "/transparency/methodology")} style={{ color: "#60a5fa" }}>
            {t("methodology_link")}
          </a>
        </p>
      </section>
    </main>
  );
}
