/**
 * Android download / install page — the front door of the Tele2 funnel
 * (launch-blocker B3, docs/TELE2_LAUNCH_PLAN.md).
 *
 * A Tele2 subscriber taps an SMS link and lands here on their phone. One clear
 * RU CTA to download the signed APK, an illustrated Samsung "unknown sources"
 * walkthrough (the one step that scares non-technical users), RuStore/Play
 * slots for when those listings go live, and the honest RF framing (a local
 * phishing filter, not an anonymity VPN).
 *
 * The APK URL is env-driven (NEXT_PUBLIC_APK_URL) so the founder points it at
 * the CDN/GitHub-Release once the signed APK is hosted, with no code change.
 * Until then the button renders as a "coming soon" pill rather than a dead link.
 */
import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";
import { routing, type Locale } from "@/i18n/routing";

const SITE_URL = "https://cleanway.ai";
const APK_URL = process.env.NEXT_PUBLIC_APK_URL || "";

function urlFor(locale: Locale | string): string {
  return locale === routing.defaultLocale ? `${SITE_URL}/android` : `${SITE_URL}/${locale}/android`;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const { locale } = await params;
  const isKnown = (routing.locales as readonly string[]).includes(locale);
  const safeLocale: Locale = isKnown ? (locale as Locale) : routing.defaultLocale;
  const t = await getTranslations({ locale: safeLocale, namespace: "Android" });
  const languages: Record<string, string> = {};
  for (const loc of routing.locales) languages[loc] = urlFor(loc as Locale);
  return {
    title: `${t("title")} — Cleanway`,
    description: t("subtitle"),
    alternates: { canonical: urlFor(safeLocale), languages },
  };
}

export default async function AndroidPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale } = await params;
  const isKnown = (routing.locales as readonly string[]).includes(locale);
  const safeLocale: Locale = isKnown ? (locale as Locale) : routing.defaultLocale;
  const t = await getTranslations({ locale: safeLocale, namespace: "Android" });

  const benefits = [t("benefit_1"), t("benefit_2"), t("benefit_3")];
  const steps = [t("step_1"), t("step_2"), t("step_3"), t("step_4")];

  return (
    <main
      style={{
        maxWidth: 760,
        margin: "40px auto",
        padding: "0 24px 90px",
        color: "#cbd5e1",
        lineHeight: 1.65,
        fontFamily: "-apple-system, system-ui, sans-serif",
      }}
    >
      <header style={{ marginBottom: 28 }}>
        <h1 style={{ color: "#f8fafc", fontSize: 34, marginBottom: 10 }}>{t("title")}</h1>
        <p style={{ color: "#94a3b8", fontSize: 17 }}>{t("subtitle")}</p>
      </header>

      {/* Primary CTA */}
      <div style={{ marginBottom: 20 }}>
        {APK_URL ? (
          <a
            href={APK_URL}
            style={{
              display: "block",
              textAlign: "center",
              background: "#22c55e",
              color: "#052e16",
              fontSize: 19,
              fontWeight: 700,
              padding: "18px 24px",
              borderRadius: 14,
              textDecoration: "none",
            }}
          >
            {t("download_cta")}
          </a>
        ) : (
          <div
            style={{
              textAlign: "center",
              background: "#111827",
              border: "1px solid #1f2937",
              color: "#94a3b8",
              fontSize: 16,
              padding: "18px 24px",
              borderRadius: 14,
            }}
          >
            {t("download_soon")}
          </div>
        )}
        <p style={{ color: "#64748b", fontSize: 13.5, textAlign: "center", marginTop: 10 }}>
          {/* Without a hosted APK the steps below describe a button that is not
              on the page — say so plainly instead of letting the reader hunt
              for a download that does not exist yet. */}
          {APK_URL ? t("download_note") : t("download_soon_note")}
        </p>
      </div>

      {/* Benefits */}
      <ul style={{ listStyle: "none", padding: 0, margin: "0 0 40px" }}>
        {benefits.map((b, i) => (
          <li key={i} style={{ display: "flex", gap: 12, marginBottom: 14 }}>
            <span style={{ color: "#34d399", fontWeight: 700, flexShrink: 0 }}>✓</span>
            <span style={{ fontSize: 15.5 }}>{b}</span>
          </li>
        ))}
      </ul>

      {/* Install steps */}
      <h2 style={{ color: "#f8fafc", fontSize: 22, marginBottom: 18 }}>{t("steps_title")}</h2>
      <ol style={{ paddingLeft: 0, listStyle: "none", counterReset: "step", margin: "0 0 20px" }}>
        {steps.map((s, i) => (
          <li
            key={i}
            style={{ display: "flex", gap: 14, marginBottom: 16, alignItems: "flex-start" }}
          >
            <span
              style={{
                flexShrink: 0,
                width: 28,
                height: 28,
                borderRadius: 999,
                background: "#1e293b",
                color: "#e2e8f0",
                fontSize: 14,
                fontWeight: 700,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              {i + 1}
            </span>
            <span style={{ fontSize: 15.5, paddingTop: 3 }}>{s}</span>
          </li>
        ))}
      </ol>

      {/* Unknown-sources explainer */}
      <section
        style={{
          background: "#0f1a2e",
          border: "1px solid #1e293b",
          borderRadius: 14,
          padding: 20,
          marginBottom: 40,
        }}
      >
        <div style={{ color: "#e2e8f0", fontSize: 16, fontWeight: 600, marginBottom: 8 }}>
          {t("unknown_title")}
        </div>
        <p style={{ margin: 0, color: "#cbd5e1", fontSize: 14.5 }}>{t("unknown_body")}</p>
      </section>

      {/* Store options */}
      <h2 style={{ color: "#f8fafc", fontSize: 20, marginBottom: 16 }}>{t("stores_title")}</h2>
      <div style={{ display: "flex", gap: 12, marginBottom: 40, flexWrap: "wrap" }}>
        {[t("rustore"), t("gplay")].map((store) => (
          <div
            key={store}
            style={{
              flex: "1 1 200px",
              background: "#111827",
              border: "1px solid #1f2937",
              borderRadius: 12,
              padding: "14px 18px",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <span style={{ color: "#e2e8f0", fontSize: 15, fontWeight: 600 }}>{store}</span>
            <span style={{ color: "#64748b", fontSize: 13 }}>{t("store_soon")}</span>
          </div>
        ))}
      </div>

      {/* Honest RF framing */}
      <section
        style={{
          borderTop: "1px solid #1f2937",
          paddingTop: 24,
        }}
      >
        <div style={{ color: "#e2e8f0", fontSize: 16, fontWeight: 600, marginBottom: 8 }}>
          {t("privacy_title")}
        </div>
        <p style={{ margin: 0, color: "#94a3b8", fontSize: 14.5 }}>{t("privacy_body")}</p>
      </section>
    </main>
  );
}
