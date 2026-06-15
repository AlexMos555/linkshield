import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";

import { routing, type Locale } from "@/i18n/routing";

const SITE_URL = "https://cleanway.ai";

function urlFor(locale: Locale | string): string {
  return locale === routing.defaultLocale ? `${SITE_URL}/success` : `${SITE_URL}/${locale}/success`;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const { locale } = await params;
  const isLocaleKnown = (routing.locales as readonly string[]).includes(locale);
  const safeLocale: Locale = isLocaleKnown ? (locale as Locale) : routing.defaultLocale;

  const t = await getTranslations({ locale: safeLocale, namespace: "Success" });

  const languages: Record<string, string> = {};
  for (const loc of routing.locales) languages[loc] = urlFor(loc as Locale);
  languages["x-default"] = urlFor(routing.defaultLocale);

  return {
    title: t("page_title"),
    description: t("page_description"),
    metadataBase: new URL(SITE_URL),
    alternates: { canonical: urlFor(safeLocale), languages },
    // Confirmation pages are not indexable — they're personal post-checkout
    // and Google penalises duplicate / thin content like this.
    robots: { index: false, follow: false },
  };
}

type Props = {
  searchParams: Promise<{ session_id?: string }>;
  params: Promise<{ locale: string }>;
};

export default async function SuccessPage({ searchParams, params }: Props) {
  const { session_id } = await searchParams;
  const { locale } = await params;
  const isLocaleKnown = (routing.locales as readonly string[]).includes(locale);
  const safeLocale: Locale = isLocaleKnown ? (locale as Locale) : routing.defaultLocale;
  const t = await getTranslations({ locale: safeLocale, namespace: "Success" });

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
          <a href="/" style={{ color: "#f8fafc", textDecoration: "none", fontWeight: 800, fontSize: 20 }}>
            Cleanway
          </a>
        </div>
      </nav>

      <main style={{ maxWidth: 600, margin: "0 auto", padding: "80px 24px", textAlign: "center" }}>
        {/* Success indicator — decorative checkmark, hidden from
            screen readers because the heading below carries the meaning. */}
        <div
          aria-hidden="true"
          style={{
            width: 96,
            height: 96,
            borderRadius: "50%",
            background: "rgba(34,197,94,0.12)",
            border: "3px solid #22c55e",
            margin: "0 auto 24px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 48,
          }}
        >
          ✅
        </div>

        <h1 style={{ fontSize: 32, fontWeight: 800, color: "#f8fafc", marginBottom: 12 }}>
          {t("heading")}
        </h1>
        <p style={{ fontSize: 17, color: "#94a3b8", lineHeight: 1.6, marginBottom: 32 }}>
          {t("subheading")}
        </p>

        {/* Next steps card */}
        <div style={{ background: "#1e293b", borderRadius: 16, padding: 28, textAlign: "left", border: "1px solid #334155" }}>
          <h2 style={{ fontSize: 18, fontWeight: 700, color: "#f8fafc", marginTop: 0, marginBottom: 16 }}>
            {t("next_steps_heading")}
          </h2>

          <div style={{ display: "flex", gap: 14, marginBottom: 16, alignItems: "flex-start" }}>
            <div style={{ width: 28, height: 28, borderRadius: "50%", background: "#22c55e", color: "#052e16", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 800, flexShrink: 0 }}>1</div>
            <div>
              <div style={{ fontSize: 15, fontWeight: 600, color: "#f8fafc", marginBottom: 4 }}>{t("step1_title")}</div>
              <div style={{ fontSize: 13, color: "#94a3b8" }}>{t("step1_body")}</div>
              <div style={{ marginTop: 10, display: "flex", gap: 8, flexWrap: "wrap" }}>
                <a href="https://chrome.google.com/webstore" style={{ background: "#22c55e", color: "#052e16", padding: "8px 16px", borderRadius: 8, fontWeight: 700, fontSize: 13, textDecoration: "none" }}>Chrome</a>
                <a href="https://addons.mozilla.org" style={{ background: "#0f172a", color: "#f8fafc", padding: "8px 16px", borderRadius: 8, fontWeight: 700, fontSize: 13, textDecoration: "none", border: "1px solid #334155" }}>Firefox</a>
                <a href="https://apps.apple.com/app/cleanway" style={{ background: "#0f172a", color: "#f8fafc", padding: "8px 16px", borderRadius: 8, fontWeight: 700, fontSize: 13, textDecoration: "none", border: "1px solid #334155" }}>Safari</a>
              </div>
            </div>
          </div>

          <div style={{ display: "flex", gap: 14, marginBottom: 16, alignItems: "flex-start" }}>
            <div style={{ width: 28, height: 28, borderRadius: "50%", background: "#3b82f6", color: "white", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 800, flexShrink: 0 }}>2</div>
            <div>
              <div style={{ fontSize: 15, fontWeight: 600, color: "#f8fafc", marginBottom: 4 }}>{t("step2_title")}</div>
              <div style={{ fontSize: 13, color: "#94a3b8" }}>{t("step2_body")}</div>
            </div>
          </div>

          <div style={{ display: "flex", gap: 14, alignItems: "flex-start" }}>
            <div style={{ width: 28, height: 28, borderRadius: "50%", background: "#f59e0b", color: "#1f2937", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 800, flexShrink: 0 }}>3</div>
            <div>
              <div style={{ fontSize: 15, fontWeight: 600, color: "#f8fafc", marginBottom: 4 }}>{t("step3_title")}</div>
              <div style={{ fontSize: 13, color: "#94a3b8" }}>{t("step3_body")}</div>
            </div>
          </div>
        </div>

        {/* Support footer. The #475569 colour previously used here failed
            WCAG AA at 2.36:1 against the dark background; #94a3b8 passes
            ~4.5:1. (Audit landing-a11y MEDIUM contrast.) */}
        <p style={{ fontSize: 13, color: "#94a3b8", marginTop: 32, lineHeight: 1.6 }}>
          {t("support_question")}{" "}
          <a href="mailto:support@cleanway.ai" style={{ color: "#60a5fa" }}>support@cleanway.ai</a>
          {session_id ? (
            <>
              <br />
              <span style={{ fontSize: 11, color: "#94a3b8" }}>
                {t("reference_label")}: <code style={{ color: "#94a3b8", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace" }}>{session_id.slice(0, 12)}…</code>
              </span>
            </>
          ) : null}
        </p>
      </main>
    </div>
  );
}
