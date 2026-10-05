import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";

import { routing, RTL_LOCALES, type Locale } from "@/i18n/routing";
import { localePath } from "@/lib/locale-path";
import SignupForm from "./SignupForm";

const SITE_URL = "https://cleanway.ai";

function urlFor(locale: Locale | string): string {
  return locale === routing.defaultLocale ? `${SITE_URL}/signup` : `${SITE_URL}/${locale}/signup`;
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
  const t = await getTranslations({ locale: safeLocale, namespace: "Signup" });

  const languages: Record<string, string> = {};
  for (const loc of routing.locales) languages[loc] = urlFor(loc as Locale);
  languages["x-default"] = urlFor(routing.defaultLocale);

  return {
    title: t("meta_title"),
    description: t("meta_description"),
    metadataBase: new URL(SITE_URL),
    alternates: { canonical: urlFor(safeLocale), languages },
    // Signup conversion pages benefit from being indexable so SEO from
    // /pricing benefits both pages. follow=true lets PageRank flow back.
    robots: { index: true, follow: true },
  };
}

type Props = {
  /** `error` is the stable code /auth/callback leaves when a link failed. */
  searchParams: Promise<{ plan?: string; interval?: string; error?: string }>;
  params: Promise<{ locale: string }>;
};

const VALID_PLANS = new Set(["personal", "family", "business"]);
const VALID_INTERVALS = new Set(["monthly", "yearly"]);

const PLAN_LABELS: Record<string, string> = {
  personal: "Personal",
  family: "Family",
  business: "Business",
};

export default async function SignupPage({ searchParams, params }: Props) {
  const sp = await searchParams;
  const safeLocale = resolveLocale((await params).locale);
  const t = await getTranslations({ locale: safeLocale, namespace: "Signup" });
  // "Back" arrow must mirror in RTL. ← reads as "left" everywhere — in
  // Arabic that LOOKS like "forward". → in Arabic locale gives the
  // user-expected "back" direction. (Audit landing-a11y LOW
  // "Hardcoded left-arrow '← Back to pricing' in signup/page.tsx is
  // mirrored-wrong in Arabic RTL".)
  const isRtl = (RTL_LOCALES as readonly string[]).includes(safeLocale);
  const backArrow = isRtl ? "→" : "←";
  const plan = sp.plan && VALID_PLANS.has(sp.plan) ? sp.plan : null;
  const interval = sp.interval && VALID_INTERVALS.has(sp.interval) ? sp.interval : null;
  const storeItems = t.raw("store_items") as string[];

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
          <a href={localePath(safeLocale, "/pricing")} style={{ color: "#94a3b8", textDecoration: "none", fontSize: 14 }}>
            {backArrow} {t("back_to_pricing")}
          </a>
        </div>
      </nav>

      <div style={{ maxWidth: 480, margin: "0 auto", padding: "60px 24px" }}>
        <h1 style={{ fontSize: 30, fontWeight: 800, color: "#f8fafc", marginBottom: 8 }}>
          {t("heading")}
        </h1>
        <p style={{ fontSize: 15, color: "#94a3b8", marginBottom: 32, lineHeight: 1.6 }}>
          {t("intro")}
        </p>

        {/* Plan context — only shown when arrived from /pricing */}
        {plan && (
          <div
            style={{
              background: "#1e293b",
              borderRadius: 12,
              padding: "14px 18px",
              marginBottom: 24,
              border: "1px solid #22c55e40",
              display: "flex",
              alignItems: "center",
              gap: 12,
            }}
          >
            <div style={{ width: 32, height: 32, borderRadius: "50%", background: "#22c55e20", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16 }}>
              ✓
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 14, fontWeight: 600, color: "#f8fafc" }}>
                {t("plan_label", { plan: PLAN_LABELS[plan] || plan })}
                {interval ? ` · ${t(interval === "yearly" ? "interval_yearly" : "interval_monthly")}` : ""}
              </div>
              <div style={{ fontSize: 12, color: "#94a3b8" }}>
                {t("plan_next")}
              </div>
            </div>
          </div>
        )}

        <SignupForm planFromQuery={plan} intervalFromQuery={interval} errorFromQuery={sp.error ?? null} />

        {/* Privacy reassurance */}
        <div style={{ marginTop: 28, padding: "16px 18px", background: "#1e293b80", borderRadius: 10, border: "1px solid #1e293b" }}>
          <div style={{ fontSize: 12, color: "#64748b", textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 8 }}>
            {t("store_title")}
          </div>
          <ul style={{ margin: 0, paddingInlineStart: 18, fontSize: 13, color: "#94a3b8", lineHeight: 1.7 }}>
            {storeItems.map((item) => <li key={item}>{item}</li>)}
          </ul>
          <div style={{ marginTop: 10, fontSize: 12, color: "#64748b" }}>
            {t("store_note")}{" "}
            <a href={localePath(safeLocale, "/privacy-policy")} style={{ color: "#60a5fa" }}>{t("store_more")}</a>
          </div>
        </div>
      </div>
    </div>
  );
}
