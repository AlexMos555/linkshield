/**
 * How to cancel the operator-billed subscription and get a refund.
 *
 * Exists only with NEXT_PUBLIC_BILLING_ENABLED on (otherwise a localized 404,
 * like any unknown path). The law behind the page: 376-ФЗ — a cancel means
 * not one more charge; ст. 32 ЗоЗПП — the right to withdraw at any time. The
 * four channels are the ones docs/BILLING.md implements: one tap in the app,
 * SMS «СТОП» to a short number (shown once the operator assigns it), support,
 * and the operator's own account area.
 */
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { getTranslations } from "next-intl/server";

import { routing, type Locale } from "@/i18n/routing";
import { BILLING_ENABLED, BILLING_TERMS, STOP_NUMBER } from "@/lib/billing-config";
import { localePath } from "@/lib/locale-path";
import { SUPPORT_EMAIL, SUPPORT_EMAIL_LIVE } from "@/lib/support";

const SITE_URL = "https://cleanway.ai";

function urlFor(locale: Locale | string): string {
  return locale === routing.defaultLocale ? `${SITE_URL}/cancel` : `${SITE_URL}/${locale}/cancel`;
}

function resolveLocale(locale: string): Locale {
  return (routing.locales as readonly string[]).includes(locale) ? (locale as Locale) : routing.defaultLocale;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  if (!BILLING_ENABLED) notFound();
  const safeLocale = resolveLocale((await params).locale);
  const t = await getTranslations({ locale: safeLocale, namespace: "Cancel" });
  const languages: Record<string, string> = {};
  for (const loc of routing.locales) languages[loc] = urlFor(loc as Locale);
  return {
    title: `${t("meta_title")} — Cleanway`,
    description: t("meta_description"),
    alternates: { canonical: urlFor(safeLocale), languages },
    robots: { index: true, follow: true },
  };
}

const card: React.CSSProperties = {
  background: "#111827",
  border: "1px solid #1f2937",
  borderRadius: 14,
  padding: 20,
};

const heading: React.CSSProperties = { color: "#f8fafc", fontSize: 22, margin: "40px 0 16px" };
const link: React.CSSProperties = { color: "#34d399", textDecoration: "underline" };

export default async function CancelPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  if (!BILLING_ENABLED) notFound();
  const safeLocale = resolveLocale((await params).locale);
  const t = await getTranslations({ locale: safeLocale, namespace: "Cancel" });
  const billing = await getTranslations({ locale: safeLocale, namespace: "Billing" });
  const lapse = billing(`lapse_${BILLING_TERMS.lapsePolicy}`);

  const ways: Array<{ key: string; title: string; body: string; pending?: boolean }> = [
    { key: "app", title: t("way_app_title"), body: t("way_app_body") },
    STOP_NUMBER
      ? { key: "sms", title: t("way_sms_title"), body: t("way_sms_body", { number: STOP_NUMBER }) }
      : { key: "sms", title: t("way_sms_title"), body: t("way_sms_pending"), pending: true },
    { key: "support", title: t("way_support_title"), body: t("way_support_body") },
    { key: "operator", title: t("way_operator_title"), body: t("way_operator_body") },
  ];
  const after = [t("after_1"), t("after_2"), t("after_3", { lapse }), t("after_4")];

  return (
    <main
      data-testid="cancel-page"
      style={{
        maxWidth: 760,
        margin: "40px auto",
        padding: "0 24px 80px",
        color: "#cbd5e1",
        lineHeight: 1.65,
        fontFamily: "-apple-system, system-ui, sans-serif",
      }}
    >
      <a href={localePath(safeLocale, "/pricing")} style={{ color: "#60a5fa", fontSize: 14, textDecoration: "none" }}>
        {t("back")}
      </a>
      <header style={{ margin: "24px 0 8px" }}>
        <h1 style={{ color: "#f8fafc", fontSize: 34, marginBottom: 10 }}>{t("title")}</h1>
        <p style={{ color: "#94a3b8", fontSize: 17, margin: 0 }}>{t("intro")}</p>
      </header>

      <h2 style={heading}>{t("ways_title")}</h2>
      <div style={{ display: "grid", gap: 12 }}>
        {ways.map((way) => (
          <section key={way.key} style={way.pending ? { ...card, border: "1px solid #78350f" } : card} data-testid={`cancel-way-${way.key}`}>
            <h3 style={{ color: "#f1f5f9", fontSize: 17, margin: "0 0 6px" }}>{way.title}</h3>
            <p style={{ margin: 0, fontSize: 15.5, color: way.pending ? "#fbbf24" : "#cbd5e1" }}>{way.body}</p>
          </section>
        ))}
      </div>

      <h2 style={heading}>{t("after_title")}</h2>
      <ul style={{ paddingInlineStart: 20, margin: 0 }} data-testid="cancel-after">
        {after.map((item) => (
          <li key={item} style={{ marginBottom: 8 }}>{item}</li>
        ))}
      </ul>

      <h2 style={heading}>{t("refund_title")}</h2>
      <p data-testid="cancel-refund">{t("refund_body")}</p>
      <p style={{ color: "#94a3b8", fontSize: 14 }}>{t("refund_law")}</p>

      <h2 style={heading}>{t("contact_title")}</h2>
      {SUPPORT_EMAIL_LIVE ? (
        <a href={`mailto:${SUPPORT_EMAIL}`} style={{ color: "#34d399", fontSize: 20, fontWeight: 600, textDecoration: "none" }}>
          {SUPPORT_EMAIL}
        </a>
      ) : (
        <p style={{ ...card, border: "1px solid #78350f", color: "#fbbf24", fontSize: 15, margin: 0 }} data-testid="cancel-contact-pending">
          {t("contact_pending")}
        </p>
      )}

      <p style={{ marginTop: 32, fontSize: 15, display: "flex", flexWrap: "wrap", gap: "8px 20px" }}>
        <a href={localePath(safeLocale, "/terms")} style={link}>{billing("link_terms")}</a>
        <a href={localePath(safeLocale, "/privacy-policy")} style={link}>{billing("link_privacy")}</a>
      </p>
    </main>
  );
}
