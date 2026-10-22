/**
 * Where the operator's payment page sends the buyer back — after a payment
 * AND after a failed or abandoned one: BILLING_MIXPLAT_RETURN_URL (default
 * https://cleanway.ai/ru/subscription/return, api/billing/settings.py) is both
 * the success and the fail URL of the payment form (api/billing/providers/
 * mixplat.py). The page cannot tell which, and does not need to: the app learns
 * the outcome from the billing service, so this page sends the reader back to
 * the app and says what each outcome means.
 *
 * Exists only with NEXT_PUBLIC_BILLING_ENABLED on (otherwise a localized 404,
 * like /cancel). Not indexed: it is a stop on the way back from a payment.
 */
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { getTranslations } from "next-intl/server";

import { routing, type Locale } from "@/i18n/routing";
import { BILLING_ENABLED } from "@/lib/billing-config";
import { localePath } from "@/lib/locale-path";

// The app's own scheme (mobile/app.json): opens Cleanway where it is installed.
const APP_URL = "cleanway://";

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
  const t = await getTranslations({ locale: safeLocale, namespace: "SubscriptionReturn" });
  return {
    title: `${t("meta_title")} — Cleanway`,
    robots: { index: false, follow: false },
  };
}

const button: React.CSSProperties = {
  display: "inline-block",
  background: "#22c55e",
  color: "#052e16",
  fontWeight: 700,
  fontSize: 17,
  padding: "14px 28px",
  minHeight: 44,
  borderRadius: 12,
  textDecoration: "none",
};
const link: React.CSSProperties = { color: "#34d399", textDecoration: "underline" };
const card: React.CSSProperties = {
  background: "#111827",
  border: "1px solid #1f2937",
  borderRadius: 14,
  padding: 20,
  textAlign: "start",
};

export default async function SubscriptionReturnPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  if (!BILLING_ENABLED) notFound();
  const safeLocale = resolveLocale((await params).locale);
  const t = await getTranslations({ locale: safeLocale, namespace: "SubscriptionReturn" });

  return (
    <main
      data-testid="subscription-return"
      style={{
        maxWidth: 640,
        margin: "40px auto",
        padding: "0 24px 80px",
        color: "#cbd5e1",
        lineHeight: 1.65,
        fontFamily: "-apple-system, system-ui, sans-serif",
        textAlign: "center",
      }}
    >
      <h1 style={{ color: "#f8fafc", fontSize: 32, margin: "32px 0 12px" }}>{t("title")}</h1>
      <p style={{ color: "#94a3b8", fontSize: 17, margin: "0 0 28px" }}>{t("intro")}</p>

      <a href={APP_URL} style={button} data-testid="subscription-return-open-app">
        {t("open_app")}
      </a>

      <div style={{ display: "grid", gap: 12, margin: "32px 0" }}>
        <section style={card} data-testid="subscription-return-paid">
          <h2 style={{ color: "#f1f5f9", fontSize: 17, margin: "0 0 6px" }}>{t("paid_title")}</h2>
          <p style={{ margin: 0, fontSize: 15.5 }}>{t("paid_body")}</p>
        </section>
        <section style={card} data-testid="subscription-return-failed">
          <h2 style={{ color: "#f1f5f9", fontSize: 17, margin: "0 0 6px" }}>{t("failed_title")}</h2>
          <p style={{ margin: 0, fontSize: 15.5 }}>{t("failed_body")}</p>
        </section>
      </div>

      <p style={{ fontSize: 15, display: "flex", flexWrap: "wrap", justifyContent: "center", gap: "8px 20px" }}>
        <a href={localePath(safeLocale, "/android")} style={link}>{t("get_app")}</a>
        <a href={localePath(safeLocale, "/cancel")} style={link}>{t("cancel_link")}</a>
        <a href={localePath(safeLocale, "/support")} style={link}>{t("support_link")}</a>
      </p>
    </main>
  );
}
