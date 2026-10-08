/**
 * /delete-account — the public "delete your account" page.
 *
 * Google Play requires a web address where people can ask for their account
 * to be deleted without installing the app (Play Console → Data safety →
 * "Delete account URL"; listed in docs/STORES.md). The deletion itself lives
 * on /account (sign in → "Delete account", DELETE /api/v1/user/account); this
 * page explains the steps, what is deleted and what is kept, in the reader's
 * language, and is indexable so the store reviewer and anyone else can find
 * it. What it says follows docs/PRIVACY.md ("Accounts, devices and
 * purchases", "Your rights") and api/routers/user.py (30-day grace, Stripe
 * subscription cancelled at once).
 */
import type { CSSProperties } from "react";
import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";

import { routing, RTL_LOCALES, type Locale } from "@/i18n/routing";
import { localePath } from "@/lib/locale-path";
import { SUPPORT_EMAIL, SUPPORT_EMAIL_LIVE } from "@/lib/support";

const SITE_URL = "https://cleanway.ai";
const PATH = "/delete-account";

function urlFor(locale: Locale | string, path: string): string {
  return locale === routing.defaultLocale ? `${SITE_URL}${path}` : `${SITE_URL}/${locale}${path}`;
}

function resolveLocale(locale: string): Locale {
  return (routing.locales as readonly string[]).includes(locale) ? (locale as Locale) : routing.defaultLocale;
}

type Props = { params: Promise<{ locale: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const locale = resolveLocale((await params).locale);
  const t = await getTranslations({ locale, namespace: "DeleteAccount" });
  const languages: Record<string, string> = {};
  for (const loc of routing.locales) languages[loc] = urlFor(loc as Locale, PATH);
  languages["x-default"] = urlFor(routing.defaultLocale, PATH);
  return {
    title: t("meta_title"),
    description: t("meta_description"),
    metadataBase: new URL(SITE_URL),
    alternates: { canonical: urlFor(locale, PATH), languages },
    robots: { index: true, follow: true },
  };
}

export default async function DeleteAccountPage({ params }: Props) {
  const locale = resolveLocale((await params).locale);
  const t = await getTranslations({ locale, namespace: "DeleteAccount" });
  const isRtl = (RTL_LOCALES as readonly string[]).includes(locale);
  const steps = t.raw("steps") as string[];
  const deleted = t.raw("deleted_items") as string[];
  const kept = t.raw("kept_items") as string[];

  return (
    <div style={page}>
      <main style={{ maxWidth: 760, margin: "0 auto", padding: "60px 16px" }}>
        <a href={localePath(locale, "/")} style={link}>
          {isRtl ? "→" : "←"} {t("back")}
        </a>
        <h1 style={{ fontSize: 34, fontWeight: 800, color: "#f8fafc", margin: "24px 0 12px" }}>{t("title")}</h1>
        <p style={{ ...body, marginBottom: 32 }}>{t("intro")}</p>

        <section style={card} aria-labelledby="steps-h">
          <h2 id="steps-h" style={h2}>{t("steps_heading")}</h2>
          <ol style={{ ...body, paddingInlineStart: 22, margin: "0 0 12px" }}>
            {steps.map((step) => <li key={step} style={{ marginBottom: 6 }}>{step}</li>)}
          </ol>
          <p style={{ ...body, margin: "0 0 16px" }}>{t("steps_app")}</p>
          <a href={localePath(locale, "/account")} style={button} data-testid="delete-account-cta">{t("cta")}</a>
        </section>

        <section style={section} aria-labelledby="deleted-h">
          <h2 id="deleted-h" style={h2}>{t("deleted_heading")}</h2>
          <ul style={list}>{deleted.map((item) => <li key={item} style={{ marginBottom: 4 }}>{item}</li>)}</ul>
          <p style={body}>{t("timing")}</p>
        </section>

        <section style={section} aria-labelledby="kept-h">
          <h2 id="kept-h" style={h2}>{t("kept_heading")}</h2>
          <ul style={list}>{kept.map((item) => <li key={item} style={{ marginBottom: 4 }}>{item}</li>)}</ul>
        </section>

        <section style={section} aria-labelledby="subscription-h">
          <h2 id="subscription-h" style={h2}>{t("subscription_heading")}</h2>
          <p style={body}>{t("subscription_body")}</p>
        </section>

        <section style={section} aria-labelledby="help-h">
          <h2 id="help-h" style={h2}>{t("help_heading")}</h2>
          {SUPPORT_EMAIL_LIVE ? (
            <p style={body}>
              {t("help_live")}{" "}
              <a href={`mailto:${SUPPORT_EMAIL}`} style={link}>{SUPPORT_EMAIL}</a>
            </p>
          ) : (
            <p style={body} data-testid="delete-account-help-not-live">{t("help_not_live")}</p>
          )}
          <p style={body}>
            <a href={localePath(locale, "/privacy-policy")} style={link}>{t("privacy_link")}</a>
          </p>
        </section>
      </main>
    </div>
  );
}

const page: CSSProperties = {
  background: "#0f172a",
  color: "#e2e8f0",
  fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  minHeight: "100vh",
};
const body: CSSProperties = { fontSize: 16, lineHeight: 1.7, color: "#cbd5e1", margin: "0 0 12px" };
const list: CSSProperties = { ...body, paddingInlineStart: 20 };
const h2: CSSProperties = { fontSize: 20, fontWeight: 700, color: "#f8fafc", margin: "0 0 12px" };
const link: CSSProperties = { color: "#60a5fa", textDecoration: "underline" };
const section: CSSProperties = { marginTop: 32 };
const card: CSSProperties = {
  background: "#111c33",
  border: "1px solid #1e293b",
  borderRadius: 16,
  padding: 20,
};
const button: CSSProperties = {
  display: "inline-block",
  background: "#4c8dff",
  color: "#fff",
  borderRadius: 10,
  padding: "12px 18px",
  minHeight: 44,
  fontSize: 16,
  fontWeight: 600,
  textDecoration: "none",
};
