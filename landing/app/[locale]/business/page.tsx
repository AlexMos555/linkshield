/**
 * /business — Cleanway for teams, in the reader's language.
 *
 * The previous page was English-only and sold a product that does not exist:
 * "$3.99/user/month", a 14-day trial, SSO, an org dashboard, an email proxy
 * and phishing simulations (api/routers/org.py only queues a stub), plus a
 * priced comparison with a named competitor. Since 2026-10 there is one plan
 * that counts devices (docs/ACCOUNTS_BILLING_PLAN.md §5), so a team buys the
 * same plan; prices live on /pricing, which reads them from the API. This
 * page carries no price at all (scripts/check-landing-claims.py forbids a
 * hand-written one in landing.business) and says plainly what Cleanway does
 * not do for a company.
 */
import type { CSSProperties } from "react";
import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";

import { routing, type Locale } from "@/i18n/routing";
import { localePath } from "@/lib/locale-path";
import { SUPPORT_EMAIL, SUPPORT_EMAIL_LIVE } from "@/lib/support";

const SITE_URL = "https://cleanway.ai";

function urlFor(locale: Locale | string, path: string): string {
  return locale === routing.defaultLocale ? `${SITE_URL}${path}` : `${SITE_URL}/${locale}${path}`;
}

function resolveLocale(locale: string): Locale {
  return (routing.locales as readonly string[]).includes(locale) ? (locale as Locale) : routing.defaultLocale;
}

type Props = { params: Promise<{ locale: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const safeLocale = resolveLocale((await params).locale);
  const t = await getTranslations({ locale: safeLocale, namespace: "Business" });
  const canonical = urlFor(safeLocale, "/business");

  const languages: Record<string, string> = {};
  for (const loc of routing.locales) languages[loc] = urlFor(loc as Locale, "/business");
  languages["x-default"] = urlFor(routing.defaultLocale, "/business");

  const title = t("meta_title");
  const description = t("meta_description");

  return {
    title,
    description,
    metadataBase: new URL(SITE_URL),
    alternates: { canonical, languages },
    openGraph: { title, description, url: canonical, siteName: "Cleanway", type: "website", locale: safeLocale },
    twitter: { card: "summary", title, description, site: "@cleanwayai" },
    robots: { index: true, follow: true },
  };
}

export default async function BusinessPage({ params }: Props) {
  const locale = resolveLocale((await params).locale);
  const t = await getTranslations({ locale, namespace: "Business" });
  const how = t.raw("how_items") as string[];

  return (
    <div style={page}>
      <nav style={{ background: "#0f172af0", borderBottom: "1px solid #1e293b", padding: "14px 16px" }}>
        <div style={{ maxWidth: 900, margin: "0 auto" }}>
          <a href={localePath(locale, "/")} style={{ color: "#f8fafc", textDecoration: "none", fontWeight: 800, fontSize: 20 }}>
            {t("brand")}
          </a>
        </div>
      </nav>

      <main style={{ maxWidth: 820, margin: "0 auto", padding: "56px 16px 80px" }}>
        <div style={{ textAlign: "center", marginBottom: 40 }}>
          <div style={badge}>{t("badge")}</div>
          <h1 style={{ fontSize: 36, fontWeight: 800, color: "#f8fafc", lineHeight: 1.2, margin: "0 0 16px" }}>{t("title")}</h1>
          <p style={{ ...body, fontSize: 18, maxWidth: 640, margin: "0 auto" }}>{t("subtitle")}</p>
        </div>

        <section style={card} aria-labelledby="how-h">
          <h2 id="how-h" style={h2}>{t("how_heading")}</h2>
          <ol style={{ ...body, paddingInlineStart: 22, margin: 0 }}>
            {how.map((item) => <li key={item} style={{ marginBottom: 8 }}>{item}</li>)}
          </ol>
        </section>

        <section style={card} aria-labelledby="price-h" data-testid="business-pricing">
          <h2 id="price-h" style={h2}>{t("pricing_heading")}</h2>
          <p style={body}>{t("pricing_body")}</p>
          <a href={localePath(locale, "/pricing")} style={button}>{t("pricing_cta")}</a>
        </section>

        <section style={card} aria-labelledby="contact-h">
          <h2 id="contact-h" style={h2}>{t("contact_heading")}</h2>
          {SUPPORT_EMAIL_LIVE ? (
            <p style={body}>
              {t("contact_live")}{" "}
              <a href={`mailto:${SUPPORT_EMAIL}`} style={{ color: "#60a5fa" }}>{SUPPORT_EMAIL}</a>
            </p>
          ) : (
            <p style={body} data-testid="business-contact-not-live">{t("contact_not_live")}</p>
          )}
        </section>

        <section style={card} aria-labelledby="honest-h">
          <h2 id="honest-h" style={h2}>{t("honest_heading")}</h2>
          <p style={body}>{t("honest_body")}</p>
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
const h2: CSSProperties = { fontSize: 20, fontWeight: 700, color: "#f8fafc", margin: "0 0 12px" };
const card: CSSProperties = {
  background: "#111c33",
  border: "1px solid #1e293b",
  borderRadius: 16,
  padding: 20,
  marginBottom: 20,
};
const badge: CSSProperties = {
  display: "inline-block",
  background: "#3b82f620",
  color: "#93c5fd",
  border: "1px solid #3b82f640",
  padding: "6px 16px",
  borderRadius: 20,
  fontSize: 14,
  fontWeight: 600,
  marginBottom: 20,
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
