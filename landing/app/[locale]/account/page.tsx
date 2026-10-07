import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";

import { routing, type Locale } from "@/i18n/routing";

import AccountClient from "./AccountClient";

const SITE_URL = "https://cleanway.ai";

function resolveLocale(locale: string): Locale {
  return (routing.locales as readonly string[]).includes(locale) ? (locale as Locale) : routing.defaultLocale;
}

function urlFor(locale: Locale): string {
  return locale === routing.defaultLocale ? `${SITE_URL}/account` : `${SITE_URL}/${locale}/account`;
}

type Props = { params: Promise<{ locale: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const locale = resolveLocale((await params).locale);
  const t = await getTranslations({ locale, namespace: "Account" });
  return {
    title: t("page_title"),
    description: t("page_meta_description"),
    metadataBase: new URL(SITE_URL),
    alternates: { canonical: urlFor(locale) },
    // A personal page: nothing for a search engine here.
    robots: { index: false, follow: false },
  };
}

/**
 * /account — the signed-in person's plan and linked devices, with unlink,
 * sign out and delete account. Signed in through the same email code /
 * magic link as /signup (Supabase session in cookies); the plan and devices
 * come from the API (GET /api/v1/me/entitlement) in the client component.
 */
export default async function AccountPage({ params }: Props) {
  const locale = resolveLocale((await params).locale);
  const t = await getTranslations({ locale, namespace: "Account" });
  return (
    <div
      style={{
        background: "#0f172a",
        color: "#e2e8f0",
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        minHeight: "100vh",
      }}
    >
      <nav style={{ background: "#0f172af0", borderBottom: "1px solid #1e293b", padding: "14px 16px" }}>
        <div style={{ maxWidth: 720, margin: "0 auto" }}>
          <a href={locale === routing.defaultLocale ? "/" : `/${locale}`}
             style={{ color: "#f8fafc", textDecoration: "none", fontWeight: 800, fontSize: 20 }}>
            {t("brand")}
          </a>
        </div>
      </nav>
      <main style={{ maxWidth: 720, margin: "0 auto", padding: "40px 16px 80px" }}>
        <h1 style={{ fontSize: 28, fontWeight: 800, color: "#f8fafc", margin: "0 0 24px" }}>{t("heading")}</h1>
        <AccountClient />
      </main>
    </div>
  );
}
