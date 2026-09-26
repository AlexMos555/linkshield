/**
 * Privacy policy, in the reader's language.
 *
 * Grounded in docs/PRIVACY.md, which is written against the code: the VPN-based
 * DNS shield and what it sees, where lookups for unblocked sites go in the
 * released app version (scripts/check-landing-claims.py fails when
 * mobile/app.json moves on and the policy still names the old version), the
 * blocklist download, domain-only site checks and the third parties behind
 * them, the on-device message check, accounts, Family, retention. The previous page was English-only, dated May,
 * described a browser extension that isn't published, and said "your browsing
 * data lives only on your device" (report #11).
 *
 * A lawyer still has to review it against 152-FZ before it is final.
 */
import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";

import { LegalDocument, type LegalSection } from "@/components/LegalDocument";
import { routing, RTL_LOCALES, type Locale } from "@/i18n/routing";
import { localePath } from "@/lib/locale-path";
import { SUPPORT_EMAIL, SUPPORT_EMAIL_LIVE } from "@/lib/support";

const SITE_URL = "https://cleanway.ai";

function urlFor(locale: Locale | string, path: string): string {
  return locale === routing.defaultLocale ? `${SITE_URL}${path}` : `${SITE_URL}/${locale}${path}`;
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
  const t = await getTranslations({ locale: safeLocale, namespace: "PrivacyPolicy" });
  const canonical = urlFor(safeLocale, "/privacy-policy");

  const languages: Record<string, string> = {};
  for (const loc of routing.locales) languages[loc] = urlFor(loc as Locale, "/privacy-policy");
  languages["x-default"] = urlFor(routing.defaultLocale, "/privacy-policy");

  const title = t("meta_title");
  const description = t("meta_description");

  return {
    title,
    description,
    metadataBase: new URL(SITE_URL),
    alternates: { canonical, languages },
    openGraph: {
      title,
      description,
      url: canonical,
      siteName: "Cleanway",
      type: "article",
      locale: safeLocale,
    },
    twitter: {
      card: "summary",
      title,
      description,
      site: "@cleanwayai",
    },
    robots: { index: true, follow: true },
  };
}

export default async function PrivacyPolicy({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const safeLocale = resolveLocale((await params).locale);
  const t = await getTranslations({ locale: safeLocale, namespace: "PrivacyPolicy" });
  const sections = t.raw("sections") as LegalSection[];
  const isRtl = (RTL_LOCALES as readonly string[]).includes(safeLocale);

  const contact = SUPPORT_EMAIL_LIVE ? (
    <p style={{ margin: 0 }}>
      {t("contact_live")}{" "}
      <a href={`mailto:${SUPPORT_EMAIL}`} style={{ color: "#60a5fa" }}>{SUPPORT_EMAIL}</a>
    </p>
  ) : (
    <p style={{ margin: 0 }} data-testid="privacy-contact-not-live">{t("contact_not_live")}</p>
  );

  return (
    <LegalDocument
      backHref={localePath(safeLocale, "/")}
      backLabel={t("back")}
      backArrow={isRtl ? "→" : "←"}
      title={t("title")}
      updated={t("updated")}
      intro={t("intro")}
      sections={sections}
      slots={{ contact }}
    />
  );
}
