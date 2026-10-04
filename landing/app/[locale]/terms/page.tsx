/**
 * Terms of use, in the reader's language.
 *
 * The previous page was English-only and promised things the product does not
 * do (a 14-day trial on every plan, App Store / Google Play billing, "your
 * browsing data stays on your device"). This version states only what is
 * true today and what we explicitly do NOT promise. A lawyer still has to
 * review it (governing law and the operator's details are not filled in).
 */
import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";

import { LegalDocument, type LegalSection } from "@/components/LegalDocument";
import { routing, RTL_LOCALES, type Locale } from "@/i18n/routing";
import { replaceSection } from "@/lib/billing";
import { BILLING_ENABLED, BILLING_TERMS } from "@/lib/billing-config";
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
  const t = await getTranslations({ locale: safeLocale, namespace: "Terms" });
  const canonical = urlFor(safeLocale, "/terms");

  const languages: Record<string, string> = {};
  for (const loc of routing.locales) languages[loc] = urlFor(loc as Locale, "/terms");
  languages["x-default"] = urlFor(routing.defaultLocale, "/terms");

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

const linkStyle: React.CSSProperties = { color: "#60a5fa" };

/** The subscription section with the lapse-policy sentence as its last paragraph. */
function billingSection(section: LegalSection, lapseSentence: string): LegalSection {
  return { ...section, paragraphs: [...(section.paragraphs ?? []), lapseSentence] };
}

export default async function Terms({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const safeLocale = resolveLocale((await params).locale);
  const t = await getTranslations({ locale: safeLocale, namespace: "Terms" });
  const currentSections = t.raw("sections") as LegalSection[];
  // With the operator-billed subscription on, the "no paid plans in Russia,
  // Stripe elsewhere" section gives way to the subscription terms; what
  // happens after a failed payment follows the configured lapse policy.
  const sections = BILLING_ENABLED
    ? replaceSection(currentSections, "payments", billingSection(t.raw("billing.section") as LegalSection, t(`billing.lapse_${BILLING_TERMS.lapsePolicy}`)))
    : currentSections;
  const isRtl = (RTL_LOCALES as readonly string[]).includes(safeLocale);

  const privacyLink = (
    <p style={{ margin: 0 }}>
      <a href={localePath(safeLocale, "/privacy-policy")} style={linkStyle}>{t("privacy_link")}</a>
    </p>
  );
  const contact = SUPPORT_EMAIL_LIVE ? (
    <p style={{ margin: 0 }}>
      {t("contact_live")}{" "}
      <a href={`mailto:${SUPPORT_EMAIL}`} style={linkStyle}>{SUPPORT_EMAIL}</a>
    </p>
  ) : (
    <p style={{ margin: 0 }}>
      {t("contact_not_live")}{" "}
      <a href={localePath(safeLocale, "/support")} style={linkStyle}>{t("support_link")}</a>
    </p>
  );

  return (
    <LegalDocument
      backHref={localePath(safeLocale, "/")}
      backLabel={t("back")}
      backArrow={isRtl ? "→" : "←"}
      title={t("title")}
      updated={t("updated")}
      sections={sections}
      slots={{ privacy: privacyLink, contact }}
    />
  );
}
