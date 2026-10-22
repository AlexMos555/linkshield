import type { Metadata } from "next";
import { getTranslations } from "next-intl/server";

import { routing, type Locale } from "@/i18n/routing";
import { DEFAULT_OG_IMAGE } from "@/lib/seo";

import JoinClient from "./JoinClient";

const SITE_URL = "https://cleanway.ai";

function urlFor(locale: Locale | string): string {
  return locale === routing.defaultLocale
    ? `${SITE_URL}/family/join`
    : `${SITE_URL}/${locale}/family/join`;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const { locale } = await params;
  const isLocaleKnown = (routing.locales as readonly string[]).includes(locale);
  const safeLocale: Locale = isLocaleKnown ? (locale as Locale) : routing.defaultLocale;
  const t = await getTranslations({ locale: safeLocale, namespace: "FamilyJoin" });

  const languages: Record<string, string> = {};
  for (const loc of routing.locales) languages[loc] = urlFor(loc as Locale);
  languages["x-default"] = urlFor(routing.defaultLocale);

  const title = t("meta_title");
  const description = t("meta_description");
  const canonical = urlFor(safeLocale);

  return {
    title,
    description,
    metadataBase: new URL(SITE_URL),
    alternates: { canonical, languages },
    // The invite travels by messenger: its preview is in the reader's
    // language. og:url never carries the #code=…&pin=… fragment.
    openGraph: { title, description, url: canonical, siteName: "Cleanway", type: "website", locale: safeLocale, images: [DEFAULT_OG_IMAGE] },
    twitter: { card: "summary_large_image", title, description, images: [DEFAULT_OG_IMAGE.url] },
    // Personal landing — never index. Hash params don't reach the server,
    // but we still don't want this URL to look generically search-discoverable.
    robots: { index: false, follow: false },
  };
}

export default function FamilyJoinPage() {
  return <JoinClient />;
}
