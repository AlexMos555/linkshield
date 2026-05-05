import type { Metadata } from "next";

import { routing, type Locale } from "@/i18n/routing";

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

  const languages: Record<string, string> = {};
  for (const loc of routing.locales) languages[loc] = urlFor(loc as Locale);
  languages["x-default"] = urlFor(routing.defaultLocale);

  return {
    title: "Join a Cleanway family",
    description:
      "You've been invited to a Cleanway family group. Install Cleanway and use the invite code to join.",
    metadataBase: new URL(SITE_URL),
    alternates: { canonical: urlFor(safeLocale), languages },
    // Personal landing — never index. Hash params don't reach the server,
    // but we still don't want this URL to look generically search-discoverable.
    robots: { index: false, follow: false },
  };
}

export default function FamilyJoinPage() {
  return <JoinClient />;
}
