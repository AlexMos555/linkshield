import type { Metadata, Viewport } from "next";
import { NextIntlClientProvider, hasLocale } from "next-intl";

import ServiceWorkerRegistration from "@/components/ServiceWorkerRegistration";
import { getTranslations, setRequestLocale } from "next-intl/server";
import { notFound } from "next/navigation";
import { routing, RTL_LOCALES, type Locale } from "@/i18n/routing";

/**
 * Site-wide default metadata, in the page's language.
 *
 * Pages without their own openGraph block (support, terms, the 404...) fall
 * back to this, and that fallback is what Telegram and WhatsApp show when a
 * link is shared. It used to be English everywhere and promised "your
 * browsing data lives only on your device" — untrue, since checked site names
 * reach our server. Keep it to what the product does today.
 */
export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const { locale } = await params;
  const safeLocale: Locale = hasLocale(routing.locales, locale) ? locale : routing.defaultLocale;
  const t = await getTranslations({ locale: safeLocale, namespace: "Meta" });
  const title = t("title");
  const description = t("description");

  return {
    metadataBase: new URL("https://cleanway.ai"),
    manifest: "/manifest.webmanifest",
    title,
    description,
    keywords: [
      "phishing protection",
      "scam detection",
      "link checker",
      "anti-fraud",
      "Android",
      "safe browsing",
    ],
    openGraph: {
      title,
      description,
      siteName: "Cleanway",
      type: "website",
      locale: safeLocale,
      // Per-page generateMetadata overrides url with the locale-correct canonical.
      // Omit url here so a non-default-locale page that forgets to override
      // doesn't inherit the apex URL and leak a wrong canonical to OG consumers.
    },
    twitter: {
      card: "summary_large_image",
      title,
      description,
      site: "@cleanwayai",
    },
  };
}

// Viewport / theme color — Next 15 wants this as a separate export so it
// can be served as a meta tag without re-rendering the page metadata.
export const viewport: Viewport = {
  themeColor: "#0f172a",
  colorScheme: "dark",
  width: "device-width",
  initialScale: 1,
};

export function generateStaticParams() {
  return routing.locales.map((locale) => ({ locale }));
}

interface LocaleLayoutProps {
  children: React.ReactNode;
  params: Promise<{ locale: string }>;
}

export default async function LocaleLayout({ children, params }: LocaleLayoutProps) {
  const { locale } = await params;

  if (!hasLocale(routing.locales, locale)) {
    notFound();
  }

  // Enable static rendering for this locale
  setRequestLocale(locale as Locale);

  const dir = RTL_LOCALES.includes(locale as Locale) ? "rtl" : "ltr";

  return (
    <html lang={locale} dir={dir}>
      <body style={{ margin: 0 }}>
        <ServiceWorkerRegistration />
        <NextIntlClientProvider>{children}</NextIntlClientProvider>
      </body>
    </html>
  );
}
