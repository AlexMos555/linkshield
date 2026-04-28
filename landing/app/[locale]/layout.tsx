import type { Metadata, Viewport } from "next";
import { NextIntlClientProvider, hasLocale } from "next-intl";

import ServiceWorkerRegistration from "@/components/ServiceWorkerRegistration";
import { setRequestLocale } from "next-intl/server";
import { notFound } from "next/navigation";
import { routing, RTL_LOCALES, type Locale } from "@/i18n/routing";

export const metadata: Metadata = {
  metadataBase: new URL("https://cleanway.ai"),
  manifest: "/manifest.webmanifest",
  title: "Cleanway — Protection from scam links",
  description:
    "Automatic scam link detection with plain-language explanations. 91% detection rate, 10 languages, your browsing data stays on your device.",
  keywords: [
    "phishing protection",
    "scam detection",
    "link checker",
    "privacy audit",
    "anti-fraud",
    "browser extension",
    "safe browsing",
  ],
  openGraph: {
    title: "Cleanway — Protection from scam links",
    description: "Your browsing data lives only on your device.",
    siteName: "Cleanway",
    type: "website",
    url: "https://cleanway.ai",
  },
  twitter: {
    card: "summary_large_image",
    title: "Cleanway — Protection from scam links",
    description: "91% scam detection. 10 languages. Zero data stored.",
    site: "@cleanwayai",
  },
};

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
