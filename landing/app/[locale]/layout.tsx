import type { Metadata } from "next";
import { NextIntlClientProvider, hasLocale } from "next-intl";
import { setRequestLocale } from "next-intl/server";
import { notFound } from "next/navigation";
import { routing, RTL_LOCALES, type Locale } from "@/i18n/routing";

export const metadata: Metadata = {
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
  },
  twitter: {
    card: "summary_large_image",
    title: "Cleanway — Protection from scam links",
    description: "91% scam detection. 10 languages. Zero data stored.",
  },
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
        <NextIntlClientProvider>{children}</NextIntlClientProvider>
      </body>
    </html>
  );
}
