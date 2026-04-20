import { defineRouting } from "next-intl/routing";

/**
 * LinkShield supports 10 languages — see .planning/I18N_ARCHITECTURE.md
 * RTL (Arabic) handled via CSS `dir="rtl"` on locale === "ar".
 */
export const routing = defineRouting({
  locales: ["en", "es", "hi", "pt", "ru", "ar", "fr", "de", "it", "id"] as const,
  defaultLocale: "en",
  // /en not shown in URL; /ru, /es, ... prefixed
  localePrefix: "as-needed",
});

export type Locale = (typeof routing.locales)[number];

export const LOCALE_NAMES: Record<Locale, string> = {
  en: "English",
  es: "Español",
  hi: "हिन्दी",
  pt: "Português",
  ru: "Русский",
  ar: "العربية",
  fr: "Français",
  de: "Deutsch",
  it: "Italiano",
  id: "Bahasa Indonesia",
};

export const RTL_LOCALES: readonly Locale[] = ["ar"] as const;
