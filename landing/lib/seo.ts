import { routing } from "@/i18n/routing";

/**
 * URLs, hreflang and share images for page metadata — one place, so every page
 * says the same thing to search engines.
 *
 * Before this, each page built its own: the home page pointed its canonical at
 * /ru/ (which 308-redirects to /ru, so Google saw a canonical that is not a
 * page), /android and /support had no x-default, /check had no canonical at
 * all, and any page with its own openGraph block lost the share image.
 */
export const SITE_URL = "https://cleanway.ai";

/**
 * The wordless brand card (lib/og-card.tsx). It is the same picture in every
 * language on purpose — the localized title and description carry the words —
 * so every locale can point at the one route. Served at /og.png
 * (app/og.png/route.ts): /opengraph-image went through the locale middleware
 * and answered 307 to a bot sending a non-English Accept-Language. The locale
 * layout names it too, for pages without an openGraph block of their own.
 */
export const DEFAULT_OG_IMAGE = {
  url: "/og.png",
  width: 1200,
  height: 630,
  alt: "Cleanway",
} as const;

/**
 * Absolute URL of a path in a locale, exactly as the site serves it: English
 * at the apex, every other locale prefixed, and no trailing slash anywhere
 * (Next redirects /ru/ → /ru, so a slash would name a redirect, not a page).
 */
export function localeUrl(locale: string, path: string): string {
  const clean = path === "" || path === "/" ? "" : path.startsWith("/") ? path : `/${path}`;
  if (locale === routing.defaultLocale) return `${SITE_URL}${clean}`;
  return `${SITE_URL}/${locale}${clean}`;
}

/** hreflang map for a path: every locale plus x-default (English). */
export function hreflangFor(path: string): Record<string, string> {
  const languages: Record<string, string> = {};
  for (const locale of routing.locales) languages[locale] = localeUrl(locale, path);
  languages["x-default"] = localeUrl(routing.defaultLocale, path);
  return languages;
}

/** `alternates` for generateMetadata: self canonical + the full hreflang set. */
export function localeAlternates(locale: string, path: string): { canonical: string; languages: Record<string, string> } {
  return { canonical: localeUrl(locale, path), languages: hreflangFor(path) };
}
