import { routing } from "@/i18n/routing";

/**
 * In-site link for a locale. With `localePrefix: "as-needed"` English lives at
 * the apex and every other locale is prefixed: ("ru", "/support") → "/ru/support".
 *
 * A bare "/support" on a Russian page still works, but only via a middleware
 * redirect that guesses the language from cookies and Accept-Language — and a
 * wrong guess drops a Russian reader onto the English page.
 */
export function localePath(locale: string, path: string): string {
  const clean = path.startsWith("/") ? path : `/${path}`;
  if (locale === routing.defaultLocale) return clean;
  return clean === "/" ? `/${locale}` : `/${locale}${clean}`;
}
