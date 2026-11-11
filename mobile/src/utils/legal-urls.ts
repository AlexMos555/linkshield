/**
 * The legal pages the app links to: from sign-in (app/auth.tsx, where the
 * email address is collected — GDPR Art. 13 wants the policy at that point),
 * the paywall (App Store Review 3.1.2) and Settings. One place, so the three
 * cannot drift apart.
 *
 * Each opens in the app's language: the site has every page under
 * /<locale>/ for the same ten languages (landing/i18n/routing.ts; English has
 * no prefix). A Russian screen used to open the English Terms (Galaxy,
 * 2026-11-11). A language the site does not have opens English.
 */
const SITE = "https://cleanway.ai";
/** landing/i18n/routing.ts `locales`, minus the unprefixed default (en). scripts/test-device-fixes.mjs pins the pair. */
export const SITE_LOCALES: readonly string[] = ["es", "hi", "pt", "ru", "ar", "fr", "de", "it", "id"];

/** "/ru" for a language the site has under a prefix, "" for English and anything else. */
function localePrefix(language: string | null | undefined): string {
  const base = (language ?? "").toLowerCase().split(/[-_]/)[0];
  return SITE_LOCALES.includes(base) ? `/${base}` : "";
}

export function privacyPolicyUrl(language: string | null | undefined): string {
  return `${SITE}${localePrefix(language)}/privacy-policy`;
}

export function termsUrl(language: string | null | undefined): string {
  return `${SITE}${localePrefix(language)}/terms`;
}

/**
 * Settings → About → Data sources: the credit the open data asks for (the
 * popular-site ranking, the Android shield's veto list among its copies, is
 * adapted from the Majestic Million, CC BY 3.0, and the Chrome UX Report,
 * CC BY 4.0). The section's id is DATA_SOURCES_ANCHOR in
 * landing/lib/data-sources.ts.
 */
export const DATA_SOURCES_URL = "https://cleanway.ai/transparency/methodology#data-sources";
