/**
 * The message namespaces the browser actually needs.
 *
 * `<NextIntlClientProvider>` without a `messages` prop serialises EVERY
 * message into every page. Once the privacy policy, terms and methodology
 * moved into the locale files, that was ~50 KB of legal text riding on
 * /ru/android — the page elderly Tele2 subscribers open on mobile data.
 *
 * Server components read their strings on the server; only client components
 * ("use client" + useTranslations) need theirs shipped. This is that list.
 * scripts/test-landing-honesty.mjs scans every client component and fails if
 * one reads a namespace missing here — otherwise it would render raw keys.
 */
export const CLIENT_NAMESPACES = [
  "Account",
  "AccountRestore",
  "Check",
  "LanguageSwitcher",
  "Nav",
  "Pricing",
  "Signup",
] as const;

export function pickClientMessages<T extends Record<string, unknown>>(messages: T): Partial<T> {
  return Object.fromEntries(
    Object.entries(messages).filter(([namespace]) => (CLIENT_NAMESPACES as readonly string[]).includes(namespace)),
  ) as Partial<T>;
}
