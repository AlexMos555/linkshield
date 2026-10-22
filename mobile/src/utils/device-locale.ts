/**
 * The language the app starts in: the first of the phone's preferred
 * languages (expo-localization's getLocales(), in the phone's order) that the
 * app has. Null when it has none of them — the caller then uses English.
 *
 * Only the first preferred language used to be read, so a phone set to
 * Ukrainian, Kazakh or Belarusian with Russian second opened in English.
 * Whether those languages should fall back to Russian on their own is a
 * product decision, not made here.
 *
 * Pure (no expo), so scripts/test-reason-label.mjs runs it under plain node.
 */

/**
 * Android reports a few languages by their pre-1989 ISO codes
 * (java.util.Locale.getLanguage()): Indonesian comes in as "in", which the
 * app's "id" never matched.
 */
const LEGACY_CODES: Readonly<Record<string, string>> = { in: "id" };

export function firstSupportedLocale<L extends string>(
  deviceLocales: readonly { languageCode?: string | null }[] | null | undefined,
  supported: readonly L[],
): L | null {
  for (const locale of deviceLocales ?? []) {
    const raw = locale?.languageCode?.toLowerCase();
    if (!raw) continue;
    const code = LEGACY_CODES[raw] ?? raw;
    if ((supported as readonly string[]).includes(code)) return code as L;
  }
  return null;
}
