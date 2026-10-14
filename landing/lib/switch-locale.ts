/**
 * Where the language switcher navigates: the current page in another locale.
 *
 * With `localePrefix: "as-needed"` English lives at the apex ("/check") and
 * every other locale is prefixed ("/es/check"). The switcher swaps (or adds,
 * or drops) that first segment and keeps the rest of the path.
 *
 * The result is handed to window.location.assign, so it must never leave the
 * site: the requested locale must be one we serve (a <select> value is DOM
 * text a script on the page could change), and the path is resolved against
 * the current origin and rejected if it lands anywhere else — a segment like
 * "\evil.example" would otherwise turn "/" + segment into a protocol-relative
 * "//evil.example". Pure and dependency-free so a node script can test it.
 *
 * Returns the same-origin path, or null when nothing should happen.
 */
export function switchLocaleHref(options: {
  pathname: string;
  current: string;
  next: string;
  locales: readonly string[];
  defaultLocale: string;
  origin: string;
}): string | null {
  const { pathname, current, next, locales, defaultLocale, origin } = options;
  if (next === current || !locales.includes(next)) return null;

  const segments = pathname.split("/").filter(Boolean);
  const hasLocaleSegment = segments.length > 0 && locales.includes(segments[0]);
  const rest = hasLocaleSegment ? segments.slice(1) : segments;
  const parts = next === defaultLocale ? rest : [next, ...rest];
  const path = "/" + parts.join("/");

  let target: URL;
  let base: URL;
  try {
    base = new URL(origin);
    target = new URL(path, base);
  } catch {
    return null;
  }
  if (target.origin !== base.origin) return null;
  return target.pathname;
}
