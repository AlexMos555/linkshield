/**
 * One route param as a plain string.
 *
 * expo-router hands back `string[]` for a repeated query param —
 * cleanway:///shared?url=a&url=b — whatever the screen's type parameter says.
 * The cleanway:// scheme is public: any app or web page can open such a link.
 * A screen that called a string method on the array threw during render, and
 * a render error with no boundary is fatal in release builds (the Android
 * shield runs in the same process and went down with it).
 *
 * The first value of a repeated param, "" for a missing one or anything that
 * is not a string. Pinned in scripts/test-host-parser.mjs.
 */
export function firstValue(v: unknown): string {
  const value = Array.isArray(v) ? v[0] : v;
  return typeof value === "string" ? value : "";
}
