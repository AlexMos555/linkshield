import { domainToUnicode } from "node:url";

/**
 * How a checked site's name is shown on the scorecard (server only).
 *
 * The check works on the ASCII form — президент.рф arrives as
 * xn--d1abbgf6aiiy.xn--p1ai, which is what the API validates — but nobody
 * recognises their own government's site in punycode. So a name under a
 * non-Latin top-level zone (.рф, .рус, .москва…) written entirely in
 * non-Latin letters is shown the way people type it.
 *
 * Everything else keeps its ASCII form, as browsers do: "аррӏе.com" in
 * Cyrillic letters would read as apple.com, and a look-alike must never be
 * dressed up as the real thing on a page that judges it.
 */
const NON_ASCII = /[^\x00-\x7F]/;
const LATIN = /[a-z]/i;

export function displayHost(host: string): string {
  const unicode = domainToUnicode(host);
  if (!unicode || unicode === host) return host;
  const labels = unicode.split(".");
  const tld = labels[labels.length - 1];
  const readable = NON_ASCII.test(tld) && labels.every((label) => label === "www" || !LATIN.test(label));
  return readable ? unicode : host;
}
