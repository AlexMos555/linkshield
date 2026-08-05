import { toASCII } from "punycode";

/**
 * Reduce anything a user can hand us — a typed name, a pasted link, a shared
 * string, a QR payload — to the bare hostname we are allowed to send.
 *
 * Two separate defects made this necessary, and each screen had its own copy of
 * the parsing:
 *
 * 1. PRIVACY. The old parsers cut at the first "/" only. A URL whose secret
 *    rides in the query or fragment with no preceding slash — evil.com?token=…,
 *    evil.com#access_token=… — kept it, as did user:password@evil.com. All of
 *    that was sent to the server under an on-screen promise that reads "Only
 *    the website name was sent — nothing else."
 *
 * 2. DETECTION. Unicode hostnames were passed through as typed. Verified
 *    against production: "пaypal.com" (Cyrillic п) returns HTTP 400 — no
 *    verdict at all — while its punycode form xn--aypal-oye.com scores 81 and
 *    is called dangerous with five signals. A homograph link, the most classic
 *    attack this product exists to catch, silently got no answer.
 *
 * Returns null when there is no plausible hostname, so callers can show their
 * "that doesn't look like a link" copy instead of shipping junk to the API.
 */
export function toCheckableHost(input: string): string | null {
  let s = (input || "").trim();
  if (!s) return null;

  // A shared message is often "look at this scam https://evil.tld/x" — take the
  // first token that looks like a link rather than the whole sentence.
  //
  // Deliberately split on whitespace instead of matching with a \b anchor: in a
  // non-unicode regex, \b treats every non-ASCII letter as a non-word
  // character, so "пaypal.com" matched starting AFTER the Cyrillic п and the
  // function happily returned "aypal.com" — a different, real domain. Silently
  // rewriting a homograph into the thing it imitates is worse than not
  // handling it at all. Caught by the table in host.test.ts.
  const token = s.split(/\s+/).find((part) => part.includes("."));
  if (token) s = token;

  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");

  // Authority ends at the first delimiter. Cutting on all three is the whole
  // point: "/" alone left query and fragment attached.
  const authority = s.split(/[/?#]/, 1)[0];
  if (!authority) return null;

  // Drop userinfo. The last "@" wins — a password may legitimately contain one.
  const at = authority.lastIndexOf("@");
  let host = at >= 0 ? authority.slice(at + 1) : authority;

  // Strip the port, but leave a bare IPv6 literal alone.
  if (!host.startsWith("[")) host = host.split(":", 1)[0];
  host = host.replace(/\.+$/, "").toLowerCase();
  if (!host || !host.includes(".")) return null;

  // Nothing but a hostname may survive.
  if (/[^a-z0-9.\-¡-￿]/i.test(host)) return null;

  try {
    const ascii = toASCII(host);
    return ascii && ascii.includes(".") ? ascii : null;
  } catch {
    return null;
  }
}
