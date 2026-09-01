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

  // Payload formats that are not links at all. A QR business card or wifi
  // config contains dots and even email addresses; parsing a hostname out of
  // one and rendering a verdict for it answered a question nobody asked —
  // and shipped a stranger's mail domain to the server under the scanner's
  // "only the website name is sent" promise.
  if (/^(BEGIN:VCARD|MECARD:|WIFI:|MATMSG:|SMSTO:|geo:|tel:|mailto:)/i.test(s)) {
    return null;
  }

  // Token selection, in order of confidence:
  //  1. the first token carrying an explicit web scheme — in "check file.pdf
  //     from https://evil.tld/x" the link is the thing to check, but plain
  //     first-dot-token-wins picked "file.pdf" and the real scam was never
  //     looked at;
  //  2. otherwise the first dot-containing token ("evil.com might be fake").
  //
  // Split on whitespace, never \b: in a non-unicode regex \b treats every
  // non-ASCII letter as a non-word character, so "пaypal.com" matched from
  // AFTER the Cyrillic п and this function returned "aypal.com" — a
  // different, real domain. Caught by the table in test-host-parser.mjs.
  const tokens = s.split(/\s+/);
  const token =
    tokens.find((part) => /^https?:\/\//i.test(part)) ??
    tokens.find((part) => part.includes("."));
  if (token) s = token;

  // A link pasted mid-sentence drags its punctuation along: "evil.com," or
  // "(see evil.com)". Strip wrapping/trailing punctuation before parsing —
  // it used to fail the hostname character check and the app answered
  // "that doesn't look like a link" to a message that plainly contained one.
  s = s.replace(/^[(<\["'«»]+/, "").replace(/[)>\]"'«».,;:!?…]+$/, "");

  // A non-web scheme that survived the guards above (odd casing, new
  // formats): a hostname extracted from it would answer the wrong question.
  const scheme = s.match(/^([a-z][a-z0-9+.-]*):\/\//i);
  if (scheme && !/^https?$/i.test(scheme[1])) return null;
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
