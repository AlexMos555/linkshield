/**
 * The URL the link-guard screen may open after it checked a site.
 *
 * app/shared.tsx checks ONE host — toCheckableHost(url) — and then offers
 * "Open in browser" / "Open anyway". It used to pass the raw shared string to
 * the native openInBrowser, so what opened was not what was checked:
 *   "intent://evil.tld/#Intent;…;end https://google.com" was checked as
 *   google.com and launched as an intent:// URL (another app, chosen by the
 *   attacker); "https://google.com https://evil.tld/x" was checked as
 *   google.com and opened whatever Android's Uri.parse made of the whole
 *   string. The cleanway:///shared deep link that carries the string is
 *   reachable by any app or web page, so it is attacker-shaped input.
 *
 * The rule: the answer is null, or an http(s) URL REBUILT from parsed parts
 * whose host is exactly the checked host — no userinfo, path/query/fragment
 * percent-encoded where a browser and Uri.parse could disagree. Anything the
 * parser is not sure about falls back to "https://<checked host>/": the person
 * still gets the site they were shown, just not the deep path.
 *
 * Pure (no React Native, no URL global — RN's URL polyfill does not implement
 * hostname), so scripts/test-open-url.mjs runs it under plain node. The native
 * side re-checks scheme and host (OpenUrlPolicy.kt) before it launches.
 */

/** An ASCII hostname as toCheckableHost returns it: dotted labels, punycoded. */
const HOSTNAME = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/;

/**
 * Whitespace, controls, and the backslash (which browsers read as "/" in an
 * http URL, so "https://google.com\@evil.tld" has a different host for a
 * browser than for a naive parser). Any of these means "more than one thing
 * or a smuggling attempt" — never pass the rest through.
 */
const UNSAFE = /[\s\u0000-\u001f\u007f-\u009f\\]/;

/** Kept as-is in path/query/fragment: RFC 3986 unreserved + sub-delims + ":@/?". */
const KEEP = /[A-Za-z0-9\-._~!$&'()*+,;=:@/?]/;

export function browserUrlFor(
  raw: string | null | undefined,
  checkedHost: string | null | undefined,
): string | null {
  const host = (checkedHost ?? "").trim().toLowerCase();
  if (!HOSTNAME.test(host)) return null;
  const fallback = `https://${host}/`;

  const s = (raw ?? "").trim();
  if (!s || UNSAFE.test(s)) return fallback;

  // Only an explicit http(s) scheme. Authority ends at the first / ? #.
  const m = /^(https?):\/\/([^/?#]*)(.*)$/i.exec(s);
  if (!m) return fallback;
  const scheme = m[1].toLowerCase();
  const authority = m[2];

  // userinfo ("google.com@evil.tld") is where host confusion lives; the
  // checked host is the part after "@", and we rebuild without any userinfo.
  if (authority.includes("@")) return fallback;
  const am = /^([^:]*)(?::(\d{1,5}))?$/.exec(authority);
  if (!am) return fallback;
  const authHost = am[1].toLowerCase().replace(/\.+$/, "");
  if (authHost !== host) return fallback;
  let port = "";
  if (am[2] !== undefined) {
    const n = Number(am[2]);
    if (!(n >= 1 && n <= 65535)) return fallback;
    port = `:${n}`;
  }

  const rest = encodeRest(m[3]);
  if (rest === null) return fallback;
  // "https://host?q" / "https://host#f": give it the path a browser would.
  const path = rest.startsWith("/") ? rest : `/${rest}`;
  return `${scheme}://${host}${port}${path}`;
}

/**
 * Re-encode path + query + fragment character by character, so the string we
 * hand Android is plain ASCII that every parser splits the same way. An
 * existing %XX escape is kept; a stray "%" becomes %25; a second "#" becomes
 * %23. Returns null for text encodeURIComponent cannot encode (lone surrogate).
 */
function encodeRest(rest: string): string | null {
  let out = "";
  let sawHash = false;
  const chars = Array.from(rest);
  for (let i = 0; i < chars.length; i++) {
    const c = chars[i];
    if (c === "%") {
      const hex = (chars[i + 1] ?? "") + (chars[i + 2] ?? "");
      out += /^[0-9A-Fa-f]{2}$/.test(hex) ? "%" : "%25";
    } else if (c === "#") {
      out += sawHash ? "%23" : "#";
      sawHash = true;
    } else if (KEEP.test(c)) {
      out += c;
    } else {
      try {
        out += encodeURIComponent(c);
      } catch {
        return null;
      }
    }
  }
  return out;
}
