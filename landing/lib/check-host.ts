/**
 * The only thing the website check may send anywhere: a site's name.
 *
 * The check form used to submit whatever was typed as `?q=`, and only an input
 * starting with "http" was cut down to its host. A pasted scheme-less link —
 * `bank-verify.ru/confirm?email=me@x.ru` — reached our server whole, became an
 * indexable /check/<everything> page and was forwarded to the API, while the
 * hero, the FAQ and the privacy policy all say "only the site's name".
 *
 * `toCheckHost` reduces any input to the lowercase ASCII host (IDNs become
 * punycode, which is what the API validates) or returns null when there is no
 * plausible site name in it. The form runs it in the browser before anything
 * is sent; the pages run it again on whatever reaches them by URL.
 */

/** One DNS label: letters, digits and inner hyphens (RFC 1035, punycode included). */
const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const MAX_HOST_LENGTH = 253;
const HAS_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;

export function toCheckHost(input: string | null | undefined): string | null {
  const text = (input ?? "").trim();
  if (!text || /\s/.test(text)) return null;
  let host: string;
  try {
    host = new URL(HAS_SCHEME.test(text) ? text : `http://${text}`).hostname;
  } catch {
    return null;
  }
  host = host.replace(/\.$/, "");
  if (host.length > MAX_HOST_LENGTH) return null;
  const labels = host.split(".");
  return labels.length >= 2 && labels.every((label) => LABEL.test(label)) ? host : null;
}

/**
 * Host from a `[domain]` route segment. Malformed percent-encoding throws in
 * decodeURIComponent; that is "no host", not a 500.
 */
export function hostFromSegment(segment: string): string | null {
  try {
    return toCheckHost(decodeURIComponent(segment));
  } catch {
    return null;
  }
}
