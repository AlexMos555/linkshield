/**
 * JSON for an inline `<script type="application/ld+json">` block.
 *
 * JSON.stringify leaves `<`, `>` and `&` alone, so any string in the object
 * that holds "</script>" closes the tag and the rest is parsed as HTML. The
 * audit pages once built their JSON-LD from the URL's [domain] segment, which
 * made that a reflected XSS. Escaping them as < / > / & keeps
 * the JSON identical to a parser while the HTML tokenizer never sees a tag.
 * U+2028/U+2029 are escaped too: valid in JSON, line terminators in old JS.
 *
 * Every dangerouslySetInnerHTML JSON-LD block goes through this
 * (scripts/test-landing-honesty.mjs fails on a bare JSON.stringify).
 */
const UNSAFE = /[<>&\u2028\u2029]/g;
const ESCAPES: Record<string, string> = {
  "<": "\\u003c",
  ">": "\\u003e",
  "&": "\\u0026",
  "\u2028": "\\u2028",
  "\u2029": "\\u2029",
};

export function safeJsonLd(value: unknown): string {
  return (JSON.stringify(value) ?? "null").replace(UNSAFE, (char) => ESCAPES[char]);
}
