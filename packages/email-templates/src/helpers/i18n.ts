/**
 * Email i18n helper — CommonJS version that loads JSON at runtime.
 *
 * Why not ESM `import ... with { type: "json" }`:
 *   Node 18/20 don't have stable support, and we render from a script
 *   that has to run cleanly in CI without --experimental-json-modules.
 *
 * Reads from packages/i18n-strings/src/{locale}.json — the SAME source every
 * other client uses. One source of truth across product.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const I18N_DIR = path.resolve(__dirname, "../../../i18n-strings/src");

export const SUPPORTED_LOCALES = [
  "en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar",
] as const;
export type Locale = (typeof SUPPORTED_LOCALES)[number];

type LeafEntry = {
  text: string;
  placeholders?: Record<string, unknown>;
  _needs_native_review?: boolean;
};

// Cache loaded JSON so each template render doesn't hit disk
const _cache = new Map<Locale, unknown>();

function load(locale: Locale): unknown {
  const cached = _cache.get(locale);
  if (cached) return cached;
  const file = path.join(I18N_DIR, `${locale}.json`);
  const raw = fs.readFileSync(file, "utf-8");
  const parsed = JSON.parse(raw);
  _cache.set(locale, parsed);
  return parsed;
}

function resolve(locale: Locale, dottedKey: string): LeafEntry | null {
  const parts = dottedKey.split(".");
  let node: unknown = load(locale);
  for (const p of parts) {
    if (!node || typeof node !== "object") return null;
    node = (node as Record<string, unknown>)[p];
    if (node === undefined) return null;
  }
  if (node && typeof node === "object" && "text" in node) {
    return node as LeafEntry;
  }
  return null;
}

/**
 * Translate a dotted key to the given locale, with placeholder substitution.
 * Falls back to English if the locale doesn't have the key.
 *
 * Placeholders:
 *   - chrome.i18n style `$NAME$` — replaced by vars[lowercase_name]
 *   - also accepts `{{name}}` style
 *
 * Example:
 *   t("ru", "email.receipt.next_billing", { date: "2026-05-16" })
 *   → "Следующее списание: 2026-05-16"
 */
export function t(
  locale: Locale,
  dottedKey: string,
  vars: Record<string, string | number> = {},
): string {
  let entry = resolve(locale, dottedKey);
  if (!entry) {
    entry = resolve("en", dottedKey);
    if (!entry) {
      throw new Error(`i18n key missing in EN source: ${dottedKey}`);
    }
  }
  let text = entry.text;
  for (const [key, value] of Object.entries(vars)) {
    const upper = key.toUpperCase();
    text = text.split(`$${upper}$`).join(String(value));
    text = text.split(`{{${key}}}`).join(String(value));
  }
  return text;
}

export const RTL_LOCALES: readonly Locale[] = ["ar"] as const;

export function isRTL(locale: Locale): boolean {
  return RTL_LOCALES.includes(locale);
}
