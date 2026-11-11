#!/usr/bin/env node
/**
 * Table test for src/utils/reason-label.ts — run with
 * `node scripts/test-reason-label.mjs`.
 *
 * The server sends each reason as an English `detail` plus a `code`; the app
 * shows the label for the code in the person's language and falls back to
 * the English detail only for a code it does not know. Review of 1.0.2 found
 * the codes the API's verdict_basis release adds — among them
 * unreachable_from_scanner, which fires on exactly the Russian bank and
 * government sites the release is for — unmapped, so a Russian screen would
 * have shown English sentences under a Russian verdict. Pinned here:
 *  - those codes (and the phone's own on_device_list) read in Russian;
 *  - every mapped code has its label in every locale, so no mapping can
 *    quietly point at a key that does not exist.
 * Google's credit (src/utils/google-advisory.ts): a verdict whose reasons
 * include Google's (`safe_browsing`, the code the API gives a Google Web Risk
 * hit) carries "Advisory provided by Google" and the learn-more links — the
 * same addresses as the extension and the website — and a verdict built on
 * other sources does not; Google's line is a suspicion in every language.
 * Also the language the app starts in (src/utils/device-locale.ts): the first
 * of the phone's preferred languages the app has. It used to read only the
 * first one, so a phone set to Ukrainian, Kazakh or Belarusian with Russian
 * second opened in English.
 * Same approach as test-host-parser.mjs: compile the files with the tree's
 * TypeScript and run them against the generated mobile/i18n/*.json.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { deepStrictEqual } from "node:assert";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const src = resolve(root, "src/utils/reason-label.ts");
const deviceLocale = resolve(root, "src/utils/device-locale.ts");
const googleAdvisory = resolve(root, "src/utils/google-advisory.ts");
const out = mkdtempSync(join(tmpdir(), "cleanway-reason-label-"));

const locales = Object.fromEntries(
  readdirSync(join(root, "i18n"))
    .filter((f) => f.endsWith(".json"))
    .map((f) => [f.slice(0, -5), JSON.parse(readFileSync(join(root, "i18n", f), "utf8"))]),
);

/** i18next's t() as reasonLabel uses it: the key's value, else defaultValue. */
const tFor = (locale) => (key, options) => locales[locale][key] ?? options?.defaultValue ?? key;

// The codes the API's verdict_basis release adds, and the one the phone adds.
const NEW_CODES = [
  "domain_not_found", "cleanway_blocklist", "unreachable_from_scanner",
  "checks_incomplete", "partial_analysis", "user_content_platform", "on_device_list",
];

try {
  execFileSync(
    "npx",
    [
      "tsc", src, deviceLocale, googleAdvisory, "--outDir", out, "--rootDir", root,
      "--module", "esnext", "--target", "es2020", "--moduleResolution", "bundler", "--skipLibCheck",
    ],
    { cwd: root, stdio: "inherit" },
  );
  const m = await import(pathToFileURL(join(out, "src/utils/reason-label.js")).href);
  const { firstSupportedLocale } = await import(pathToFileURL(join(out, "src/utils/device-locale.js")).href);
  const g = await import(pathToFileURL(join(out, "src/utils/google-advisory.js")).href);
  const en = locales.en;
  // The app's locales are the generated files (src/i18n/index.ts imports each).
  const SUPPORTED = Object.keys(locales).sort();
  /** expo-localization's getLocales(), reduced to what the picker reads. */
  const phone = (...codes) => codes.map((languageCode) => ({ languageCode }));
  const ru = tFor("ru");
  const english = "English detail from the server";

  const CASES = [
    [
      "the new API codes and the phone's list code read in Russian, never the English detail",
      () => NEW_CODES.filter((code) => m.reasonLabel({ code, detail: english }, ru) === english),
      [],
    ],
    [
      "the scanner-abroad reason says it is not a sign of danger, in Russian",
      () => m.reasonLabel({ code: "unreachable_from_scanner", detail: english }, ru).includes("не признак опасности"),
      true,
    ],
    [
      "every mapped code has its label in every locale",
      () => Object.entries(locales).flatMap(([locale, strings]) =>
        Object.values(m.CODE_TO_KEY)
          .filter((key) => !(`mobile.reason.${key}` in strings))
          .map((key) => `${locale}: mobile.reason.${key}`)),
      [],
    ],
    [
      "an unknown code still falls back to the server's own words",
      () => m.reasonLabel({ code: "some_future_code", detail: english }, ru),
      english,
    ],
    [
      "no code at all (older API builds): the detail as sent",
      () => m.reasonLabel({ detail: english }, ru),
      english,
    ],
    // --- Google's credit (Web Risk's rules for warnings) ---------------------
    [
      "a verdict with Google's reason gets the credit; one built on other sources does not",
      () => [
        g.hasGoogleAdvisory([{ code: "domain_new", detail: "x" }, { code: "safe_browsing", detail: english }]),
        g.hasGoogleAdvisory([{ code: "phishtank", detail: "x" }, { code: "multi_blocklist", detail: "x" }]),
        g.hasGoogleAdvisory([{ detail: "Flagged by Google" }]),
        g.hasGoogleAdvisory([]),
        g.hasGoogleAdvisory(undefined),
      ],
      [true, false, false, false, false],
    ],
    [
      "the credit links to the Web Risk Advisory, antiphishing.org and Google's malware page",
      () => ({ ...g.GOOGLE_ADVISORY_LINKS }),
      {
        advisory: "https://docs.cloud.google.com/web-risk/docs/advisory",
        phishing: "https://www.antiphishing.org/",
        malware: "https://developers.google.com/search/docs/advanced/security/malware",
        // The server asks Web Risk about UNWANTED_SOFTWARE too, and every
        // warning must let people learn more about its threat type.
        unwanted: "https://www.google.com/about/company/unwanted-software-policy.html",
      },
    ],
    // --- How long a verdict on Google's lists may be kept ---------------------
    // Web Risk's rules: only while Google's answer is valid. The server says
    // for how long (advisory_ttl, seconds); a Google verdict without it is
    // kept nowhere, a longer one never past the cache's own limit.
    [
      "a Google verdict is kept only as long as the server says Google's answer lives",
      () => {
        const ttl = (reasons, advisory_ttl) => g.advisoryKeepMs({ reasons, ...(advisory_ttl === undefined ? {} : { advisory_ttl }) }, 900_000);
        const google = [{ code: "safe_browsing", detail: "x" }];
        const other = [{ code: "phishtank", detail: "x" }];
        return [ttl(google, 120), ttl(google, 9999), ttl(google, undefined), ttl(google, 0), ttl(other, undefined), ttl(other, 60)];
      },
      [120_000, 900_000, 0, 0, 900_000, 60_000],
    ],
    [
      "the message-link cache keeps each answer for advisoryKeepMs, not a flat 15 minutes",
      () => {
        const code = readFileSync(resolve(root, "src/services/message-link-check.ts"), "utf8");
        return [/advisoryKeepMs\(data, CACHE_TTL_MS\)/.test(code), /Date\.now\(\) - cached\.at < CACHE_TTL_MS/.test(code)];
      },
      [true, false],
    ],
    [
      "the credit's words exist in every locale, and name Google",
      () => Object.entries(locales).flatMap(([locale, strings]) =>
        ["extension.advisory.google", "extension.advisory.learn_more", "extension.advisory.learn_phishing", "extension.advisory.learn_malware", "extension.advisory.learn_unwanted"]
          .filter((key) => typeof strings[key] !== "string" || !strings[key])
          .map((key) => `${locale}: ${key}`)
          .concat(/Google/.test(strings["extension.advisory.google"] || "") ? [] : [`${locale}: the credit does not name Google`])),
      [],
    ],
    [
      "Google's reason line is a suspicion, and never names Safe Browsing",
      () => [
        /\b(may|might|suspected|possibly)\b/i.test(en["mobile.reason.flagged_dangerous"]),
        Object.entries(locales).filter(([, strings]) => /Safe Browsing/.test(strings["mobile.reason.flagged_dangerous"])).map(([l]) => l),
      ],
      [true, []],
    ],
    [
      "the first onboarding screen says a check can be wrong both ways",
      () => [/safe site/i.test(en["mobile.onboarding.s1_desc"]), /dangerous one/i.test(en["mobile.onboarding.s1_desc"])],
      [true, true],
    ],
    // --- the language the app starts in -------------------------------------
    [
      "the app ships the 10 locales the picker is given",
      () => SUPPORTED,
      ["ar", "de", "en", "es", "fr", "hi", "id", "it", "pt", "ru"],
    ],
    [
      "Russian second after a language the app lacks: Russian, not English",
      () => [phone("uk", "ru"), phone("kk", "ru"), phone("be", "ru", "en")].map((p) => firstSupportedLocale(p, SUPPORTED)),
      ["ru", "ru", "ru"],
    ],
    [
      "the phone's order decides between two the app has",
      () => [phone("kk", "en", "ru"), phone("ru", "en"), phone("de")].map((p) => firstSupportedLocale(p, SUPPORTED)),
      ["en", "ru", "de"],
    ],
    [
      "Android's legacy code for Indonesian (\"in\") is Indonesian",
      () => firstSupportedLocale(phone("in"), SUPPORTED),
      "id",
    ],
    [
      "a missing code is skipped, and case does not matter",
      () => firstSupportedLocale([{ languageCode: null }, {}, { languageCode: "RU" }], SUPPORTED),
      "ru",
    ],
    [
      "none the app has, or no list at all: null (the app then starts in English)",
      () => [phone("uk", "be"), [], undefined, null].map((p) => firstSupportedLocale(p, SUPPORTED)),
      [null, null, null, null],
    ],
  ];

  let failed = 0;
  for (const [name, run, expected] of CASES) {
    try {
      deepStrictEqual(await run(), expected);
      console.log(`  ok    ${name}`);
    } catch (e) {
      failed += 1;
      console.log(`  FAIL  ${name}\n        ${String(e.message).split("\n").join("\n        ")}`);
    }
  }
  if (failed > 0) {
    console.error(`\n${failed} of ${CASES.length} cases failed`);
    process.exitCode = 1;
  } else {
    console.log(`\nall ${CASES.length} cases pass`);
  }
} finally {
  rmSync(out, { recursive: true, force: true });
}
