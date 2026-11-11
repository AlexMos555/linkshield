#!/usr/bin/env node
/**
 * Table test for what two real phones showed on 2026-11-11 (a Galaxy and an
 * iPhone, 1.0.x builds) — each a quiet bug no other check would catch.
 *
 * Run: node --experimental-strip-types mobile/scripts/test-device-fixes.mjs
 *
 * Pinned:
 *   • Settings → Plan says what the paywall says: paid → "subscription
 *     active" + "Manage", free → the old text + "Upgrade", not read yet →
 *     neither. It said "free / Upgrade" under an active subscription;
 *   • the "Try these" examples keep their verdicts: the dangerous one is
 *     Cleanway's own list canary (in every blocklist by construction), not an
 *     invented name that stopped existing;
 *   • the back button has a translated name for VoiceOver, not "(tabs)";
 *   • a language change that flips the layout direction is judged by what the
 *     app last asked for, not by I18nManager.isRTL (a constant while the
 *     shield keeps the process alive): Arabic → Russian writes LTR and
 *     restarts the JS; a phone left mirrored restarts once at start, never in
 *     a loop;
 *   • the paywall ends above Android's navigation bar;
 *   • Terms and Privacy open in the app's language (the site has the same ten),
 *     English for anything else;
 *   • a date in History is in the app's language: 26.10.2026 in Russian;
 *   • the ongoing Android notification is re-posted when the language changes.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { directionChange, directionName, isRtlLanguage, startupReload } from "../src/utils/layout-direction.ts";
import { SITE_LOCALES, privacyPolicyUrl, termsUrl } from "../src/utils/legal-urls.ts";
import { relativeTime, shortDate } from "../src/utils/relative-time.ts";
import { CHECK_EXAMPLES, DANGEROUS_EXAMPLE } from "../src/utils/check-examples.ts";
import { settingsPlanRow } from "../src/utils/freemium.ts";

const here = dirname(fileURLToPath(import.meta.url));
const mobile = resolve(here, "..");
const repo = resolve(mobile, "..");
const read = (p) => readFileSync(resolve(mobile, p), "utf8");
const LOCALES = ["en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar"];
const strings = Object.fromEntries(LOCALES.map((l) => [l, JSON.parse(read(`i18n/${l}.json`))]));

let passed = 0;
function test(name, fn) {
  try {
    fn();
    passed += 1;
  } catch (e) {
    console.error(`FAIL ${name}\n  ${e.message}`);
    process.exitCode = 1;
  }
}

// ── 1. Settings → Plan ────────────────────────────────────────────────
test("plan row: paid says so and offers Manage", () => {
  assert.deepEqual(settingsPlanRow(true), { descKey: "mobile.settings.plan_desc_paid", actionKey: "mobile.settings.plan_manage" });
});
test("plan row: free keeps the old text and Upgrade", () => {
  assert.deepEqual(settingsPlanRow(false), { descKey: "mobile.settings.plan_desc", actionKey: "mobile.settings.upgrade" });
});
test("plan row: not read yet claims neither", () => {
  assert.deepEqual(settingsPlanRow(null), { descKey: null, actionKey: null });
});
test("plan row: its strings exist in all 10 locales, and paid is not the free text", () => {
  for (const l of LOCALES) {
    for (const k of ["mobile.settings.plan_desc_paid", "mobile.settings.plan_manage", "mobile.settings.plan_desc", "mobile.settings.upgrade"]) {
      assert.ok(strings[l][k]?.trim(), `${l} ${k}`);
    }
    assert.notEqual(strings[l]["mobile.settings.plan_desc_paid"], strings[l]["mobile.settings.plan_desc"], l);
    assert.notEqual(strings[l]["mobile.settings.plan_manage"], strings[l]["mobile.settings.upgrade"], l);
  }
});
test("plan row: Settings reads the plan the paywall reads, on focus and on change", () => {
  const settings = read("app/(tabs)/settings.tsx");
  assert.doesNotMatch(settings, /desc=\{t\("mobile\.settings\.plan_desc"\)\}/);
  assert.match(settings, /settingsPlanRow\(planPaid\)/);
  assert.match(settings, /isPaid\(\)\.then\(setPlanPaid/);
  assert.match(settings, /useFocusEffect\(loadPlan\)/);
  assert.match(settings, /freemiumEvents\.on\("changed", loadPlan\)/);
});

// ── 2. "Try these" ────────────────────────────────────────────────────
test("examples: the dangerous one is the blocklist's own canary", () => {
  const py = readFileSync(resolve(repo, "api/services/blocklist_artifact.py"), "utf8");
  const canary = /^LIST_CANARY = "([^"]+)"$/m.exec(py)?.[1];
  assert.equal(DANGEROUS_EXAMPLE, canary);
  assert.ok(CHECK_EXAMPLES.includes(DANGEROUS_EXAMPLE));
});
test("examples: no invented or misleading names, and the screen lists these", () => {
  assert.deepEqual([...CHECK_EXAMPLES], ["google.com", "list-canary.cleanway.ai", "pay-pal.com"]);
  const check = read("app/check.tsx");
  assert.match(check, /CHECK_EXAMPLES\.map\(/);
  assert.doesNotMatch(check, /paypa1|evil\.netlify/);
});

// ── 3. Back button ────────────────────────────────────────────────────
test("back button: a translated name in every locale, set on the stack", () => {
  assert.match(read("app/_layout.tsx"), /headerBackTitle: t\("mobile\.nav\.back"\)/);
  for (const l of LOCALES) {
    const v = strings[l]["mobile.nav.back"];
    assert.ok(v?.trim(), l);
    assert.doesNotMatch(v, /tabs/i, l);
  }
});

// ── 4. Layout direction ───────────────────────────────────────────────
test("direction: only Arabic is RTL", () => {
  assert.deepEqual(LOCALES.filter(isRtlLanguage), ["ar"]);
});
test("direction: same direction, nothing pending → nothing to do", () => {
  assert.deepEqual(directionChange({ startedRTL: false, requestedRTL: false }, false), { write: false, reload: false });
  assert.deepEqual(directionChange({ startedRTL: true, requestedRTL: true }, true), { write: false, reload: false });
});
test("direction: Russian → Arabic writes RTL and restarts", () => {
  assert.deepEqual(directionChange({ startedRTL: false, requestedRTL: false }, true), { write: true, reload: true });
});
test("direction: Arabic → Russian after a real restart writes LTR and restarts", () => {
  assert.deepEqual(directionChange({ startedRTL: true, requestedRTL: true }, false), { write: true, reload: true });
});
test("direction: the Galaxy — Arabic chosen, JS never restarted (shield on), back to Russian", () => {
  // The JS started LTR and asked for RTL; the window was rebuilt mirrored.
  // The old code compared with the start value: no write, no dialog.
  assert.deepEqual(directionChange({ startedRTL: false, requestedRTL: true }, false), { write: true, reload: true });
});
test("direction: a second Arabic tap while the restart is pending still restarts, writes nothing", () => {
  assert.deepEqual(directionChange({ startedRTL: false, requestedRTL: true }, true), { write: false, reload: true });
});
test("direction: at start, a mirrored Russian screen restarts once, then never loops", () => {
  assert.equal(startupReload(true, false, null), true);
  assert.equal(startupReload(true, false, directionName(false)), false);
  // A restart spent on the other direction does not block this one.
  assert.equal(startupReload(true, false, directionName(true)), true);
  assert.equal(startupReload(false, false, null), false);
  assert.equal(startupReload(true, true, "ltr"), false);
});
test("direction: the app tracks what it asked for, restarts the JS, and Settings offers no way round", () => {
  const index = read("src/i18n/index.ts");
  assert.doesNotMatch(index, /I18nManager\.isRTL !== shouldRTL/);
  assert.doesNotMatch(index, /!== I18nManager\.isRTL/);
  assert.match(index, /direction\.requestedRTL = shouldRTL/);
  assert.match(index, /reloadAppAsync\(/);
  const settings = read("app/(tabs)/settings.tsx");
  assert.match(settings, /reloadForDirection\(\)/);
  assert.match(settings, /language_restart_action"\), onPress: \(\) => void restartForDirection\(\)/);
  assert.match(settings, /\{ cancelable: false \}/);
  for (const l of LOCALES) {
    for (const k of ["mobile.settings.language_restart_body", "mobile.settings.language_restart_action", "mobile.settings.language_reload_body"]) {
      assert.ok(strings[l][k]?.trim(), `${l} ${k}`);
    }
  }
});

// ── 5. Paywall above the navigation bar ───────────────────────────────
test("paywall: the sheet ends above Android's navigation bar", () => {
  const paywall = read("app/paywall.tsx");
  assert.match(paywall, /paddingBottom: Platform\.OS === "android" \? insets\.bottom : 0/);
});

// ── 6. Terms / Privacy in the app's language ──────────────────────────
test("legal: the site's locales are the ones the app prefixes", () => {
  const routing = readFileSync(resolve(repo, "landing/i18n/routing.ts"), "utf8");
  const list = /locales: \[([^\]]+)\]/.exec(routing)?.[1].match(/[a-z]{2}/g) ?? [];
  assert.equal(/defaultLocale: "en"/.test(routing), true);
  assert.equal(/localePrefix: "as-needed"/.test(routing), true);
  assert.deepEqual([...SITE_LOCALES].sort(), list.filter((l) => l !== "en").sort());
  assert.deepEqual(LOCALES.filter((l) => l !== "en").sort(), [...SITE_LOCALES].sort());
});
test("legal: each language opens its own page, English and unknown the English one", () => {
  assert.equal(termsUrl("ru"), "https://cleanway.ai/ru/terms");
  assert.equal(privacyPolicyUrl("ru"), "https://cleanway.ai/ru/privacy-policy");
  assert.equal(termsUrl("ar"), "https://cleanway.ai/ar/terms");
  assert.equal(termsUrl("pt-BR"), "https://cleanway.ai/pt/terms");
  for (const l of ["en", "en-GB", "uk", "", null, undefined]) {
    assert.equal(termsUrl(l), "https://cleanway.ai/terms", String(l));
    assert.equal(privacyPolicyUrl(l), "https://cleanway.ai/privacy-policy", String(l));
  }
});
test("legal: no screen opens the fixed English address", () => {
  for (const f of ["app/auth.tsx", "app/paywall.tsx", "app/(tabs)/settings.tsx"]) {
    const src = read(f);
    assert.doesNotMatch(src, /\b(TERMS_URL|PRIVACY_POLICY_URL)\b/, f);
    assert.match(src, /termsUrl\(i18n\.language\)/, f);
    assert.match(src, /privacyPolicyUrl\(i18n\.language\)/, f);
  }
});

// ── 7. Dates in the app's language ────────────────────────────────────
const OCT_26 = new Date(2026, 9, 26, 12, 0, 0).getTime();
test("dates: Russian and German write 26.10.2026, never the phone's 26/10/2026", () => {
  assert.equal(shortDate(OCT_26, "ru"), "26.10.2026");
  assert.equal(shortDate(OCT_26, "de"), "26.10.2026");
  assert.equal(shortDate(OCT_26, "en"), "10/26/2026");
  assert.equal(shortDate(NaN, "ru"), "");
});
test("dates: an unknown language falls back instead of throwing", () => {
  assert.ok(shortDate(OCT_26, "not a locale").length > 0);
});
test("dates: a History row older than a week uses the app's language", () => {
  const t = (key) => key;
  const now = OCT_26 + 16 * 86_400_000;
  assert.equal(relativeTime(OCT_26, t, "ru", now), "26.10.2026");
  assert.equal(relativeTime(now - 2 * 86_400_000, t, "ru", now), "mobile.history.days_ago");
  for (const f of ["src/components/history/HistoryRows.tsx", "src/components/history/ShieldEventSheet.tsx"]) {
    assert.doesNotMatch(read(f), /relativeTime\(item\.ts, t\)/, f);
  }
  assert.doesNotMatch(read("app/report.tsx"), /toLocaleDateString\(\)/);
});

// ── 8. The ongoing notification follows the language ──────────────────
test("notification: a language change re-posts the ongoing notification", () => {
  const java = "modules/cleanway-vpn/android/src/main/java";
  const module = read(`${java}/expo/modules/cleanwayvpn/CleanwayVpnModule.kt`);
  const service = read(`${java}/ai/cleanway/app/CleanwayVpnService.kt`);
  const localized = read(`${java}/ai/cleanway/app/LocalizedContext.kt`);
  assert.match(localized, /fun set\(context: Context, code: String\): Boolean/);
  assert.match(module, /if \(changed && CleanwayVpnService\.isRunning\)/);
  assert.match(module, /setAction\(CleanwayVpnService\.ACTION_REFRESH_NOTIFICATION\)/);
  assert.match(service, /const val ACTION_REFRESH_NOTIFICATION = "/);
  assert.match(service, /intent\?\.action == ACTION_REFRESH_NOTIFICATION\) \{[^}]*if \(running\) refreshForeground\(\)/s);
});

if (process.exitCode) {
  console.error("device-fixes table test FAILED");
} else {
  console.log(`device-fixes table test: ${passed} cases passed`);
}
