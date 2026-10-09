#!/usr/bin/env node
/**
 * Table test for the iPhone's DNS protection (docs/IOS.md §4): the native
 * report parser (modules/cleanway-vpn/src/IosDnsSettings.ts), the setup state
 * machine (src/utils/ios-dns.ts), its copy in all 10 locales, and source
 * checks on the Swift side and the home screen — nothing here can run
 * NetworkExtension or render React Native.
 *
 * Run: node --experimental-strip-types mobile/scripts/test-ios-dns.mjs
 *
 * Pinned:
 *   • the layer is "on" only when iOS says our configuration is saved, points
 *     at today's gateway AND is enabled; anything odd from the native side
 *     reads as "not there", never as on;
 *   • the two steps follow iOS (save → the person picks it in Settings), the
 *     sheet's one main button matches the step, an error is worded for the
 *     call that failed, "Remove" appears only when something is saved;
 *   • the privacy copy says the names go to Cleanway's server (unlike
 *     Android), never "stays on your phone", and comes before any button;
 *   • the Swift side saves DoH to https://dns.cleanway.ai/dns-query — the
 *     path the API serves — with no pinned IPs and no on-demand rules, and
 *     never sets isEnabled (only the person can);
 *   • nothing calls this feature a VPN (App Review 5.4 misfile risk) except
 *     where it names Apple's own Settings page or a VPN app.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { parseIosDnsReport } from "../modules/cleanway-vpn/src/IosDnsSettings.ts";
import {
  INITIAL_IOS_DNS,
  IOS_DNS_SHEET_KEYS,
  iosDnsErrorKey,
  iosDnsFinished,
  iosDnsLayerStatus,
  iosDnsPhase,
  iosDnsSheet,
  iosDnsStarted,
} from "../src/utils/ios-dns.ts";
import { iosProtectionLayers } from "../src/utils/platform-features.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const MOBILE = join(HERE, "..");
const REPO = join(MOBILE, "..");
const LOCALES = ["en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar"];
const STRINGS = Object.fromEntries(
  LOCALES.map((loc) => [loc, JSON.parse(readFileSync(join(MOBILE, "i18n", `${loc}.json`), "utf8"))]),
);
const read = (rel) => readFileSync(join(MOBILE, rel), "utf8");

let failures = 0;
function check(name, fn) {
  try {
    fn();
    console.log(`  ok   ${name}`);
  } catch (err) {
    failures += 1;
    console.log(`  FAIL ${name}\n       ${err.message}`);
  }
}

const report = (over = {}) => parseIosDnsReport({ installed: true, current: true, enabled: true, ...over });
const state = (rep, over = {}) => ({ ...INITIAL_IOS_DNS, supported: true, report: rep, lastAction: "status", ...over });

// ── The native report ────────────────────────────────────────────────

check("a clean report parses as it came", () => {
  assert.deepEqual(parseIosDnsReport({ installed: true, current: true, enabled: false, step: "load" }), {
    installed: true, current: true, enabled: false, error: null, message: null,
  });
});

check("odd native values never read as on", () => {
  for (const raw of [null, undefined, 42, "on", [], {}]) {
    const r = parseIosDnsReport(raw);
    assert.equal(r.installed, false, String(raw));
    assert.equal(r.enabled, false, String(raw));
  }
  // Not an object at all is a bridge failure — "failed", not "not set up".
  assert.equal(parseIosDnsReport(null).error, "failed");
  assert.equal(parseIosDnsReport({}).error, null);
  // "enabled" with nothing installed cannot be ours.
  assert.equal(parseIosDnsReport({ installed: false, current: true, enabled: true }).enabled, false);
  assert.equal(parseIosDnsReport({ installed: "yes", enabled: 1 }).enabled, false);
});

check("error codes: the known ones pass, anything else is 'failed'; the raw message is kept for logs", () => {
  for (const code of ["invalid", "disabled", "stale", "cannot_remove", "failed"]) {
    assert.equal(parseIosDnsReport({ error: code }).error, code);
  }
  assert.equal(parseIosDnsReport({ error: "permission" }).error, "failed");
  assert.equal(parseIosDnsReport({ error: "stale", message: "NEDNSSettingsErrorDomain 3: x" }).message, "NEDNSSettingsErrorDomain 3: x");
});

// ── Phases and the home card ─────────────────────────────────────────

check("phases: unavailable → checking → add → turn_on → on", () => {
  assert.equal(iosDnsPhase(INITIAL_IOS_DNS), "unavailable");
  assert.equal(iosDnsPhase({ ...INITIAL_IOS_DNS, supported: true }), "checking");
  assert.equal(iosDnsPhase(state(parseIosDnsReport({}))), "add");
  assert.equal(iosDnsPhase(state(report({ enabled: false }))), "turn_on");
  assert.equal(iosDnsPhase(state(report())), "on");
});

check("an old or foreign configuration (other server URL) is redone by step 1, even if enabled", () => {
  assert.equal(iosDnsPhase(state(report({ current: false }))), "add");
  assert.equal(iosDnsPhase(state(report({ current: false, enabled: false }))), "add");
});

check("home card: 'coming' only without support, 'on' only when on, else 'Set up' — and it reaches the card", () => {
  assert.equal(iosDnsLayerStatus("unavailable"), "coming");
  assert.equal(iosDnsLayerStatus("checking"), "setup");
  assert.equal(iosDnsLayerStatus("add"), "setup");
  assert.equal(iosDnsLayerStatus("turn_on"), "setup");
  assert.equal(iosDnsLayerStatus("on"), "on");
  const dns = iosProtectionLayers({ dns: iosDnsLayerStatus("on") }).find((l) => l.id === "dns");
  assert.equal(dns.status, "on");
});

// ── Transitions ──────────────────────────────────────────────────────

check("a call marks busy, its answer replaces the report and clears busy", () => {
  let s = { ...INITIAL_IOS_DNS, supported: true };
  s = iosDnsStarted(s, "install");
  assert.equal(s.busy, "install");
  assert.equal(iosDnsSheet(s).primary.busy, true);
  assert.equal(iosDnsSheet(s).primary.labelKey, "mobile.ios.dns.adding");
  s = iosDnsFinished(s, "install", report({ enabled: false }));
  assert.equal(s.busy, null);
  assert.equal(iosDnsPhase(s), "turn_on");
});

check("a status read landing during an install does not end the install's busy state", () => {
  let s = iosDnsStarted({ ...INITIAL_IOS_DNS, supported: true }, "install");
  s = iosDnsFinished(s, "status", parseIosDnsReport({}));
  assert.equal(s.busy, "install");
});

check("no native support after all (null report) → unavailable, not a guess", () => {
  const s = iosDnsFinished(iosDnsStarted(state(report()), "status"), "status", null);
  assert.equal(iosDnsPhase(s), "unavailable");
  assert.equal(s.busy, null);
});

check("a failed install keeps what iOS holds and words the error for the install", () => {
  const s = iosDnsFinished(iosDnsStarted(state(parseIosDnsReport({})), "install"), "install",
    parseIosDnsReport({ installed: false, error: "failed", message: "x" }));
  assert.equal(iosDnsPhase(s), "add");
  assert.equal(iosDnsErrorKey(s), "mobile.ios.dns.error_add");
  assert.equal(iosDnsSheet(s).primary.action, "install");
});

check("a failed removal keeps the layer as it is and points to Settings", () => {
  const s = iosDnsFinished(state(report()), "remove", report({ error: "cannot_remove" }));
  assert.equal(iosDnsPhase(s), "on");
  assert.equal(iosDnsErrorKey(s), "mobile.ios.dns.error_remove");
});

check("a failed read is worded as a read; a good answer clears the error", () => {
  const bad = iosDnsFinished(state(null), "status", parseIosDnsReport({ error: "stale" }));
  assert.equal(iosDnsErrorKey(bad), "mobile.ios.dns.error_status");
  const good = iosDnsFinished(bad, "status", report());
  assert.equal(iosDnsErrorKey(good), null);
});

// ── The sheet ────────────────────────────────────────────────────────

check("step 1 current: main button saves the setting; nothing to remove", () => {
  const sheet = iosDnsSheet(state(parseIosDnsReport({})));
  assert.deepEqual(sheet.steps, { add: "current", turnOn: "todo" });
  assert.deepEqual(sheet.primary, { action: "install", labelKey: "mobile.ios.dns.add", busy: false });
  assert.equal(sheet.statusKey, "mobile.ios.dns.status_add");
  assert.equal(sheet.removable, false);
});

check("still reading iOS: the add button waits (no double save)", () => {
  const sheet = iosDnsSheet({ ...INITIAL_IOS_DNS, supported: true });
  assert.equal(sheet.primary.busy, true);
  assert.equal(sheet.statusKey, "mobile.ios.dns.status_checking");
});

check("step 2 current: main button opens Settings; removable", () => {
  const sheet = iosDnsSheet(state(report({ enabled: false })));
  assert.deepEqual(sheet.steps, { add: "done", turnOn: "current" });
  assert.equal(sheet.primary.action, "open_settings");
  assert.equal(sheet.statusKey, "mobile.ios.dns.status_turn_on");
  assert.equal(sheet.removable, true);
});

check("on: both steps done, no main action (Done), removable; removing hides the button's twin", () => {
  const sheet = iosDnsSheet(state(report()));
  assert.deepEqual(sheet.steps, { add: "done", turnOn: "done" });
  assert.equal(sheet.primary, null);
  assert.equal(sheet.statusKey, "mobile.ios.dns.status_on");
  assert.equal(sheet.removable, true);
  const removing = iosDnsSheet(iosDnsStarted(state(report()), "remove"));
  assert.equal(removing.removable, false);
  assert.equal(removing.removing, true);
});

// ── Copy ─────────────────────────────────────────────────────────────

check("every key the sheet and the home screen can show exists in all 10 locales", () => {
  const keys = [...IOS_DNS_SHEET_KEYS, "mobile.home.privacy_ios_dns", "mobile.home.hero.sub_ios_ready"];
  for (const loc of LOCALES) {
    for (const key of keys) {
      assert.ok(typeof STRINGS[loc][key] === "string" && STRINGS[loc][key].trim().length > 0, `${loc}: ${key}`);
    }
  }
});

check("privacy copy: names go to Cleanway's server, unlike Android; Cloudflare named; never 'stays on the phone'", () => {
  const en = STRINGS.en["mobile.ios.dns.privacy_body"];
  assert.match(en, /Cleanway's server/);
  assert.match(en, /Android/);
  assert.match(en, /Cloudflare/);
  assert.match(en, /never the full link/);
  // The gateway since PR #124: no per-query log line, aggregate counters,
  // a cache keyed by the question only — never "a blocked name in our log".
  assert.match(en, /writes no log of the names/);
  assert.match(en, /never by who asked/);
  assert.ok(!/in our log/.test(en), "the old blocked-name log line is gone");
  for (const loc of LOCALES) {
    const body = STRINGS[loc]["mobile.ios.dns.privacy_body"];
    assert.match(body, /Cloudflare/, loc);
    assert.match(body, /Android/, loc);
    assert.match(body, /example\.com/, loc);
    assert.match(body, /11/, loc); // points to the policy section
  }
  assert.ok(!/stays on your (phone|iPhone)|never leaves your (phone|iPhone)/i.test(en));
  assert.match(STRINGS.en["mobile.home.privacy_ios_dns"], /DNS protection/);
});

check("policy §11 describes the gateway on main: Cloudflare only, no log line, question-keyed memory cache, hashed limit", () => {
  for (const loc of LOCALES) {
    const src = JSON.parse(readFileSync(join(REPO, "packages", "i18n-strings", "src", `${loc}.json`), "utf8"));
    const sec = src.landing.privacy_policy.sections[10];
    assert.match(sec.title, /^11\./, loc);
    const [, filter, iphone] = sec.paragraphs;
    assert.match(filter, /dns\.cleanway\.ai/, loc);
    assert.match(filter, /Cloudflare/, loc);
    assert.match(filter, /\b6\b/, `${loc}: the 6 h stale fallback`);
    assert.match(iphone, /iPhone/, loc);
    assert.match(iphone, /iOS 26/, loc);
    for (const p of [filter, iphone]) {
      assert.ok(!/Quad9/.test(p), `${loc}: Quad9 is not a DoH upstream by default`);
      assert.ok(!/\b32\b/.test(p), `${loc}: the 32-character log line is gone`);
    }
    assert.ok(!/Quad9/.test(STRINGS[loc]["mobile.ios.dns.privacy_body"]), loc);
  }
  const ups = readFileSync(join(REPO, "api", "services", "doh_upstream.py"), "utf8");
  assert.match(ups, /DEFAULT_UPSTREAMS = \(CLOUDFLARE_DOH_URL, CLOUDFLARE_IP_DOH_URL\)/, "the copy names Cloudflare only");
});

check("never calls the feature a VPN — only Apple's Settings page and VPN apps may say it", () => {
  const allowed = new Set([
    "mobile.ios.dns.step_on_body", "mobile.ios.dns.error_remove", "mobile.ios.dns.note_vpn",
  ]);
  for (const loc of LOCALES) {
    for (const [key, value] of Object.entries(STRINGS[loc])) {
      if (!key.startsWith("mobile.ios.") || allowed.has(key)) continue;
      assert.ok(!/VPN/.test(value), `${loc}: ${key}`);
    }
    // The Settings path names the real page, in each language.
    assert.match(STRINGS[loc]["mobile.ios.dns.step_on_body"], /DNS/, loc);
  }
  assert.match(STRINGS.en["mobile.ios.dns.step_on_body"], /General → VPN & Device Management → DNS/);
});

// ── Source checks ────────────────────────────────────────────────────

const swift = read("modules/cleanway-vpn/ios/CleanwayVpnModule.swift");

check("Swift: DoH to the gateway the API serves, no pinned IPs, no on-demand rules", () => {
  assert.match(swift, /static let serverURL = "https:\/\/dns\.cleanway\.ai\/dns-query"/);
  assert.match(swift, /NEDNSOverHTTPSSettings\(servers: \[\]\)/);
  assert.match(swift, /manager\.onDemandRules = nil/);
  assert.match(swift, /manager\.localizedDescription = displayName/);
  assert.match(swift, /static let displayName = "Cleanway"/);
  const doh = readFileSync(join(REPO, "api", "routers", "doh.py"), "utf8");
  assert.match(doh, /"\/dns-query"/, "the API still serves /dns-query");
});

check("Swift: loads before saving, re-reads after, never sets isEnabled; failover only behind the iOS 26 check", () => {
  assert.ok(!/isEnabled\s*=/.test(swift), "isEnabled is the person's");
  const install = swift.slice(swift.indexOf("static func install"), swift.indexOf("static func remove"));
  const load = install.indexOf("loadFromPreferences");
  const save = install.indexOf("saveToPreferences");
  assert.ok(load >= 0 && save > load, "load, then save");
  assert.ok(install.lastIndexOf("loadFromPreferences") > save, "re-read after save");
  assert.match(swift, /#if compiler\(>=6\.2\)[\s\S]*if #available\(iOS 26\.0, \*\) \{\s*settings\.allowFailover = true/);
  for (const fn of ["dnsSettingsStatus", "installDnsSettings", "removeDnsSettings"]) {
    assert.match(swift, new RegExp(`AsyncFunction\\("${fn}"\\)`), fn);
  }
  assert.match(swift, /Events\("onDomainBlocked", "onDnsSettingsChanged"\)/);
  assert.match(swift, /\.NEDNSSettingsConfigurationDidChange/);
});

check("JS bridge: iOS only, optional native functions, the change event typed", () => {
  const vpn = read("modules/cleanway-vpn/index.ts");
  assert.match(vpn, /return Platform\.OS === 'ios' && typeof CleanwayVpn\.dnsSettingsStatus === 'function'/);
  const decl = read("modules/cleanway-vpn/src/CleanwayVpnModule.ts");
  for (const fn of ["dnsSettingsStatus", "installDnsSettings", "removeDnsSettings"]) {
    assert.match(decl, new RegExp(`${fn}\\?\\(\\)`), fn);
  }
  assert.match(read("modules/cleanway-vpn/src/CleanwayVpn.types.ts"), /onDnsSettingsChanged:/);
});

check("home: the DNS layer comes from iOS, its row opens the sheet; the sheet shows privacy before any button", () => {
  const home = read("app/(tabs)/index.tsx");
  assert.match(home, /iosProtectionLayers\(\{ dns: iosDns\.layer \}\)/);
  assert.match(home, /if \(id === "dns"\) setDnsSheetVisible\(true\)/);
  assert.match(home, /<IosDnsSetupSheet visible=\{dnsSheetVisible\}/);
  const sheet = read("src/components/shield/IosDnsSetupSheet.tsx");
  const privacy = sheet.indexOf('t("mobile.ios.dns.privacy_body")');
  assert.ok(privacy > 0 && privacy < sheet.indexOf("onPress={onPrimary}"), "privacy before the main button");
  assert.match(sheet, /Linking\.openSettings\(\)/);
  assert.ok(!/App-[Pp]refs:|prefs:root/.test(sheet), "no private Settings URLs (App Review 2.5.1)");
  // An "on" row opens the flow too (to see it or remove it); "coming" never does.
  assert.match(read("src/components/shield/IosProtectionCard.tsx"), /return ready && onSetUp \? \(/);
  // Live status: foreground and iOS's change notice both re-read.
  const hook = read("src/hooks/useIosDnsProtection.ts");
  assert.match(hook, /AppState\.addEventListener\("change"/);
  assert.match(hook, /addIosDnsChangedListener\(/);
});

if (failures > 0) {
  console.log(`\n${failures} failing`);
  process.exit(1);
}
console.log("\niOS DNS protection: all passed");
