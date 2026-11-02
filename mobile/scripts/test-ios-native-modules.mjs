#!/usr/bin/env node
/**
 * What the iPhone app's JavaScript gets from the native-module layer — run
 * with `node scripts/test-ios-native-modules.mjs`.
 *
 * App Review's automated check flagged the iPhone app as "VPN" (docs/IOS.md
 * §3.6); one trigger was a native module named after Android's VPN shield
 * that the iPhone build linked only to answer "no". The shield module is now
 * Android-only, and the iPhone's DNS protection has its own module. Pinned:
 *
 *  1. modules/cleanway-vpn has no iOS half (no pod, no Swift, no web shim),
 *     and only src/native.android.ts asks for the Kotlin module; iOS and web
 *     bundle src/native.ts, which asks for nothing.
 *  2. Every function modules/cleanway-vpn/index.ts exports runs on iOS and
 *     web over that stub without throwing and answers "not on this platform"
 *     — no false "on", no network probe. The app imports the module at launch
 *     (src/i18n, app/_layout.tsx), so a throw here would be a crash. The
 *     table must list every export: a new one needs its iPhone answer here.
 *  3. On Android, src/native.android.ts hands over the Kotlin module itself.
 *  4. modules/cleanway-dns (iOS only): asks for CleanwayDns on iOS alone,
 *     says "unsupported" without it, and passes the native reports through
 *     the same parser — a rejected call reads "failed", never "not set up".
 *
 * No test runner in mobile/: the modules are transpiled with the tree's
 * TypeScript and loaded with a small require that hands them their stubs.
 */
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const appRequire = createRequire(join(root, "package.json"));
const ts = appRequire("typescript");
const read = (rel) => readFileSync(join(root, rel), "utf8");
const VPN_DIR = "modules/cleanway-vpn";

let failures = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log(`  ok   ${name}`);
  } catch (err) {
    failures += 1;
    console.log(`  FAIL ${name}\n       ${String(err.message).split("\n").join("\n       ")}`);
  }
}

/** CommonJS-load a .ts file of the app with [stubs] in place of the imports they name. */
function loadTs(file, stubs) {
  const { outputText } = ts.transpileModule(readFileSync(file, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, esModuleInterop: true },
    fileName: file,
  });
  const module = { exports: {} };
  const requireHere = (spec) => {
    if (spec in stubs) return stubs[spec];
    if (spec.startsWith(".")) return loadTs(resolve(dirname(file), `${spec}.ts`), stubs);
    return appRequire(spec);
  };
  new Function("require", "module", "exports", outputText)(requireHere, module, module.exports);
  return module.exports;
}

const reactNative = (os) => ({
  Platform: { OS: os, Version: 0 },
  AppState: { currentState: "active", addEventListener: () => ({ remove() {} }) },
  PermissionsAndroid: new Proxy({}, { get() { throw new Error(`PermissionsAndroid touched on ${os}`); } }),
});

/** The expo package as an app without the asked-for native module sees it; records what was asked for. */
function expoWithout() {
  const asked = [];
  return {
    asked,
    requireOptionalNativeModule: (name) => { asked.push(name); return null; },
    requireNativeModule: (name) => { throw new Error(`Cannot find native module '${name}'`); },
  };
}

// ── 1. The shield module's shape ────────────────────────────────────

/** Every .ts/.tsx the app bundles: app/, src/ and the modules' JS (not android/ or ios/). */
function bundledSources() {
  const out = [];
  for (const dir of ["app", "src", "modules"]) {
    for (const f of readdirSync(join(root, dir), { recursive: true }).map(String)) {
      if (!/\.(ts|tsx)$/.test(f) || /(^|\/)(android|ios|node_modules)\//.test(f)) continue;
      out.push(`${dir}/${f}`);
    }
  }
  return out;
}

await check("the shield module is Android-only: no pod, no Swift, no web shim", () => {
  const config = JSON.parse(read(`${VPN_DIR}/expo-module.config.json`));
  assert.deepEqual(config.platforms, ["android"]);
  assert.equal(config.apple, undefined);
  assert.ok(!existsSync(join(root, VPN_DIR, "ios")), "modules/cleanway-vpn/ios/ is gone");
  assert.deepEqual(readdirSync(join(root, VPN_DIR, "src")).filter((f) => /\.(web|ios)\.ts$/.test(f)), []);
});

await check("only src/native.android.ts asks for the Kotlin module; iOS and web get src/native.ts", () => {
  const sources = bundledSources();
  assert.ok(sources.length > 50, "scanned the app's sources");
  const asking = sources.filter((f) => /require(Optional)?NativeModule\b[^(]*\(\s*['"]CleanwayVpn['"]/.test(read(f)));
  assert.deepEqual(asking, [`${VPN_DIR}/src/native.android.ts`]);
  const stub = read(`${VPN_DIR}/src/native.ts`);
  assert.ok(!/from ['"]expo['"]|\brequire(Optional)?NativeModule\b/.test(stub.replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, "")), "the stub asks for nothing");
  assert.match(read(`${VPN_DIR}/index.ts`), /from '\.\/src\/native';/);
  // One shape for both, so the shared code cannot call what only one has.
  assert.match(stub, /const native: CleanwayVpnNativeModule = \{/);
  assert.match(read(`${VPN_DIR}/src/native.android.ts`), /requireNativeModule<CleanwayVpnNativeModule>\('CleanwayVpn'\)/);
});

// ── 2. Every export over the stub, on iOS and web ───────────────────

const SUBSCRIPTION = Symbol("a subscription that never fires");
const UNKNOWN_KEEP_ALIVE = { batteryUnrestricted: null, alwaysOn: null, oem: null };
const NO_LIST = { version: 0, count: 0, revoked: false, ageMs: null, stale: true, hasCanary: false, lastError: null, lastFetchAt: 0 };

/** export name → [arguments, the answer on a platform without the shield]. */
const NOT_HERE = {
  startVpn: [[], false],
  stopVpn: [[], undefined],
  isVpnRunning: [[], false],
  openVpnSettings: [[], false],
  verifyFiltering: [[], false],
  verifyListFiltering: [[], false],
  addDomainBlockedListener: [[() => {}], SUBSCRIPTION],
  addVpnStoppedListener: [[() => {}], SUBSCRIPTION],
  addPauseChangedListener: [[() => {}], SUBSCRIPTION],
  addBlocklistChangedListener: [[() => {}], SUBSCRIPTION],
  addNetworkChangedListener: [[() => {}], SUBSCRIPTION],
  addCallStateChangedListener: [[() => {}], SUBSCRIPTION],
  callState: [[], null],
  noteCallEvent: [["site_blocked"], undefined],
  showInCallScreen: [[], false],
  closeContactPhone: [[], null],
  setCloseContactPhone: [["+15550100"], false],
  dialCloseContact: [[], false],
  keepAliveStatus: [[], UNKNOWN_KEEP_ALIVE],
  requestBatteryExemption: [[], false],
  openOemBackgroundSettings: [[], false],
  rearmShield: [[], null],
  pauseProtection: [[Date.now() + 60_000], undefined],
  resumeProtection: [[], undefined],
  pausedUntil: [[], 0],
  nativeInstallId: [[], null],
  notificationsEnabled: [[], null],
  turnOnBlockNotifications: [[], "declined"],
  openNotificationSettings: [[], false],
  // Nothing to ask for where there is no shield to hear about.
  requestBlockNotificationPermission: [[], true],
  wasUserEnabled: [[], false],
  lastStopReason: [[], null],
  privateDnsStrictHost: [[], null],
  openPrivateDnsSettings: [[], false],
  recentShieldBlocks: [[], []],
  shieldBlockCountSince: [[0], 0],
  shieldBlockTotals: [[], { blocked: 0, warned: 0 }],
  blocklistStatus: [[], NO_LIST],
  refreshBlocklist: [[], undefined],
  allowedDomains: [[], []],
  allowDomain: [["example.com"], false],
  removeAllowedDomain: [["example.com"], undefined],
  openInBrowser: [["https://example.com/"], false],
  setNotificationLocale: [["en"], undefined],
  isLinkHandlerSupported: [[], false],
  isDefaultLinkHandler: [[], false],
  requestLinkHandler: [[], false],
  isMessageCheckSupported: [[], false],
  setRemoteConfig: [["{}"], false],
  analyzeMessage: [["Your parcel is waiting: https://example.com/"], { available: false, reason: "unsupported" }],
  matchBlocklist: [["example.com"], null],
  linkListAvailable: [[], false],
};

for (const os of ["ios", "web"]) {
  await check(`${os}: every export answers "not on this platform" over the stub, without a throw or a probe`, async () => {
    const fetches = [];
    globalThis.fetch = async (url) => { fetches.push(url); throw new Error("offline"); };
    const expo = expoWithout();
    const mod = loadTs(join(root, VPN_DIR, "index.ts"), { "react-native": reactNative(os), expo });
    // React hooks need a renderer; nothing in app/ or src/ uses one from here.
    const exported = Object.keys(mod).filter((k) => typeof mod[k] === "function" && !/^use[A-Z]/.test(k)).sort();
    assert.deepEqual(exported, Object.keys(NOT_HERE).sort(), "the table lists every exported function");
    for (const [name, [args, want]] of Object.entries(NOT_HERE)) {
      let got;
      try {
        got = await mod[name](...args);
      } catch (err) {
        assert.fail(`${name} threw: ${err.message}`);
      }
      if (want === SUBSCRIPTION) {
        assert.equal(typeof got?.remove, "function", name);
        got.remove();
      } else {
        assert.deepEqual(got, want, name);
      }
    }
    assert.deepEqual(fetches, [], "no canary lookup where there is no shield");
    // The iPhone asks only for the scam-text module (optional); never for the shield.
    assert.deepEqual([...new Set(expo.asked)], os === "ios" ? ["CleanwaySmsFilter"] : []);
  });
}

// ── 3. Android gets the Kotlin module itself ────────────────────────

await check("android: src/native.android.ts is requireNativeModule('CleanwayVpn'), untouched", () => {
  const kotlin = { addListener: () => ({ remove() {} }) };
  const asked = [];
  const expo = { requireNativeModule: (name) => { asked.push(name); return kotlin; } };
  const { default: native } = loadTs(join(root, VPN_DIR, "src/native.android.ts"), { expo });
  assert.deepEqual(asked, ["CleanwayVpn"]);
  assert.equal(native, kotlin);
});

// ── 4. The iPhone's DNS module ──────────────────────────────────────

const DNS = join(root, "modules/cleanway-dns/index.ts");

await check("cleanway-dns: Android and web never ask for it and say unsupported", async () => {
  for (const os of ["android", "web"]) {
    const expo = expoWithout();
    const dns = loadTs(DNS, { "react-native": reactNative(os), expo });
    assert.equal(dns.isIosDnsSupported(), false, os);
    assert.equal(await dns.iosDnsStatus(), null, os);
    assert.equal(await dns.installIosDns(), null, os);
    assert.equal(await dns.removeIosDns(), null, os);
    dns.addIosDnsChangedListener(() => {}).remove();
    assert.deepEqual(expo.asked, [], os);
  }
});

await check("cleanway-dns: an iPhone build without the module says unsupported, never on", async () => {
  const expo = expoWithout();
  const dns = loadTs(DNS, { "react-native": reactNative("ios"), expo });
  assert.deepEqual(expo.asked, ["CleanwayDns"]);
  assert.equal(dns.isIosDnsSupported(), false);
  assert.equal(await dns.iosDnsStatus(), null);
  dns.addIosDnsChangedListener(() => {}).remove();
});

await check("cleanway-dns: reports from CleanwayDns are parsed; a rejection is 'failed'; the change event is followed", async () => {
  const calls = [];
  const events = [];
  const native = {
    dnsSettingsStatus: async () => { calls.push("dnsSettingsStatus"); return { installed: true, current: true, enabled: true, step: "load" }; },
    installDnsSettings: async () => { calls.push("installDnsSettings"); return { installed: true, current: true, enabled: false }; },
    removeDnsSettings: async () => { calls.push("removeDnsSettings"); throw new Error("bridge gone"); },
    addListener: (event) => { events.push(event); return { remove() {} }; },
  };
  const expo = { requireOptionalNativeModule: (name) => (name === "CleanwayDns" ? native : null) };
  const dns = loadTs(DNS, { "react-native": reactNative("ios"), expo });
  assert.equal(dns.isIosDnsSupported(), true);
  assert.deepEqual(await dns.iosDnsStatus(), { installed: true, current: true, enabled: true, error: null, message: null });
  assert.deepEqual(await dns.installIosDns(), { installed: true, current: true, enabled: false, error: null, message: null });
  assert.deepEqual(await dns.removeIosDns(), { installed: false, current: false, enabled: false, error: "failed", message: null });
  assert.deepEqual(calls, ["dnsSettingsStatus", "installDnsSettings", "removeDnsSettings"]);
  dns.addIosDnsChangedListener(() => {}).remove();
  assert.deepEqual(events, ["onDnsSettingsChanged"]);
});

if (failures > 0) {
  console.log(`\n${failures} failing`);
  process.exit(1);
}
console.log("\niPhone native modules: all passed");
