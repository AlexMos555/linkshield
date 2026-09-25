#!/usr/bin/env node
/**
 * Table test for scripts/check-apk-permissions.mjs — run with
 * `node scripts/test-apk-permissions.mjs`.
 *
 * The guard is the last thing between a build and a user's phone. If it
 * misreads aapt2's output it passes an APK that Play Protect will hard-block
 * on every browser install (SMS access in the direct build), or a RuStore
 * build whose SMS receiver any app can feed fake messages. The cases run the
 * guard's pure parser and rules on aapt2-format dumps — the first one copied
 * from the real 1.0.1 release APK — so no SDK is needed here.
 */
import { deepStrictEqual, ok, strictEqual } from "node:assert";

import { checkApk, manifestFacts, parseXmlTree } from "./check-apk-permissions.mjs";

const NS = "http://schemas.android.com/apk/res/android";

// Verbatim shape of `aapt2 dump xmltree --file AndroidManifest.xml` (build-tools 35).
const REAL = `N: android=${NS} (line=2)
  E: manifest (line=2)
    A: ${NS}:versionCode(0x0101021b)=101
    A: ${NS}:versionName(0x0101021c)="1.0.1" (Raw: "1.0.1")
    A: package="ai.cleanway.app" (Raw: "ai.cleanway.app")
      E: uses-permission (line=11)
        A: ${NS}:name(0x01010003)="android.permission.BIND_VPN_SERVICE" (Raw: "android.permission.BIND_VPN_SERVICE")
      E: uses-permission (line=17)
        A: ${NS}:name(0x01010003)="android.permission.RECEIVE_BOOT_COMPLETED" (Raw: "android.permission.RECEIVE_BOOT_COMPLETED")
      E: application (line=40)
        A: ${NS}:label(0x01010001)=@0x7f120025
        A: ${NS}:name(0x01010003)="ai.cleanway.app.MainApplication" (Raw: "ai.cleanway.app.MainApplication")
          E: receiver (line=190)
            A: ${NS}:name(0x01010003)="ai.cleanway.app.BootReceiver" (Raw: "ai.cleanway.app.BootReceiver")
            A: ${NS}:enabled(0x0101000e)=true
            A: ${NS}:exported(0x01010010)=false
            A: ${NS}:process(0x01010011)=":boot" (Raw: ":boot")
              E: intent-filter (line=197)
                  E: action (line=198)
                    A: ${NS}:name(0x01010003)="android.intent.action.BOOT_COMPLETED" (Raw: "android.intent.action.BOOT_COMPLETED")
                  E: action (line=199)
                    A: ${NS}:name(0x01010003)="android.intent.action.MY_PACKAGE_REPLACED" (Raw: "android.intent.action.MY_PACKAGE_REPLACED")
          E: receiver (line=207)
            A: ${NS}:name(0x01010003)="ai.cleanway.app.BlocklistRefreshReceiver" (Raw: "ai.cleanway.app.BlocklistRefreshReceiver")
            A: ${NS}:exported(0x01010010)=false
`;

/** A dump in the same format, built from a short description. */
function dump({ pkg = "ai.cleanway.app", debuggable = null, perms = [], sdk23 = [], components = [] } = {}) {
  const attr = (indent, name, value) =>
    `${" ".repeat(indent)}A: ${NS}:${name}(0x01010000)=${typeof value === "string" ? `"${value}" (Raw: "${value}")` : value}\n`;
  let out = `N: android=${NS} (line=2)\n  E: manifest (line=2)\n    A: package="${pkg}" (Raw: "${pkg}")\n`;
  for (const p of perms) out += `      E: uses-permission (line=1)\n${attr(8, "name", p)}`;
  for (const p of sdk23) out += `      E: uses-permission-sdk-23 (line=1)\n${attr(8, "name", p)}`;
  out += "      E: application (line=1)\n";
  if (debuggable !== null) out += attr(8, "debuggable", debuggable);
  for (const c of components) {
    out += `          E: ${c.tag} (line=1)\n${attr(12, "name", c.name)}`;
    if (c.exported !== undefined) out += attr(12, "exported", c.exported);
    if (c.enabled !== undefined) out += attr(12, "enabled", c.enabled);
    if (c.permission) out += attr(12, "permission", c.permission);
    if (c.process) out += attr(12, "process", c.process);
    if (c.actions) {
      out += "              E: intent-filter (line=1)\n";
      for (const a of c.actions) out += `                  E: action (line=1)\n${attr(20, "name", a)}`;
    }
  }
  return out;
}

const BASE = ["android.permission.INTERNET", "android.permission.POST_NOTIFICATIONS"];
const SMS_RECEIVER = {
  tag: "receiver",
  name: "ai.cleanway.app.SmsReceiver",
  exported: true,
  enabled: false,
  permission: "android.permission.BROADCAST_SMS",
  process: ":sms",
  actions: ["android.provider.Telephony.SMS_RECEIVED"],
};
const RUSTORE = { perms: [...BASE, "android.permission.RECEIVE_SMS"], components: [SMS_RECEIVER] };
const facts = (d) => manifestFacts(parseXmlTree(dump(d)));

let failed = 0;
function check(name, fn) {
  try {
    fn();
    console.log(`  ok    ${name}`);
  } catch (e) {
    failed++;
    console.log(`  FAIL  ${name}\n        ${e.message.split("\n")[0]}`);
  }
}

/** The rule sentences contain the offending name; match on it. */
function fails(problems, ...needles) {
  for (const n of needles) ok(problems.some((p) => p.includes(n)), `expected a problem about ${n}, got ${JSON.stringify(problems)}`);
}

console.log("parser:");
check("reads the real aapt2 format: package, permissions, components", () => {
  const f = manifestFacts(parseXmlTree(REAL));
  strictEqual(f.packageName, "ai.cleanway.app");
  strictEqual(f.debuggable, false);
  deepStrictEqual(f.permissions, ["android.permission.BIND_VPN_SERVICE", "android.permission.RECEIVE_BOOT_COMPLETED"]);
  deepStrictEqual(f.components[0], {
    tag: "receiver",
    name: "ai.cleanway.app.BootReceiver",
    permission: null,
    exported: false,
    enabled: true,
    process: ":boot",
    actions: ["android.intent.action.BOOT_COMPLETED", "android.intent.action.MY_PACKAGE_REPLACED"],
  });
  deepStrictEqual(f.components[1].actions, []);
  // Not declared: null, which Android reads as enabled.
  strictEqual(f.components[1].enabled, null);
});
check("a colon inside a value is not an attribute name", () => {
  strictEqual(manifestFacts(parseXmlTree(REAL)).components[0].process, ":boot");
});
check("older aapt2's typed booleans read as booleans", () => {
  const text = dump({ components: [SMS_RECEIVER] }).replace('exported(0x01010000)=true', "exported(0x01010000)=(type 0x12)0xffffffff");
  ok(text.includes("(type 0x12)0xffffffff"));
  strictEqual(manifestFacts(parseXmlTree(text)).components[0].exported, true);
  const off = text.replace("(type 0x12)0xffffffff", "(type 0x12)0x0");
  strictEqual(manifestFacts(parseXmlTree(off)).components[0].exported, false);
});
check("a dump without a manifest is an error, not an empty pass", () => {
  let threw = false;
  try {
    manifestFacts(parseXmlTree("garbage"));
  } catch {
    threw = true;
  }
  ok(threw);
});

console.log("direct (browser APK):");
check("the real release manifest passes", () => deepStrictEqual(checkApk(manifestFacts(parseXmlTree(REAL)), "direct"), []));
check("RECEIVE_SMS fails it", () => fails(checkApk(facts({ perms: [...BASE, "android.permission.RECEIVE_SMS"] }), "direct"), "RECEIVE_SMS"));
check("RECEIVE_SMS via uses-permission-sdk-23 fails it too", () =>
  fails(checkApk(facts({ perms: BASE, sdk23: ["android.permission.RECEIVE_SMS"] }), "direct"), "RECEIVE_SMS"));
check("each Play-Protect trigger and template leftover fails it", () => {
  for (const p of ["READ_SMS", "SEND_SMS", "RECEIVE_MMS", "RECEIVE_WAP_PUSH", "RECORD_AUDIO", "SYSTEM_ALERT_WINDOW", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE"]) {
    fails(checkApk(facts({ perms: [...BASE, `android.permission.${p}`] }), "direct"), p);
  }
});
check("an SMS receiver fails it even without the permission", () =>
  fails(checkApk(facts({ perms: BASE, components: [SMS_RECEIVER] }), "direct"), "SmsReceiver"));
check("a notification-listener or accessibility service fails it", () => {
  for (const perm of ["BIND_NOTIFICATION_LISTENER_SERVICE", "BIND_ACCESSIBILITY_SERVICE"]) {
    const svc = { tag: "service", name: "x.Listener", exported: true, permission: `android.permission.${perm}` };
    fails(checkApk(facts({ perms: BASE, components: [svc] }), "direct"), perm);
  }
});
check("a debuggable APK fails it", () => fails(checkApk(facts({ perms: BASE, debuggable: true }), "direct"), "debuggable"));
check("another package fails it", () => fails(checkApk(facts({ pkg: "ai.cleanway.app.dev", perms: BASE }), "direct"), "package"));

console.log("rustore:");
check("RECEIVE_SMS + a guarded, exported SMS_RECEIVED receiver passes", () => deepStrictEqual(checkApk(facts(RUSTORE), "rustore"), []));
check("without RECEIVE_SMS it is not the RuStore build", () =>
  fails(checkApk(facts({ ...RUSTORE, perms: BASE }), "rustore"), "RECEIVE_SMS"));
check("without the receiver it fails", () =>
  fails(checkApk(facts({ ...RUSTORE, components: [] }), "rustore"), "SMS_RECEIVED receiver"));
check("READ_SMS or SEND_SMS fails it (least privilege)", () => {
  for (const p of ["READ_SMS", "SEND_SMS"]) fails(checkApk(facts({ ...RUSTORE, perms: [...RUSTORE.perms, `android.permission.${p}`] }), "rustore"), p);
});
check("the other triggers and template leftovers still fail it", () => {
  for (const p of ["RECEIVE_MMS", "RECORD_AUDIO", "SYSTEM_ALERT_WINDOW"]) {
    fails(checkApk(facts({ ...RUSTORE, perms: [...RUSTORE.perms, `android.permission.${p}`] }), "rustore"), p);
  }
});
check("a receiver without BROADCAST_SMS fails it: anyone could fake a message", () =>
  fails(checkApk(facts({ ...RUSTORE, components: [{ ...SMS_RECEIVER, permission: undefined }] }), "rustore"), "BROADCAST_SMS"));
check("a receiver that is not exported fails it: the SMS would never arrive", () => {
  fails(checkApk(facts({ ...RUSTORE, components: [{ ...SMS_RECEIVER, exported: false }] }), "rustore"), "not exported");
  fails(checkApk(facts({ ...RUSTORE, components: [{ ...SMS_RECEIVER, exported: undefined }] }), "rustore"), "not exported");
});
check("a receiver that is on by default fails it: nothing may be checked before the person turns it on", () => {
  fails(checkApk(facts({ ...RUSTORE, components: [{ ...SMS_RECEIVER, enabled: true }] }), "rustore"), "enabled");
  fails(checkApk(facts({ ...RUSTORE, components: [{ ...SMS_RECEIVER, enabled: undefined }] }), "rustore"), "enabled");
});
check("listening for SMS_DELIVER (the default SMS app's broadcast) fails it", () => {
  const r = { ...SMS_RECEIVER, actions: [...SMS_RECEIVER.actions, "android.provider.Telephony.SMS_DELIVER"] };
  fails(checkApk(facts({ ...RUSTORE, components: [r] }), "rustore"), "SMS_DELIVER");
});
check("a debuggable RuStore build fails it", () => fails(checkApk(facts({ ...RUSTORE, debuggable: true }), "rustore"), "debuggable"));

console.log(failed === 0 ? "\nall cases pass" : `\n${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);
