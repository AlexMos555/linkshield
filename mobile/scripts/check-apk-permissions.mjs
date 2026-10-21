#!/usr/bin/env node
/**
 * Permission guard for the two Android APKs. Run it on every build output
 * before the file goes anywhere:
 *
 *   node mobile/scripts/check-apk-permissions.mjs <apk> direct|rustore
 *
 * The two builds, from the prebuilt android/ tree (in the dev sandbox:
 * ~/Library/Caches/cleanway-dev/cwmobile/android; bin/build-rustore.sh there
 * runs the RuStore one end to end, guard included):
 *
 *   direct   ./gradlew assembleRelease → app/build/outputs/apk/release/app-release.apk
 *            cleanway.ai/android and the GitHub release. No SMS access, ever.
 *   rustore  ./gradlew assembleRustore → app/build/outputs/apk/rustore/app-rustore.apk
 *            RuStore only: release + RECEIVE_SMS + the SMS receiver, declared
 *            off until the person turns the check on
 *            (mobile/plugins/withRustoreVariant.js).
 *
 * Why check the ARTIFACT and not just our config: the merged manifest takes
 * permissions and components from every library too, and one dependency bump
 * can add access nobody wrote. For the direct APK that is fatal — Play
 * Protect's enhanced fraud protection hard-blocks a browser- or
 * messenger-downloaded install that declares SMS, notification-listener or
 * accessibility access, with no "install anyway". For the RuStore APK it is
 * least privilege: RuStore asks to justify every sensitive permission, and the
 * automatic check needs RECEIVE_SMS and nothing else.
 *
 * Reads the compiled manifest with aapt2: $AAPT2, else
 * $ANDROID_HOME/build-tools/35.0.0/aapt2, else the Homebrew SDK's.
 * Exit 0 = pass, 1 = a rule is broken, 2 = usage or aapt2 error.
 */
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const EXPECTED_PACKAGE = "ai.cleanway.app";
const ANDROID_NS = "http://schemas.android.com/apk/res/android";
const RECEIVE_SMS = "android.permission.RECEIVE_SMS";
const BROADCAST_SMS = "android.permission.BROADCAST_SMS";
const SMS_RECEIVED = "android.provider.Telephony.SMS_RECEIVED";

/** Declaring any of these gets a sideloaded install hard-blocked by Play Protect. */
const SIDELOAD_BLOCKED = [
  RECEIVE_SMS,
  "android.permission.READ_SMS",
  "android.permission.SEND_SMS",
  "android.permission.RECEIVE_MMS",
  "android.permission.RECEIVE_WAP_PUSH",
  "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
  "android.permission.BIND_ACCESSIBILITY_SERVICE",
];

/**
 * Pulled in by the Expo template, never used; app.json blockedPermissions
 * strips them and docs/RUSTORE_SUBMISSION.md declares them "No".
 */
const NEVER_USED = [
  "android.permission.RECORD_AUDIO",
  "android.permission.SYSTEM_ALERT_WINDOW",
  "android.permission.READ_EXTERNAL_STORAGE",
  "android.permission.WRITE_EXTERNAL_STORAGE",
];

/** A service guarded by one of these IS a notification listener / accessibility service. */
const BIND_SERVICE_PERMISSIONS = [
  "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
  "android.permission.BIND_ACCESSIBILITY_SERVICE",
];

/** Broadcasts only an SMS app has business with. The RuStore build may listen for the first one only. */
const SMS_ACTIONS = [
  SMS_RECEIVED,
  "android.provider.Telephony.SMS_DELIVER",
  "android.provider.Telephony.WAP_PUSH_RECEIVED",
  "android.provider.Telephony.WAP_PUSH_DELIVER",
];

const COMPONENT_TAGS = ["activity", "activity-alias", "service", "receiver", "provider"];

export const VARIANTS = ["direct", "rustore"];

/**
 * `aapt2 dump xmltree` text → element tree. Nesting is by indentation;
 * `A:` lines belong to the element just above them.
 */
export function parseXmlTree(text) {
  const root = { tag: "#root", attrs: {}, children: [], indent: -1 };
  const stack = [root];
  for (const line of text.split("\n")) {
    const m = /^(\s*)([ENA]): (.*)$/.exec(line);
    if (!m || m[2] === "N") continue;
    const indent = m[1].length;
    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) stack.pop();
    const parent = stack[stack.length - 1];
    if (m[2] === "E") {
      const el = { tag: m[3].replace(/\s*\(line=\d+\)\s*$/, ""), attrs: {}, children: [], indent };
      parent.children.push(el);
      stack.push(el);
    } else {
      const attr = parseAttr(m[3]);
      if (attr) parent.attrs[attr.key] = attr.value;
    }
  }
  return root;
}

// `http://…/android:name(0x01010003)="x" (Raw: "x")`, `package="x"`, `…:exported(0x…)=true`.
// The namespace is matched lazily: the leftmost `name=` is the attribute, a
// colon or `=` inside the value never is.
function parseAttr(body) {
  const m = /^(?:(.*?):)?([A-Za-z_][\w.-]*)(?:\(0x[0-9a-fA-F]+\))?=(.*)$/.exec(body);
  if (!m) return null;
  const [, ns, name, raw] = m;
  const key = ns === ANDROID_NS ? `android:${name}` : ns ? `${ns}:${name}` : name;
  return { key, value: parseValue(raw) };
}

function parseValue(raw) {
  const quoted = /^"((?:[^"\\]|\\.)*)"/.exec(raw);
  if (quoted) return quoted[1];
  // Older aapt2 prints booleans as a typed hex value.
  const typed = /^\(type 0x12\)0x([0-9a-fA-F]+)/.exec(raw);
  if (typed) return parseInt(typed[1], 16) === 0 ? "false" : "true";
  return raw.split(/\s/)[0];
}

function bool(value) {
  if (value === "true") return true;
  if (value === "false") return false;
  return null;
}

/** The facts the rules read: package, debuggable, requested permissions, components. */
export function manifestFacts(tree) {
  const manifest = tree.children.find((e) => e.tag === "manifest");
  if (!manifest) throw new Error("no <manifest> element in the aapt2 dump");
  const app = manifest.children.find((e) => e.tag === "application");
  const permissions = manifest.children
    .filter((e) => e.tag === "uses-permission" || e.tag === "uses-permission-sdk-23")
    .map((e) => e.attrs["android:name"])
    .filter(Boolean);
  const components = (app ? app.children : [])
    .filter((e) => COMPONENT_TAGS.includes(e.tag))
    .map((e) => ({
      tag: e.tag,
      name: e.attrs["android:name"] ?? "(unnamed)",
      permission: e.attrs["android:permission"] ?? null,
      exported: bool(e.attrs["android:exported"]),
      // null = not declared, which Android reads as enabled.
      enabled: bool(e.attrs["android:enabled"]),
      process: e.attrs["android:process"] ?? null,
      actions: e.children
        .filter((f) => f.tag === "intent-filter")
        .flatMap((f) => f.children.filter((a) => a.tag === "action").map((a) => a.attrs["android:name"]))
        .filter(Boolean),
    }));
  return {
    packageName: manifest.attrs.package ?? null,
    debuggable: app ? bool(app.attrs["android:debuggable"]) === true : false,
    permissions,
    components,
  };
}

export function smsReceivers(facts) {
  return facts.components.filter((c) => c.tag === "receiver" && c.actions.some((a) => SMS_ACTIONS.includes(a)));
}

/** Every broken rule, as a sentence. Empty = the APK may ship as [variant]. */
export function checkApk(facts, variant) {
  const problems = [];
  if (facts.packageName !== EXPECTED_PACKAGE) {
    problems.push(`package is ${facts.packageName}, expected ${EXPECTED_PACKAGE}: both APKs must be the same app`);
  }
  if (facts.debuggable) problems.push("the APK is debuggable: a shipped build never is");

  const allowed = variant === "rustore" ? [RECEIVE_SMS] : [];
  for (const perm of [...SIDELOAD_BLOCKED, ...NEVER_USED]) {
    if (facts.permissions.includes(perm) && !allowed.includes(perm)) problems.push(`requests ${perm}`);
  }
  for (const c of facts.components) {
    if (BIND_SERVICE_PERMISSIONS.includes(c.permission)) problems.push(`declares ${c.tag} ${c.name} bound by ${c.permission}`);
  }

  const receivers = smsReceivers(facts);
  if (variant === "direct") {
    for (const r of receivers) problems.push(`declares SMS receiver ${r.name} (${r.actions.join(", ")})`);
    return problems;
  }

  if (!facts.permissions.includes(RECEIVE_SMS)) problems.push(`does not request ${RECEIVE_SMS}: not the RuStore build`);
  if (!receivers.some((r) => r.actions.includes(SMS_RECEIVED))) problems.push(`declares no ${SMS_RECEIVED} receiver`);
  for (const r of receivers) {
    const extra = r.actions.filter((a) => SMS_ACTIONS.includes(a) && a !== SMS_RECEIVED);
    if (extra.length > 0) problems.push(`${r.name} listens for ${extra.join(", ")}: only the default SMS app gets those`);
    if (r.permission !== BROADCAST_SMS) problems.push(`${r.name} is not guarded by ${BROADCAST_SMS}: any app could feed it fake messages`);
    if (r.exported !== true) problems.push(`${r.name} is not exported: SMS_RECEIVED comes from the telephony process and would never arrive`);
    if (r.enabled !== false) {
      problems.push(`${r.name} is not declared android:enabled="false": it would check SMS before the person turned the check on`);
    }
  }
  return problems;
}

/** One-paragraph description of what the APK declares, for the build log. */
export function describe(facts) {
  const platform = facts.permissions.filter((p) => p.startsWith("android.permission.")).map((p) => p.slice(19));
  const receivers = smsReceivers(facts);
  const sms = receivers.length === 0 && !facts.permissions.includes(RECEIVE_SMS)
    ? "none (no SMS permission, no SMS receiver)"
    : [
        facts.permissions.includes(RECEIVE_SMS) ? "RECEIVE_SMS" : "no RECEIVE_SMS",
        ...receivers.map((r) =>
          `receiver ${r.name} [process ${r.process ?? "main"}, ${r.permission ?? "unguarded"}, ${r.enabled === false ? "off until turned on" : "ON BY DEFAULT"}]`),
      ].join("; ");
  return [
    `package ${facts.packageName}, ${facts.debuggable ? "DEBUGGABLE" : "not debuggable"}, ${facts.permissions.length} permissions requested`,
    `android.permission.*: ${platform.join(", ")}`,
    `SMS: ${sms}`,
  ];
}

function aapt2Path() {
  if (process.env.AAPT2) return process.env.AAPT2;
  const sdk = process.env.ANDROID_HOME || "/opt/homebrew/share/android-commandlinetools";
  return join(sdk, "build-tools", "35.0.0", "aapt2");
}

function main(argv) {
  const [apk, variant] = argv;
  if (!apk || !VARIANTS.includes(variant)) {
    console.error("usage: check-apk-permissions.mjs <apk> direct|rustore");
    return 2;
  }
  const aapt2 = aapt2Path();
  if (!existsSync(apk) || !existsSync(aapt2)) {
    console.error(`missing ${existsSync(apk) ? `aapt2 at ${aapt2} (set AAPT2)` : `APK ${apk}`}`);
    return 2;
  }
  let facts;
  try {
    const dump = execFileSync(aapt2, ["dump", "xmltree", "--file", "AndroidManifest.xml", resolve(apk)], {
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
    facts = manifestFacts(parseXmlTree(dump));
  } catch (e) {
    console.error(`could not read the manifest of ${apk}: ${e.message}`);
    return 2;
  }
  console.log(`check-apk-permissions: ${variant}  ${basename(apk)}`);
  for (const line of describe(facts)) console.log(`  ${line}`);
  const problems = checkApk(facts, variant);
  for (const p of problems) console.log(`  FAIL  ${p}`);
  console.log(problems.length === 0 ? "PASS" : `FAILED: ${problems.length} problem(s), do not ship this APK as "${variant}"`);
  return problems.length === 0 ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.exit(main(process.argv.slice(2)));
}
