#!/usr/bin/env node
/**
 * Table test for "Download my data" on the Account screen —
 * src/services/account-export.ts. Run: `node mobile/scripts/test-account-export.mjs`.
 * CI runs it as its own step (.github/workflows/ci.yml, mobile job).
 *
 * The service is transpiled with the tree's TypeScript and loaded with a
 * small require (as in test-domain-check-hook.mjs) that hands it stubs for
 * react-native (Alert, Share), ./api (exportAccountData) and the lazily
 * required expo-sharing / expo-file-system.
 *
 * Pinned (GDPR Art. 15 / 152-FZ art. 14, docs/runbooks/data-requests.md):
 *   • an unlinked phone (403 device_revoked) gets no alert — the app-wide
 *     listener signs it out (services/api.ts);
 *   • the hourly limit (429) has its own sentence; every other failure the
 *     generic one, under the same title;
 *   • the export goes to the share sheet as cleanway-data-YYYY-MM-DD.json
 *     (UTC date), the server's JSON pretty-printed, overwriting the last one —
 *     and only once the file is written: File.write() is async since Expo
 *     SDK 58, so the stub's write lands a tick later, like the real one;
 *   • no sharing on this device, a build without expo-sharing /
 *     expo-file-system, or a file step that throws: the text itself goes
 *     to the system share sheet instead — never a crash, never nothing;
 *   • a share sheet that fails is swallowed (the button stops spinning).
 */
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { deepStrictEqual } from "node:assert";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const appRequire = createRequire(join(root, "package.json"));
const ts = appRequire("typescript");

// ── the world the service talks to ──────────────────────────────────

let world;

function resetWorld() {
  world = {
    answer: { data: { user_id: "u-1", tables: { users: [{ id: "u-1" }] } }, error: null },
    alerts: [],
    textShares: [],
    files: [],
    fileShares: [],
    sharingAvailable: true,
    missing: new Set(),
    failWrite: false,
    failFileShare: false,
    failTextShare: false,
  };
}

const t = (key) => `t(${key})`;

function stubs() {
  return {
    "react-native": {
      Alert: { alert: (title, body) => world.alerts.push([title, body]) },
      Share: {
        share: async (content) => {
          world.textShares.push(content);
          if (world.failTextShare) throw new Error("share sheet failed");
          return { action: "sharedAction" };
        },
      },
    },
    "./api": { exportAccountData: async () => world.answer },
    "expo-sharing": {
      isAvailableAsync: async () => world.sharingAvailable,
      shareAsync: async (uri, options) => {
        if (world.failFileShare) throw new Error("no activity");
        // What the file holds at the moment the share sheet gets it.
        world.fileShares.push([uri, options, world.files.find((f) => f.uri === uri)?.text ?? null]);
      },
    },
    "expo-file-system": {
      Paths: { cache: { uri: "file:///cache/" } },
      File: class {
        constructor(dir, name) {
          this.uri = `${dir.uri}${name}`;
          this.name = name;
          world.files.push(this);
        }
        create(options) {
          this.created = options;
        }
        // expo-file-system 58 (Expo SDK 58): write() returns a Promise, and the
        // file has its content only once it resolves.
        async write(text) {
          await new Promise((done) => setTimeout(done, 0));
          if (world.failWrite) throw new Error("disk full");
          this.text = text;
        }
      },
    },
  };
}

/** CommonJS-load a .ts file of the app with the stubs above in place of its imports. */
function loadTs(file) {
  const { outputText } = ts.transpileModule(readFileSync(file, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, esModuleInterop: true },
    fileName: file,
  });
  const module = { exports: {} };
  const requireHere = (spec) => {
    if (world.missing.has(spec)) throw new Error(`Cannot find native module '${spec}'`);
    const s = stubs();
    if (spec in s) return s[spec];
    throw new Error(`account-export.ts imports ${spec}: add a stub`);
  };
  new Function("require", "module", "exports", outputText)(requireHere, module, module.exports);
  return module.exports;
}

resetWorld();
const { downloadAccountData, exportFileName } = loadTs(join(root, "src/services/account-export.ts"));

const today = () => exportFileName(new Date());
const TEXT = JSON.stringify({ user_id: "u-1", tables: { users: [{ id: "u-1" }] } }, null, 2);
const failure = (kind, code) => ({ data: null, error: { kind, message: kind, ...(code ? { code } : {}) } });

/** What the person saw: alerts, the text share sheet, the file share sheet. */
async function press(setup = () => {}) {
  resetWorld();
  setup();
  await downloadAccountData(t);
  return {
    alerts: world.alerts,
    textShares: world.textShares,
    fileShares: world.fileShares.map(([uri, options, text]) => ({ uri, ...options, text })),
    files: world.files.map((f) => ({ name: f.name, created: f.created ?? null, text: f.text ?? null })),
  };
}

const textFallback = { alerts: [], textShares: [{ title: "t(mobile.account.export_share_title)", message: TEXT }], fileShares: [] };

const CASES = [
  [
    "file name: the UTC date the copy was made",
    async () => [
      exportFileName(new Date("2026-10-22T09:00:00Z")),
      exportFileName(new Date("2026-10-22T23:30:00-05:00")),
      exportFileName(new Date("2027-01-01T00:00:00+03:00")),
    ],
    ["cleanway-data-2026-10-22.json", "cleanway-data-2026-10-23.json", "cleanway-data-2026-12-31.json"],
  ],
  [
    "an unlinked phone (403 device_revoked): no alert, nothing shared — the app signs it out",
    () => press(() => (world.answer = failure("forbidden", "device_revoked"))),
    { alerts: [], textShares: [], fileShares: [], files: [] },
  ],
  [
    "another 403: the generic failure alert",
    () => press(() => (world.answer = failure("forbidden", "something_else"))),
    {
      alerts: [["t(mobile.account.export_failed_title)", "t(mobile.account.export_failed_body)"]],
      textShares: [], fileShares: [], files: [],
    },
  ],
  [
    "the hourly limit (429): its own sentence",
    () => press(() => (world.answer = failure("rate_limited"))),
    {
      alerts: [["t(mobile.account.export_failed_title)", "t(mobile.account.export_rate_limited)"]],
      textShares: [], fileShares: [], files: [],
    },
  ],
  ...["network", "timeout", "http_5xx", "http_4xx", "invalid_json", "unauthorized"].map((kind) => [
    `${kind}: the generic failure alert, nothing shared`,
    () => press(() => (world.answer = failure(kind))),
    {
      alerts: [["t(mobile.account.export_failed_title)", "t(mobile.account.export_failed_body)"]],
      textShares: [], fileShares: [], files: [],
    },
  ]),
  [
    "success: a JSON file in the cache, overwritten, handed to the share sheet once it is written",
    () => press(),
    {
      alerts: [],
      textShares: [],
      fileShares: [{
        uri: `file:///cache/${today()}`,
        mimeType: "application/json",
        UTI: "public.json",
        dialogTitle: "t(mobile.account.export_share_title)",
        text: TEXT,
      }],
      files: [{ name: today(), created: { overwrite: true }, text: TEXT }],
    },
  ],
  [
    "no sharing on this device: the text goes to the system share sheet",
    async () => {
      const seen = await press(() => (world.sharingAvailable = false));
      return { alerts: seen.alerts, textShares: seen.textShares, fileShares: seen.fileShares };
    },
    textFallback,
  ],
  ...["expo-sharing", "expo-file-system"].map((mod) => [
    `a build without ${mod}: the text goes to the system share sheet`,
    async () => {
      const seen = await press(() => world.missing.add(mod));
      return { alerts: seen.alerts, textShares: seen.textShares, fileShares: seen.fileShares };
    },
    textFallback,
  ]),
  [
    "writing the file fails: the text goes to the system share sheet",
    async () => {
      const seen = await press(() => (world.failWrite = true));
      return { alerts: seen.alerts, textShares: seen.textShares, fileShares: seen.fileShares };
    },
    textFallback,
  ],
  [
    "the file share sheet fails: the text goes to the system share sheet",
    async () => {
      const seen = await press(() => (world.failFileShare = true));
      return { alerts: seen.alerts, textShares: seen.textShares, fileShares: seen.fileShares };
    },
    textFallback,
  ],
  [
    "the text share sheet fails too: swallowed, no alert, the call returns",
    async () => {
      const seen = await press(() => {
        world.sharingAvailable = false;
        world.failTextShare = true;
      });
      return { alerts: seen.alerts, shares: seen.textShares.length };
    },
    { alerts: [], shares: 1 },
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
