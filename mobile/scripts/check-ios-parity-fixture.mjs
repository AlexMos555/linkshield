#!/usr/bin/env node
/**
 * CI gate for the iPhone scam-text filter (docs/IOS.md §5).
 *
 * The filter's engine is a Swift port of the Android message check
 * (mobile/targets/sms-filter). Its parity tests replay
 * Tests/CleanwayMessageEngineTests/Fixtures/kotlin_parity.json — what the
 * KOTLIN engine says about every corpus message — and require the same
 * verdict and reasons. That only means something while the fixture was made
 * from the engine, assets and corpora as they are now, so this script
 * re-hashes every input the fixture records and fails when one changed
 * without the fixture being regenerated. (CI runs no JVM and no Xcode; the
 * regeneration and the Swift run are local, docs/IOS.md §5.4.)
 *
 * It also pins the privacy promise — message text never leaves the phone:
 * the extension and the engine open no connection and never defer a message
 * to the network, and the extension's Info.plist names no network URL.
 *
 * Run: node mobile/scripts/check-ios-parity-fixture.mjs
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..");
const TARGET = join(REPO, "mobile", "targets", "sms-filter");
const FIXTURE = join(TARGET, "Tests", "CleanwayMessageEngineTests", "Fixtures", "kotlin_parity.json");
const RES = join(REPO, "mobile", "modules", "cleanway-vpn", "android", "src", "test", "resources");
const require = createRequire(import.meta.url);

let failures = 0;
function check(name, fn) {
  try {
    fn();
    console.log(`  ok   ${name}`);
  } catch (err) {
    failures += 1;
    console.log(`  FAIL ${name}\n       ${err.message.split("\n").join("\n       ")}`);
  }
}

const fixture = JSON.parse(readFileSync(FIXTURE, "utf8"));
const REGEN =
  "Regenerate it (docs/IOS.md §5.4): run MessageIosParityTest with CLEANWAY_WRITE_IOS_PARITY=1, " +
  "then `swift test` in mobile/targets/sms-filter — and port the Kotlin change to Swift if a case now differs.";

check("the fixture was made from the current engine, assets and corpora", () => {
  const inputs = fixture.inputs ?? {};
  assert.ok(Object.keys(inputs).length >= 16, "the fixture records too few inputs");
  const stale = Object.entries(inputs).filter(([path, sha]) => {
    const now = createHash("sha256").update(readFileSync(join(REPO, path))).digest("hex");
    return now !== sha;
  });
  assert.deepEqual(stale.map(([p]) => p), [], `changed since the fixture was generated. ${REGEN}`);
});

check("every engine file and corpus is an input (a new one would go unhashed)", () => {
  const inputs = new Set(Object.keys(fixture.inputs));
  const kt = "mobile/modules/cleanway-vpn/android/src/main/java/ai/cleanway/app/";
  for (const f of ["MessageAnalyzer", "MessageGeneric", "MessageLinks", "MessageModel", "MessageRules", "MessageSignals", "MessageText", "RemoteConfig"]) {
    assert.ok(inputs.has(`${kt}${f}.kt`), f);
  }
  const testKt = "mobile/modules/cleanway-vpn/android/src/test/java/ai/cleanway/app/";
  const corpora = readdirSync(join(REPO, testKt)).filter((f) => /^Message\w*Corpus\.kt$/.test(f));
  for (const f of corpora) assert.ok(inputs.has(testKt + f), `${f} is not an input of the fixture`);
  const tsvs = readdirSync(RES).filter((f) => /^message_(heldout|blind)_.*\.tsv$/.test(f));
  for (const f of tsvs) {
    assert.ok(inputs.has(`mobile/modules/cleanway-vpn/android/src/test/resources/${f}`), `${f} is not an input of the fixture`);
  }
  for (const a of require("../plugins/withSmsFilter.js").ASSETS) {
    assert.ok(inputs.has(`mobile/modules/cleanway-vpn/android/src/main/assets/${a}`), a);
  }
});

check("the fixture holds every held-out and blind message, under three configs", () => {
  const texts = new Set(fixture.cases.map((c) => c.text));
  for (const f of readdirSync(RES).filter((n) => /^message_(heldout|blind)_.*\.tsv$/.test(n))) {
    const rows = readFileSync(join(RES, f), "utf8").split("\n").filter((l) => l.trim() && !l.startsWith("#"));
    for (const row of rows) assert.ok(texts.has(row.slice(row.lastIndexOf("\t") + 1)), `${f}: a message is missing`);
  }
  assert.ok(fixture.cases.length > 2000, `only ${fixture.cases.length} cases`);
  for (const c of fixture.cases) {
    assert.ok(["dangerous", "caution", "no_signals"].includes(c.on[0]), c.id);
    assert.equal(c.on.length, 7, c.id);
  }
  assert.ok(fixture.raised.caution > 0 && fixture.raised.danger > 0);
});

// ── Offline only ─────────────────────────────────────────────────────

const swiftSources = [
  ...readdirSync(join(TARGET, "Sources", "CleanwayMessageEngine")).map((f) => join(TARGET, "Sources", "CleanwayMessageEngine", f)),
  ...readdirSync(join(TARGET, "Extension")).map((f) => join(TARGET, "Extension", f)),
].filter((f) => f.endsWith(".swift"));
/** Code only: comments may (and do) name what the code must never do. */
const code = (src) => src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");

check("the extension never defers a message to the network and opens no connection", () => {
  assert.ok(swiftSources.length >= 10, "sources not found");
  for (const f of swiftSources) {
    const src = code(readFileSync(f, "utf8"));
    for (const banned of [/deferQueryRequestToNetwork/, /URLSession/, /URLRequest/, /import\s+Network\b/, /NWConnection/, /CFStream/, /\bsocket\(/]) {
      assert.ok(!banned.test(src), `${f.slice(REPO.length + 1)} uses ${banned}`);
    }
  }
});

check("the extension's Info.plist names no network URL and is a message filter", () => {
  const plugin = require("../plugins/withSmsFilter.js");
  const plist = plugin._infoPlist("group.ai.cleanway.app");
  assert.ok(!plist.includes("ILMessageFilterExtensionNetworkURL"));
  assert.match(plist, /<string>com\.apple\.identitylookup\.message-filter<\/string>/);
  assert.match(plist, /\$\(PRODUCT_MODULE_NAME\)\.MessageFilterExtension/);
  const ext = readFileSync(join(TARGET, "Extension", "MessageFilterExtension.swift"), "utf8");
  assert.match(ext, /class MessageFilterExtension: ILMessageFilterExtension/);
});

console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
