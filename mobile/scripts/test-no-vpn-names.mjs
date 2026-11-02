#!/usr/bin/env node
/**
 * Guard: the JavaScript an iPhone build bundles names nothing after Android's
 * VPN — run with `node scripts/test-no-vpn-names.mjs`.
 *
 * App Review's automated check flagged the iPhone app as "VPN" (docs/IOS.md
 * §3.6). Hermes does not minify a release bundle, so the shared code's
 * function and property names and its strings reach the iPhone app (local
 * names are checked too: one rule is easier to keep). The Kotlin module still
 * names its calls after the VPN (startVpn, onVpnStopped, …); only
 * modules/cleanway-vpn/src/native.android.ts — which Metro bundles for
 * Android alone — may say those names, and it maps them to neutral ones.
 *
 * Pinned:
 *  1. No identifier, string, template, regex or JSX text in app/, src/ or the
 *     modules' shared JS (not *.android.ts, not android/ or ios/) matches
 *     /vpn/i or is one of Kotlin's names (isRunning included). Comments do
 *     not reach the bundle, so they do not count. An import path counts
 *     where a release bundle keeps it. Metro swaps a path for a module id,
 *     but Expo's config allows optional dependencies — a require() or
 *     import() inside a try block — and Metro keeps an optional one's path
 *     next to its id, in a release build too (collect-dependencies.js). So
 *     the shield module's lazy require()s sit in a helper outside the try.
 *     (Hermes -O may drop such a require as dead code after a Platform.OS
 *     check, but only while that check stays.)
 *  2. No shared file names a platform file in an import path
 *     ("…/native.android"): Metro resolves that path on every platform, so
 *     the *.android.ts files item 1 skips would reach the iPhone — and
 *     native.android.ts asks for a Kotlin module iOS does not have.
 *  3. The Kotlin names appear in native.android.ts — the mapping is there.
 *  4. Every name the app takes from modules/cleanway-vpn is exported by it:
 *     named imports, and every member used on the module where a file
 *     require()s it lazily. Those files type the module as
 *     `typeof import(...)`, never a hand-written interface: require() is
 *     untyped, so a cast to one would hide a renamed export until the screen
 *     broke at runtime.
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
const MODULE = "modules/cleanway-vpn";
const ADAPTER = `${MODULE}/src/native.android.ts`;

/** What CleanwayVpnModule.kt calls things; only the adapter may say them. */
const KOTLIN_NAMES = ["startVpn", "stopVpn", "isRunning", "openVpnSettings", "onVpnStopped", "other_vpn"];

/**
 * An i18n key, renamed together with its texts in all 10 languages (the
 * strings' own guard is test-ios-dns.mjs). Nothing else may say VPN.
 */
const ALLOWED_STRINGS = new Set(["mobile.ios.dns.note_vpn"]);

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

/** The JS the app bundles on every platform: app/, src/, and each module's index.ts and src/. */
function sharedSources() {
  const out = [];
  const walk = (dir) => {
    for (const f of readdirSync(join(root, dir), { recursive: true }).map(String)) {
      if (!/\.(ts|tsx)$/.test(f) || /\.android\.tsx?$/.test(f) || /(^|\/)(android|ios|node_modules)\//.test(f)) continue;
      out.push(`${dir}/${f}`);
    }
  };
  walk("app");
  walk("src");
  for (const m of readdirSync(join(root, "modules"))) {
    if (existsSync(join(root, "modules", m, "index.ts"))) out.push(`modules/${m}/index.ts`);
    if (existsSync(join(root, "modules", m, "src"))) walk(`modules/${m}/src`);
  }
  return out;
}

function parse(rel, text = read(rel)) {
  return ts.createSourceFile(rel, text, ts.ScriptTarget.Latest, true, rel.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
}

/** An import path: `from "…"`, `require("…")`, `import("…")`, `typeof import("…")`. */
function isModulePath(node) {
  const p = node.parent;
  if (!p) return false;
  if ((ts.isImportDeclaration(p) || ts.isExportDeclaration(p)) && p.moduleSpecifier === node) return true;
  if (ts.isCallExpression(p) && p.arguments[0] === node) {
    return p.expression.kind === ts.SyntaxKind.ImportKeyword || (ts.isIdentifier(p.expression) && p.expression.text === "require");
  }
  return ts.isLiteralTypeNode(p) && ts.isImportTypeNode(p.parent);
}

/**
 * Is [node] in a try block (not its catch or finally)? Metro calls a require()
 * or import() there optional and keeps its path. Metro looks only a few
 * statements up for the try; this looks all the way, which is stricter.
 */
function inTryBlock(node) {
  for (let p = node.parent; p; p = p.parent) {
    if (ts.isBlock(p) && ts.isTryStatement(p.parent) && p.parent.tryBlock === p) return true;
  }
  return false;
}

/** Every name and text a file's code carries into the bundle: [kind, text, line]. */
function codeWords(sf) {
  const out = [];
  const visit = (node) => {
    let text = null;
    if (ts.isIdentifier(node) || ts.isPrivateIdentifier(node)) text = node.text;
    else if (ts.isStringLiteralLike(node) || ts.isTemplateLiteralToken(node) || ts.isRegularExpressionLiteral(node)) {
      text = isModulePath(node) && !inTryBlock(node) ? null : node.text;
    } else if (ts.isJsxText(node)) text = node.text;
    if (text !== null) out.push([ts.SyntaxKind[node.kind], text, sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1]);
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

function vpnWords(rel, text) {
  return codeWords(parse(rel, text))
    .filter(([, word]) => (/vpn/i.test(word) && !ALLOWED_STRINGS.has(word)) || KOTLIN_NAMES.includes(word))
    .map(([kind, word, line]) => `${rel}:${line} ${kind} ${JSON.stringify(word)}`);
}

/** Import paths that name a platform file — Metro would bundle it on every platform. */
const PLATFORM_FILE = /\.(android|ios|native|web)(\.[cm]?[jt]sx?)?$/;

function platformPaths(rel, text) {
  const sf = parse(rel, text);
  const out = [];
  const visit = (node) => {
    if (ts.isStringLiteralLike(node) && isModulePath(node) && PLATFORM_FILE.test(node.text)) {
      out.push(`${rel}:${sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1} ${node.text}`);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

// ── 1–3. Names ───────────────────────────────────────────────────────

await check("no VPN or Kotlin name in the shared code — only native.android.ts says them", () => {
  const files = sharedSources();
  assert.ok(files.length > 50, "scanned the app's sources");
  assert.ok(files.includes(`${MODULE}/index.ts`) && files.includes(`${MODULE}/src/native.ts`));
  assert.ok(!files.includes(ADAPTER));
  assert.deepEqual(files.flatMap((f) => vpnWords(f, read(f))), []);
});

await check("the guard sees a Kotlin name in the shared code (startVpn put back in index.ts)", () => {
  const index = read(`${MODULE}/index.ts`);
  const bad = index.replace("export async function startShield()", "export async function startVpn()");
  assert.notEqual(bad, index, "index.ts exports startShield");
  assert.equal(vpnWords(`${MODULE}/index.ts`, bad).length, 1);
  // …and in a hook, and in a string, but not in a comment or an import path.
  assert.equal(vpnWords("x.ts", "const a = shield.isRunning(); const b = 'onVpnStopped';").length, 2);
  assert.equal(vpnWords("x.ts", `// startVpn\nimport { a } from "../../modules/cleanway-vpn";`).length, 0);
});

await check("the guard sees an import path a release bundle keeps: a require() in a try block", () => {
  const path = '"../../modules/cleanway-vpn"';
  assert.equal(vpnWords("x.ts", `function f() { try { return require(${path}); } catch { return null; } }`).length, 1);
  assert.equal(vpnWords("x.ts", `async function f() { try { const m = await import(${path}); return m; } catch {} }`).length, 1);
  // A static import, a type and a require() called from the try are dropped.
  const dropped = `import { a } from ${path}; type M = typeof import(${path});
    const load = () => require(${path}) as M;
    function f() { try { return load(); } catch { return null; } }`;
  assert.equal(vpnWords("x.ts", dropped).length, 0);
  // shield-log.ts with its require() back inside the try, as it was.
  const rel = "src/services/shield-log.ts";
  const text = read(rel);
  const bad = text.replace("return requireShieldModule();", `return require(${path}) as ShieldLogModule;`);
  assert.notEqual(bad, text, "shield-log.ts calls requireShieldModule() in its try");
  assert.deepEqual(vpnWords(rel, bad).map((w) => w.replace(/:\d+/, "")), [`${rel} StringLiteral ${path}`]);
});

await check("no shared file names a platform file in an import path — Metro picks it by platform", () => {
  assert.deepEqual(sharedSources().flatMap((f) => platformPaths(f, read(f))), []);
});

await check("the guard sees a platform file named in an import path (native.android from a hook)", () => {
  const rel = "src/hooks/useProtectionActive.ts";
  const bad = `import { shieldService } from "../../modules/cleanway-vpn/src/native.android";\n${read(rel)}`;
  assert.deepEqual(platformPaths(rel, bad), [`${rel}:1 ../../modules/cleanway-vpn/src/native.android`]);
  assert.equal(platformPaths("x.ts", 'const a = require("./native.ios.ts"); import("./b.web"); export * from "./c.native";').length, 3);
  assert.equal(platformPaths("x.ts", 'import { a } from "./src/native"; import "react-native-web"; const s = "x.android";').length, 0);
});

await check("native.android.ts maps every Kotlin name", () => {
  const words = new Set(codeWords(parse(ADAPTER)).map(([, w]) => w));
  for (const name of KOTLIN_NAMES) assert.ok(words.has(name), name);
});

// ── 4. Every name the app takes from the module is exported ──────────

const MODULE_INDEX = resolve(root, MODULE, "index.ts");

/** Files of the app that import or require the module itself (not its src/ types). */
function consumers() {
  return sharedSources().filter((f) => {
    if (f.startsWith("modules/")) return false;
    return /["'](\.\.\/)+modules\/cleanway-vpn["']/.test(read(f));
  });
}

/** The module's exports, values and types, as TypeScript resolves them. */
function moduleExports(checker, program) {
  const sf = program.getSourceFile(MODULE_INDEX);
  return new Set(checker.getExportsOfModule(checker.getSymbolAtLocation(sf)).map((s) => s.name));
}

/** Is [type] the module's own namespace — what `typeof import(".../cleanway-vpn")` gives? */
function isModuleType(type) {
  const decl = type.getSymbol()?.valueDeclaration;
  return Boolean(decl && ts.isSourceFile(decl) && resolve(decl.fileName) === MODULE_INDEX);
}

const CONFIG = ts.getParsedCommandLineOfConfigFile(join(root, "tsconfig.typecheck.json"), {}, {
  ...ts.sys, onUnRecoverableConfigFileDiagnostic: (d) => { throw new Error(ts.flattenDiagnosticMessageText(d.messageText, "\n")); },
});

/** Parsed files, shared by both programs below (parsing react-native's types is most of the time). */
const PARSED = new Map();

/** Type-check the module's users, with [overrides] (path → source text) in place of the files on disk. */
function compile(files, overrides = {}) {
  const host = ts.createCompilerHost(CONFIG.options);
  const fromDisk = host.getSourceFile.bind(host);
  const swapped = new Map(Object.entries(overrides).map(([rel, text]) => [join(root, rel), text]));
  host.getSourceFile = (name, version, ...rest) => {
    if (swapped.has(resolve(name))) return ts.createSourceFile(name, swapped.get(resolve(name)), version, true);
    if (!PARSED.has(name)) PARSED.set(name, fromDisk(name, version, ...rest));
    return PARSED.get(name);
  };
  return ts.createProgram(files.map((f) => join(root, f)), { ...CONFIG.options, noEmit: true }, host);
}

/** What the users take from the module that it does not export, and lazy require()s not typed from it. */
function unexported(program, files) {
  const checker = program.getTypeChecker();
  const exported = moduleExports(checker, program);
  assert.ok(exported.has("isShieldRunning") && exported.has("analyzeMessage"), "read the module's exports");
  const missing = [];
  const untyped = [];
  const lazy = new Set();
  const isModulePathTo = (lit) => Boolean(lit && ts.isStringLiteral(lit) && /\/modules\/cleanway-vpn$/.test(lit.text));
  for (const f of files) {
    const visit = (node) => {
      // import { a, b as c } from "../../modules/cleanway-vpn"
      if (ts.isImportDeclaration(node) && isModulePathTo(node.moduleSpecifier)) {
        for (const el of node.importClause?.namedBindings?.elements ?? []) {
          const name = (el.propertyName ?? el.name).text;
          if (!exported.has(name)) missing.push(`${f}: import ${name}`);
        }
      }
      // require("../../modules/cleanway-vpn") as T — T must be the module's own type.
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === "require"
          && isModulePathTo(node.arguments[0])) {
        lazy.add(f);
        const cast = node.parent;
        if (!ts.isAsExpression(cast) || !isModuleType(checker.getTypeFromTypeNode(cast.type))) untyped.push(f);
      }
      // shield.startShield(), shield?.x?.(), shieldModule()?.allowDomain(…)
      if (ts.isPropertyAccessExpression(node)) {
        const type = checker.getNonNullableType(checker.getTypeAtLocation(node.expression));
        if (isModuleType(type) && !exported.has(node.name.text)) missing.push(`${f}: .${node.name.text}`);
      }
      ts.forEachChild(node, visit);
    };
    visit(program.getSourceFile(join(root, f)));
  }
  return { missing, untyped, lazy: [...lazy] };
}

const USERS = consumers();

await check("every name the app takes from modules/cleanway-vpn is exported, typed from the module", () => {
  assert.ok(USERS.length >= 15, `found the module's users (${USERS.length})`);
  const { missing, untyped, lazy } = unexported(compile(USERS), USERS);
  assert.ok(lazy.length >= 4, `found the lazy require()s (${lazy.join(", ")})`);
  assert.deepEqual(untyped, [], "require() cast to a hand-written type, not typeof import(...)");
  assert.deepEqual(missing, []);
});

await check("the export check sees a name the module does not export, and a hand-written cast", () => {
  const swap = (rel, from, to) => {
    const text = read(rel);
    assert.ok(text.includes(from), `${rel} has ${from}`);
    return [rel, text.split(from).join(to)];
  };
  const overrides = Object.fromEntries([
    swap("src/hooks/useProtectionActive.ts", "isShieldRunning", "isVpnRunning"),
    swap("src/hooks/useNetworkShield.ts", "shield.isShieldRunning()", "shield.isVpnRunning()"),
    swap("src/hooks/useShieldBlockTotals.ts", 'type ShieldLogModule = typeof import("../../modules/cleanway-vpn");',
      "interface ShieldLogModule { shieldBlockTotals(): { blocked: number; warned: number } }"),
  ]);
  const { missing, untyped } = unexported(compile(USERS, overrides), USERS);
  assert.deepEqual(missing.sort(), [
    "src/hooks/useNetworkShield.ts: .isVpnRunning",
    "src/hooks/useNetworkShield.ts: .isVpnRunning",
    "src/hooks/useProtectionActive.ts: import isVpnRunning",
  ]);
  assert.deepEqual(untyped, ["src/hooks/useShieldBlockTotals.ts"]);
});

if (failures > 0) {
  console.log(`\n${failures} failing`);
  process.exit(1);
}
console.log("\nno VPN names in the shared code: all passed");
