#!/usr/bin/env node
/**
 * Table test for src/lib/entitlement.ts — run with `node scripts/test-entitlement.mjs`.
 *
 * The device pass is what tells the native shield whether this phone is
 * paid for, so the phone must read it exactly like the server writes it. The
 * cases below are the server's own (tests/billing/test_entitlement.py), run
 * against the JS port: the JWS shape, every rejection reason, key rotation,
 * and the offline rule — a clock turned back extends nothing, a trial has no
 * grace, an open-ended pass keeps its mode.
 *
 * Tokens are signed here with tweetnacl the way the billing role signs them
 * (Ed25519 over `b64url(header).b64url(payload)`, canonical JSON with sorted
 * keys), so the test also pins that the two JSON encodings agree.
 */
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { deepStrictEqual, strictEqual, throws } from "node:assert";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const appRequire = createRequire(join(root, "package.json"));
const ts = appRequire("typescript");
const nacl = appRequire("tweetnacl");

/** CommonJS-load a .ts file of the app; bare specifiers come from node_modules. */
function loadTs(file) {
  const { outputText } = ts.transpileModule(readFileSync(file, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, esModuleInterop: true },
    fileName: file,
  });
  const module = { exports: {} };
  const requireHere = (spec) => (spec.startsWith(".") ? loadTs(resolve(dirname(file), `${spec}.ts`)) : appRequire(spec));
  new Function("require", "module", "exports", outputText)(requireHere, module, module.exports);
  return module.exports;
}

const {
  PASS_VERSION, PassInvalid, verifyPass, decodePass, claimsFromPayload, offlineMode, nextModeChange, base64UrlDecode,
} = loadTs(join(root, "src/lib/entitlement.ts"));

const NOW = 1_800_000_000;
const DAY = 86_400;

// ── a signer like the server's ─────────────────────────────────────

const b64url = (bytes) => Buffer.from(bytes).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
const canonical = (obj) => JSON.stringify(Object.fromEntries(Object.entries(obj).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))));

function signer(kid) {
  const pair = nacl.sign.keyPair();
  return {
    kid,
    publicB64: Buffer.from(pair.publicKey).toString("base64"),
    sign(claims, header = { alg: "EdDSA", typ: "JWT", kid }) {
      const input = `${b64url(Buffer.from(canonical(header)))}.${b64url(Buffer.from(canonical(claims)))}`;
      const sig = nacl.sign.detached(Buffer.from(input, "ascii"), pair.secretKey);
      return `${input}.${b64url(sig)}`;
    },
  };
}

function claims(overrides = {}) {
  return {
    v: PASS_VERSION, dev: "dev-1", mode: "full", src: "subscription", lapse_policy: "basic", iat: NOW, exp: NOW + 7 * DAY,
    plan: "family3", until: NOW + 20 * DAY, grace_until: NOW + 27 * DAY, ...overrides,
  };
}

const reasonOf = (fn) => {
  try {
    fn();
  } catch (e) {
    if (e instanceof PassInvalid) return e.reason;
    throw e;
  }
  return "no error";
};

const k1 = signer("k1");
const ring = { k1: k1.publicB64 };

const CASES = [
  ["a signed pass verifies and reads back as the same claims, no personal data", () => {
    const token = k1.sign(claims());
    const [h, p] = token.split(".").slice(0, 2).map((part) => JSON.parse(Buffer.from(part, "base64url").toString()));
    return { header: h, keys: Object.keys(p).sort(), claims: verifyPass(token, ring, NOW + 1) };
  }, {
    header: { alg: "EdDSA", typ: "JWT", kid: "k1" },
    keys: ["dev", "exp", "grace_until", "iat", "lapse_policy", "mode", "plan", "src", "until", "v"],
    claims: claims(),
  }],
  ["a tampered payload fails the signature", () => {
    const [h, , s] = k1.sign(claims()).split(".");
    const forged = b64url(Buffer.from(canonical({ ...claims(), mode: "full", until: null })));
    return reasonOf(() => verifyPass(`${h}.${forged}.${s}`, ring, NOW));
  }, "bad_signature"],
  ["a foreign key is rejected", () => reasonOf(() => verifyPass(k1.sign(claims()), { k1: signer("x").publicB64 }, NOW)), "bad_signature"],
  ["an unknown kid is rejected", () => reasonOf(() => verifyPass(k1.sign(claims()), { k2: k1.publicB64 }, NOW)), "unknown_kid"],
  ["an expired pass is rejected on arrival, at exp exactly", () => {
    const token = k1.sign(claims());
    return [Boolean(verifyPass(token, ring, NOW + 7 * DAY - 1)), reasonOf(() => verifyPass(token, ring, NOW + 7 * DAY))];
  }, [true, "expired"]],
  ["malformed tokens", () => ["not.a.jws.at.all", "a.b", "!!!.b.c", ""].map((t) => reasonOf(() => verifyPass(t, ring, NOW))),
    ["malformed", "malformed", "malformed", "malformed"]],
  ["alg none is rejected before anything else", () => {
    const h = b64url(Buffer.from('{"alg":"none","kid":"k1"}'));
    const p = b64url(Buffer.from(JSON.stringify(claims())));
    return reasonOf(() => verifyPass(`${h}.${p}.`, ring, NOW));
  }, "unsupported_alg"],
  ["a later pass version is not trusted", () => reasonOf(() => verifyPass(k1.sign(claims({ v: 2 })), ring, NOW)), "unsupported_version"],
  ["rotation: the old kid verifies until it is removed", () => {
    const oldK = signer("2026-09");
    const newK = signer("2026-12");
    const both = { "2026-09": oldK.publicB64, "2026-12": newK.publicB64 };
    const onlyNew = { "2026-12": newK.publicB64 };
    return [
      Boolean(verifyPass(oldK.sign(claims()), both, NOW)), Boolean(verifyPass(newK.sign(claims()), both, NOW)),
      Boolean(verifyPass(newK.sign(claims()), onlyNew, NOW)), reasonOf(() => verifyPass(oldK.sign(claims()), onlyNew, NOW)),
    ];
  }, [true, true, true, "unknown_kid"]],
  ["garbage payloads are malformed", () => [
    reasonOf(() => claimsFromPayload({ v: 1, dev: "d", mode: "turbo" })),
    reasonOf(() => claimsFromPayload({ ...claims(), until: "soon" })),
    reasonOf(() => claimsFromPayload([1, 2])),
    reasonOf(() => claimsFromPayload({ ...claims(), dev: "" })),
  ], ["malformed", "malformed", "malformed", "malformed"]],
  ["a stored pass reads back without its signature being checked", () => decodePass(signer("gone").sign(claims())).claims, claims()],
  ["an unsigned pass never verifies", () => reasonOf(() => verifyPass(`${k1.sign(claims()).split(".").slice(0, 2).join(".")}.`, ring, NOW)), "bad_signature"],

  // ── the offline rule (the server's cases, verbatim) ──
  ["full until, full through grace, then the lapse policy", () => {
    const c = claims();
    return [offlineMode(c, NOW + 19 * DAY), offlineMode(c, NOW + 26 * DAY), offlineMode(c, NOW + 27 * DAY),
      offlineMode(claims({ lapse_policy: "off" }), NOW + 27 * DAY)];
  }, ["full", "full", "basic", "off"]],
  ["a clock turned back cannot extend the pass", () => {
    const c = claims({ until: NOW + 1 * DAY, grace_until: null });
    return [offlineMode(c, NOW - 365 * DAY), offlineMode(c, NOW + 1 * DAY)];
  }, ["full", "basic"]],
  ["a trial has no grace", () => {
    const c = claims({ src: "trial", plan: null, until: NOW + 14 * DAY, grace_until: null });
    return [offlineMode(c, NOW + 13 * DAY), offlineMode(c, NOW + 14 * DAY)];
  }, ["full", "basic"]],
  ["an open-ended pass keeps its mode", () => [
    offlineMode(claims({ src: "legacy", plan: null, until: null, grace_until: null }), NOW + 10 * 365 * DAY),
    offlineMode(claims({ mode: "basic", src: "none", until: null, grace_until: null }), NOW + 30 * DAY),
  ], ["full", "basic"]],
  ["when the mode next changes: at the end of grace, else at until, never for an open-ended pass", () => [
    nextModeChange(claims(), NOW + 1), nextModeChange(claims(), NOW + 21 * DAY), nextModeChange(claims(), NOW + 28 * DAY),
    nextModeChange(claims({ grace_until: null }), NOW), nextModeChange(claims({ until: null, grace_until: null }), NOW),
    nextModeChange(claims(), NOW - 100 * DAY),
  ], [NOW + 27 * DAY, NOW + 27 * DAY, null, NOW + 20 * DAY, null, NOW + 27 * DAY]],
  ["base64url: padded, unpadded and plain base64 all decode; junk does not", () => [
    Buffer.from(base64UrlDecode("aGk")).toString(), Buffer.from(base64UrlDecode("aGk=")).toString(),
    Buffer.from(base64UrlDecode(Buffer.from([251, 255]).toString("base64"))).equals(Buffer.from([251, 255])),
    reasonOf(() => base64UrlDecode("a")), reasonOf(() => base64UrlDecode("a*b=")),
  ], ["hi", "hi", true, "malformed", "malformed"]],
];

let failed = 0;
for (const [name, run, expected] of CASES) {
  try {
    deepStrictEqual(run(), expected);
    console.log(`  ok    ${name}`);
  } catch (e) {
    failed += 1;
    console.log(`  FAIL  ${name}\n        ${String(e.message).split("\n").join("\n        ")}`);
  }
}
void strictEqual;
void throws;
if (failed > 0) {
  console.error(`\n${failed} of ${CASES.length} cases failed`);
  process.exitCode = 1;
} else {
  console.log(`\nall ${CASES.length} cases pass`);
}
