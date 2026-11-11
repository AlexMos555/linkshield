#!/usr/bin/env node
/**
 * decode-uri-component 0.2.2 with the 0.5.1 fix backported — run with
 * `node mobile/scripts/test-decode-uri-component.mjs`. CI runs it in the
 * mobile job; the build mirror right after `npm install`
 * (docs/RUSTORE_SUBMISSION.md §2).
 *
 * The hole (docs/EXPO_UPGRADE_PLAN.md §1.2): when the built-in
 * decodeURIComponent throws (one trailing "%zz" is enough), 0.2.2 falls back
 * to code that is quadratic in the input. GHSA-qr28-fpjm-wq7f: one full-string
 * RegExp replace per DISTINCT percent-encoded run, 224 KB = 30 s on the build
 * Mac. CVE-2026-45822: a recursive decode() of one long run, 2.4 KB = 21 s.
 * Upstream fixed both in 0.5.0 / 0.5.1, which are ESM-only; query-string@7
 * (expo-router 6) require()s 0.2.x, so Dependabot cannot update it.
 * mobile/patches/decode-uri-component+0.2.2.patch is 0.5.1's decoder in
 * 0.2.2's CommonJS, and scripts/apply-patches.js applies it on every install.
 * Nothing in the app reaches the fallback today (expo-router 6.0.24 parses
 * cleanway:// links with URL and only stringify()s with query-string); the
 * module is in the bundle all the same, and the patch is for the day a
 * queryString.parse() shows up.
 *
 * Checked, on the copy query-string actually loads:
 *  1. it is 0.2.2 with the patch applied, byte for byte;
 *  2. 0.2.2's own test vectors give exactly what they gave before, `+` as a
 *     space included, and well-formed input is decoded as the built-in does;
 *  3. 0.5.1's test vectors pass (the ones without `+`: 0.5.x keeps it);
 *  4. both attacks finish in well under a second.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const mobile = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PKG = "decode-uri-component";
const VERSION = "0.2.2";
const PATCH = join(mobile, "patches", `${PKG}+${VERSION}.patch`);
/**
 * Git blob id (`git hash-object`) of index.js in npm 0.2.2, the same file as
 * tag v0.2.2 upstream. To re-check:
 *   gh api "repos/SamVerschueren/decode-uri-component/contents/index.js?ref=v0.2.2" \
 *     --jq .content | base64 -d | git hash-object --stdin
 */
const UPSTREAM_022 = "24e7db0cc55aa22d0f98358b73298067deb33b52";

// The copy the app bundles: expo-router -> query-string -> decode-uri-component.
let pkgDir;
try {
  const fromMobile = createRequire(join(mobile, "package.json"));
  const fromRouter = createRequire(fromMobile.resolve("expo-router/package.json"));
  const fromQueryString = createRequire(fromRouter.resolve("query-string/package.json"));
  pkgDir = dirname(fromQueryString.resolve(`${PKG}/package.json`));
} catch (e) {
  // SDK 58 (docs/EXPO_UPGRADE_PLAN.md §4.2): expo-router without query-string.
  console.log(`  FAIL  expo-router no longer reaches ${PKG} through query-string (${e.message.split("\n")[0]}).`);
  console.log(`        Delete mobile/patches/${PKG}+${VERSION}.patch, this test and its CI step.`);
  process.exit(1);
}
const version = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8")).version;
const bytes = readFileSync(join(pkgDir, "index.js"));
const gitBlobId = (buf) => createHash("sha1").update(`blob ${buf.length}\0`).update(buf).digest("hex");

let failed = 0;
let passed = 0;
const check = (name, ok, detail = "") => {
  if (ok) {
    passed++;
    return;
  }
  failed++;
  console.log(`  FAIL  ${name}${detail ? `\n        ${detail}` : ""}`);
};
const show = (s) => JSON.stringify(s);

// 1. The installed file.
{
  const got = gitBlobId(bytes);
  if (version !== VERSION) {
    check(`${PKG} ${version} is installed, the patch is for ${VERSION}`, false,
      "query-string moved on: if this version decodes in linear time, delete " +
      `mobile/patches/${PKG}+${VERSION}.patch and this test`);
  } else if (!existsSync(PATCH)) {
    check(`mobile/patches/${PKG}+${VERSION}.patch is missing`, false);
  } else {
    const text = readFileSync(PATCH, "utf8");
    const files = [...text.matchAll(/^diff --git a\/\S+ b\/(\S+)$/gm)].map((m) => m[1]);
    const index = text.match(/^index ([0-9a-f]{40})\.\.([0-9a-f]{40}) /m);
    if (files.join() !== `node_modules/${PKG}/index.js`) {
      check(`the patch must change index.js and nothing else; it changes ${files.join(", ") || "nothing"}`, false);
    } else if (!index) {
      check(`the patch lost its full "index <before>..<after>" line (git diff --full-index)`, false);
    } else if (index[1] !== UPSTREAM_022) {
      check(`the patch is not made against npm ${VERSION}: it starts from ${index[1]}, expected ${UPSTREAM_022}`, false);
    } else if (got === UPSTREAM_022) {
      check(`the patch did not apply: index.js is still upstream ${VERSION}'s (npm install --ignore-scripts skips postinstall)`, false);
    } else {
      check(`index.js is neither upstream ${VERSION}'s nor the patched file (git blob ${got})`, got === index[2],
        "edited by hand, or patched twice");
    }
  }
  if (failed === 0) console.log(`  ok    ${pkgDir}: ${VERSION} with the patch applied (git blob ${got.slice(0, 7)})`);
}

const require = createRequire(import.meta.url);
const decode = require(join(pkgDir, "index.js"));
const table = (name, vectors) => {
  const before = failed;
  for (const [input, expected] of Object.entries(vectors)) {
    let got;
    try {
      got = decode(input);
    } catch (e) {
      got = `threw ${e.message}`;
    }
    check(`${name}: ${show(input)}`, got === expected, `got ${show(got)}, want ${show(expected)}`);
  }
  if (failed === before) console.log(`  ok    ${name} (${Object.keys(vectors).length})`);
};

// 2. Nothing changes for what 0.2.2 already got right.
// 0.2.2's test.js, verbatim.
table("0.2.2 test vectors", {
  "test": "test",
  "a+b": "a b",
  "a+b+c+d": "a b c d",
  "=a": "=a",
  "%": "%",
  "%25": "%",
  "%%25%%": "%%%%",
  "st%C3%A5le": "ståle",
  "st%C3%A5le%": "ståle%",
  "%st%C3%A5le%": "%ståle%",
  "%%7Bst%C3%A5le%7D%": "%{ståle}%",
  "%ab%C3%A5le%": "%abåle%",
  "%C3%A5%able%": "å%able%",
  "%7B%ab%7C%de%7D": "{%ab|%de}",
  "%7B%ab%%7C%de%%7D": "{%ab%|%de%}",
  "%7 B%ab%%7C%de%%7 D": "%7 B%ab%|%de%%7 D",
  "%ab": "%ab",
  "%ab%ab%ab": "%ab%ab%ab",
  "%61+%4d%4D": "a MM",
  "﻿test": "﻿test",
  "﻿": "﻿",
  "%EF%BB%BFtest": "﻿test",
  "%EF%BB%BF": "﻿",
  "%FE%FF": "��",
  "%FF%FE": "��",
  "†": "†",
  "%C2": "�",
  "%C2x": "�x",
  "%C2%B5": "µ",
  "%C2%B5%": "µ%",
  "%%C2%B5%": "%µ%",
  "%ea%ba%5a%ba": "%ea%baZ%ba",
  "%C3%5A%A5": "%C3Z%A5",
  "%C3%5A%A5%AB": "%C3Z%A5%AB",
});
{
  let message;
  try {
    decode(5);
  } catch (e) {
    message = e.message;
  }
  check("type error", message === "Expected `encodedURI` to be of type `string`, got `number`", `got ${show(message)}`);
}
// Well-formed input never reaches the fallback: 0.2.2 returned the built-in's
// answer after `+` -> space, and so must the patched copy.
{
  const before = failed;
  let seed = 42;
  const rand = (n) => ((seed = (seed * 1103515245 + 12345) % 2 ** 31) % n);
  const alphabet = ["a", "Z", "0", " ", "+", "%", "&", "=", "/", "?", "#", "ё", "ж", "€", "†", "﻿", "😀", "你"];
  for (let i = 0; i < 2000; i++) {
    let s = "";
    for (let j = rand(24); j > 0; j--) s += alphabet[rand(alphabet.length)];
    const encoded = encodeURIComponent(s);
    check(`well-formed ${show(encoded)}`, decode(encoded) === s, `got ${show(decode(encoded))}`);
    // `+` kept literal in the input, as in a query string: still a space.
    const mixed = encoded.replace(/%2B/g, "+");
    const want = decodeURIComponent(mixed.replace(/\+/g, " "));
    check(`well-formed with + ${show(mixed)}`, decode(mixed) === want, `got ${show(decode(mixed))}, want ${show(want)}`);
  }
  if (failed === before) console.log("  ok    well-formed input decodes as decodeURIComponent, + as a space (4000)");
}

// 3. 0.5.1's test.js, the vectors without `+` (0.5.x leaves `+` alone; 0.2.2's
// rows above pin the space). Its first table is 0.2.2's, `+` aside, so only
// the others are here. Starred rows are ones 0.2.2 got wrong, mostly double
// decoding: its replace loop turned "%25" into "%" and then decoded THAT again.
table("0.5.1 test vectors", {
  "%20": " ", "%2B": "+", "%2b": "+", "%00": "\0", "%7F": "\u007F", "%09": "\t", "%0A": "\n", "%0D%0A": "\r\n",
  "%61%62%63": "abc", "%2F%3F%23": "/?#", "%7E": "~", "%E2%80%A0": "†", "%F4%8F%BF%BF": "\u{10FFFF}",
  "%ED%9F%BF": "\u{D7FF}", "%F0%9F%98%80%F0%9F%98%81": "😀😁", "%2525": "%25", "%E4%BD%A0%E5%A5%BD": "你好",
  "%E4%BD%A0%20%E5%A5%BD%21��": "你 好!��", "%F0%9D%84%9E": "𝄞", "": "",
  "%c3%a5": "å", "%C3%a5": "å", "%7b%ab%7c%de%7d": "{%ab|%de}",
  "%C2%41": "�A", "%C2%C2": "��", "%C2G5": "�G5", "prefix%C2suffix": "prefix�suffix",
  "%C3%A5%C2": "å�", "%C2%B5%C2": "µ�", "%C2%C2%B5": "�µ", "%%C2%%": "%�%%",
  "%F0%9F%98%80": "😀", "%F0%9F%98": "%F0%9F%98", "%F0%9F": "%F0%9F", "%F0": "%F0", "%F0%9F%41": "%F0%9FA",
  "%F0%41%82%83": "%F0A%82%83", "%F5%80%80%80": "%F5%80%80%80", "%F8%88%88%88": "%F8%88%88%88",
  "%C0%AF": "%C0%AF", "%C1%BF": "%C1%BF", "%E2%82%AC": "€", "%E2%82": "%E2%82", "%E2%41%AC": "%E2A%AC",
  "%E0%80%41": "%E0%80A", "%ED%A0%80": "%ED%A0%80", "%80": "%80", "%BF": "%BF", "%C3": "%C3", "%DF": "%DF",
  "%C3%41": "%C3A", "%F0%9F%98%80%ab": "😀%ab", "%C3%A5%ab": "å%ab",
  "%E0%80%80": "%E0%80%80", "%E0%80%81": "%E0%80%81", "%F0%80%80%80": "%F0%80%80%80",
  "%F0%8F%BF%BF": "%F0%8F%BF%BF", "%E0%80%80%ab": "%E0%80%80%ab", "%ED%BF%BF": "%ED%BF%BF",
  "%F4%90%80%80": "%F4%90%80%80", "%G0": "%G0", "%0G": "%0G", "%GG": "%GG", "foo%bar": "foo%bar",
  "%u0041": "%u0041", "%C1%88": "%C1%88", "%F9%80%80%80": "%F9%80%80%80", "%FA%80%80%80": "%FA%80%80%80",
  "%FB%80%80%80": "%FB%80%80%80", "%FC%80%80%80": "%FC%80%80%80", "%FD%80%80%80": "%FD%80%80%80",
  "%FE%80%80%80": "%FE%80%80%80", "%FF%80%80%80": "%FF%80%80%80", "%FF": "%FF", "%80%80%80": "%80%80%80",
  "%C3%A5%80%C3%A5": "å%80å", "%G0%C3%A5%ab": "%G0å%ab", "%F0%9F%98%80%G0": "😀%G0", "%C3%A5%%C3%A5": "å%å",
  "%ab%cd%ef": "%ab%cd%ef", "a%FE%FFb": "a��b", "%FE%FF%FE%FF": "����",
  "%41%FE%FF": "A��", // *
  "%252525": "%2525",
  "%25C2%zz": "%C2%zz", // *
  "%25%41%zz": "%A%zz", // *
  "%%%": "%%%",
  "%25C2%25": "%C2%",
  "%2525C2": "%25C2",
  "%84%D7%25%88%90": "%84%D7%%88%90", // *
  "%20%20%25%80": "  %%80", // *
});
{
  const cases = ["%25", "st%C3%A5le", "%C3%A5%ab", "%G0%C3%A5", "%"];
  for (const input of cases) {
    const once = decode(input);
    check(`idempotent once nothing is encoded: ${show(input)}`, decode(once) === once, `got ${show(decode(once))}`);
  }
}

// 4. The attacks: 30 s and 20 s on unpatched 0.2.2 (build Mac, Node 22), and
// hours for the second one at this size. Each runs in a child that is killed
// after 10 s, so a patch that did not apply fails here instead of hanging CI.
const attack = (name, build) => {
  const src =
    `const decode = require(${show(join(pkgDir, "index.js"))}); const input = (${build})();` +
    "const t = process.hrtime.bigint(); decode(input);" +
    "console.log(input.length, Number(process.hrtime.bigint() - t) / 1e6);";
  const r = spawnSync(process.execPath, ["-e", src], { encoding: "utf8", timeout: 10000 });
  const [length, ms] = r.stdout.trim().split(" ").map(Number);
  const label = `${name} (${(length / 1000).toFixed(0)} KB)`;
  if (r.error || r.status !== 0) {
    // Unpatched, the second one dies of "Maximum call stack size exceeded".
    const error = r.stderr.split("\n").find((l) => /Error\b/.test(l)) ?? r.stderr;
    check(name, false, r.error?.code === "ETIMEDOUT" ? "still running after 10 s, killed" : error);
  } else {
    check(`${label}: ${ms.toFixed(0)} ms`, ms < 1000, "should be tens of milliseconds");
    if (ms < 1000) console.log(`  ok    ${label}: ${ms.toFixed(0)} ms`);
  }
};
// The advisory's proof of concept: 32 000 distinct runs and a trailing %zz.
attack("GHSA-qr28-fpjm-wq7f PoC", () => {
  let poc = "";
  for (let i = 0; i < 32000; i++) {
    const high = Math.floor(i / 256).toString(16).padStart(2, "0");
    const low = (i % 256).toString(16).padStart(2, "0");
    poc += `%${high}%${low}x`;
  }
  return poc + "%zz";
});
// One long run of bytes that never decode, for the old recursive decode().
attack("CVE-2026-45822, one run of 20 000 bad bytes", () => "%80".repeat(20000) + "%zz");

console.log(failed === 0 ? `\nall ${passed} checks pass` : `\n${failed} FAILED, ${passed} passed`);
process.exit(failed === 0 ? 0 : 1);
