#!/usr/bin/env node
/**
 * Icon import guard — run with `node mobile/scripts/check-icon-imports.mjs`.
 *
 * `import { Ionicons } from "@expo/vector-icons"` loads the package index,
 * which requires every icon family. Metro does not tree-shake, so all of
 * their glyph maps ship in the app bundle — MaterialIcons' "vpn-key" and
 * "vpn-lock" among them. Apple's automated review flagged 1.0.4 for "VPN
 * functionality" (docs/IOS.md §3.6), so the iPhone bundle carries no VPN
 * word it does not need. Import each family by its own path instead:
 * `import Ionicons from "@expo/vector-icons/Ionicons"`.
 *
 * Scans every .ts/.tsx/.js/.jsx under mobile/app, mobile/src and
 * mobile/modules; `--self-test` checks the matcher on known inputs.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname, resolve, relative } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const mobile = resolve(here, "..");
const ROOTS = ["app", "src", "modules"].map((d) => join(mobile, d));
const SOURCE = /\.(tsx?|jsx?)$/;

// The bare package specifier in an import/export ... from, a side-effect
// import, require() or import(); a family path ("@expo/vector-icons/X") is fine.
const BARE = /(?:\bfrom\s*|\bimport\s*|\brequire\s*\(\s*|\bimport\s*\(\s*)["']@expo\/vector-icons["']/;

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) {
      if (name === "node_modules" || name === "android" || name === "ios") continue;
      walk(p, out);
    } else if (SOURCE.test(name)) {
      out.push(p);
    }
  }
  return out;
}

function selfTest() {
  const bad = [
    'import { Ionicons } from "@expo/vector-icons";',
    "import {Ionicons} from '@expo/vector-icons'",
    'export { Ionicons } from "@expo/vector-icons";',
    'import "@expo/vector-icons";',
    'const { Ionicons } = require("@expo/vector-icons");',
    'const m = await import("@expo/vector-icons");',
  ];
  const good = [
    'import Ionicons from "@expo/vector-icons/Ionicons";',
    'const Ionicons = require("@expo/vector-icons/Ionicons");',
    "// see @expo/vector-icons createIconSet",
  ];
  const wrong = [...bad.filter((s) => !BARE.test(s)), ...good.filter((s) => BARE.test(s))];
  if (wrong.length) {
    console.error("check-icon-imports self-test failed on:\n  " + wrong.join("\n  "));
    process.exit(1);
  }
  console.log(`ok: self-test (${bad.length} caught, ${good.length} allowed)`);
}

if (process.argv.includes("--self-test")) {
  selfTest();
} else {
  const files = ROOTS.flatMap((r) => walk(r));
  const offenders = files.filter((f) => BARE.test(readFileSync(f, "utf8")));
  if (offenders.length) {
    console.error(
      "These files import the @expo/vector-icons index, which bundles every icon family's glyph names" +
        ' (MaterialIcons "vpn-key" included). Import the family by path, e.g.' +
        ' `import Ionicons from "@expo/vector-icons/Ionicons"`:\n  ' +
        offenders.map((f) => relative(mobile, f)).join("\n  "),
    );
    process.exit(1);
  }
  console.log(`ok: ${files.length} files import icon families by path only`);
}
