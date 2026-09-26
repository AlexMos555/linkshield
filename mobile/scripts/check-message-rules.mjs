#!/usr/bin/env node
/**
 * Asset check for the on-device message check's vocabulary — run with
 * `node scripts/check-message-rules.mjs`.
 *
 * message_rules.json is hand-edited, and a broken one does not crash
 * anything: MessageCheck.rules() falls back to an empty vocabulary with a
 * single log line, and MessageRules.group() reads a renamed group as empty.
 * Either way the APK ships with the text check silently off — every message
 * "no signals" unless its link is on the list — and nobody is told. The
 * Kotlin tests would catch it, but they run only in the local sandbox, not
 * in CI. So this pins the asset itself:
 *  - it is strict JSON (JSON.parse is stricter than Android's org.json);
 *  - every group the analyzer reads (MessageRules.REQUIRED_GROUPS, read from
 *    the Kotlin source so the two cannot drift) is present and non-empty;
 *  - every organisation has an id, a known kind and at least one name.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const android = resolve(here, "../modules/cleanway-vpn/android/src/main");
const assetPath = resolve(android, "assets/message_rules.json");
const kotlin = readFileSync(resolve(android, "java/ai/cleanway/app/MessageRules.kt"), "utf8");

const errors = [];

// const val THREAT = "threat" → { THREAT: "threat" }
const names = Object.fromEntries(
  [...kotlin.matchAll(/const val ([A-Z_]+) = "([a-z_]+)"/g)].map((m) => [m[1], m[2]]),
);
const requiredBlock = kotlin.match(/val REQUIRED_GROUPS = listOf\(([\s\S]*?)\)/)?.[1] ?? "";
const required = requiredBlock.split(",").map((s) => s.trim()).filter(Boolean);
if (required.length === 0) errors.push("REQUIRED_GROUPS not found in MessageRules.kt");
for (const constant of required) {
  if (!names[constant]) errors.push(`REQUIRED_GROUPS names ${constant}, which has no const val`);
}
const kinds = (kotlin.match(/enum class Kind \{([^}]*)\}/)?.[1] ?? "")
  .split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);

let rules = null;
try {
  rules = JSON.parse(readFileSync(assetPath, "utf8"));
} catch (e) {
  errors.push(`message_rules.json is not valid JSON: ${e.message}`);
}

const nonEmptyStrings = (value) =>
  Array.isArray(value) && value.length > 0 && value.every((v) => typeof v === "string" && v.trim() !== "");

if (rules) {
  for (const constant of required) {
    const group = names[constant];
    if (group && !nonEmptyStrings(rules.groups?.[group])) {
      errors.push(`group "${group}" is missing, empty or has a non-string entry`);
    }
  }
  const orgs = Array.isArray(rules.organisations) ? rules.organisations : [];
  if (orgs.length === 0) errors.push("no organisations");
  for (const [i, org] of orgs.entries()) {
    const label = org?.id ?? `#${i}`;
    if (typeof org?.id !== "string" || org.id === "") errors.push(`organisation ${label}: no id`);
    if (!kinds.includes(String(org?.kind))) errors.push(`organisation ${label}: unknown kind "${org?.kind}"`);
    if (!nonEmptyStrings(org?.names)) errors.push(`organisation ${label}: no names`);
  }
  for (const list of ["negators", "shorteners", "messengers", "trusted_domains", "bare_tlds", "country_tlds", "app_stores"]) {
    if (!nonEmptyStrings(rules[list])) errors.push(`list "${list}" is missing or empty`);
  }
}

if (errors.length > 0) {
  console.error("message_rules.json check failed:");
  for (const e of errors) console.error(`  - ${e}`);
  process.exit(1);
}
console.log(`message_rules.json ok: ${required.length} groups, ${rules.organisations.length} organisations`);
