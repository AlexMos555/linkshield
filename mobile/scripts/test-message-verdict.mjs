#!/usr/bin/env node
/**
 * Table test for src/utils/message-verdict.ts — run with
 * `node scripts/test-message-verdict.mjs`.
 *
 * The JS half of the SMS check decides three things a person relies on, and
 * each has a way to fail quietly:
 *  - which hosts leave the phone: a shortener or messenger host would come
 *    back "popular, clean" and say nothing about the real destination; an IP
 *    is not a domain; more than MAX_SERVER_CHECKS drains the per-IP quota;
 *  - how server answers fold in: a "safe" site must never clear a message that
 *    asks for a code, and a dangerous one must make the message dangerous;
 *  - how shared text is routed: a bare link keeps the link check, a message
 *    goes to the message check.
 * Same approach as test-host-parser.mjs: compile the one file with the tree's
 * TypeScript, run the table for real, exit non-zero on failure.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { deepStrictEqual } from "node:assert";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const src = resolve(root, "src/utils/message-verdict.ts");
const out = mkdtempSync(join(tmpdir(), "cleanway-verdict-"));

const link = (host, extra = {}) => ({
  text: `https://${host}/x?token=1`, host, status: "unknown", shortener: false, messenger: false, ...extra,
});

try {
  execFileSync(
    "npx",
    [
      "tsc", src, "--outDir", out, "--rootDir", root,
      "--module", "esnext", "--target", "es2020", "--moduleResolution", "bundler", "--skipLibCheck",
    ],
    { cwd: root, stdio: "inherit" },
  );

  const m = await import(pathToFileURL(join(out, "src/utils/message-verdict.js")).href);

  const CASES = [
    // ── share routing ────────────────────────────────────────────────
    ["a bare link is not a message", () => m.isMessageText("https://evil.tld/x?s=1"), false],
    ["a bare link with spaces around is not a message", () => m.isMessageText("  evil.tld \n"), false],
    ["words around a link are a message", () => m.isMessageText("Ваша карта заблокирована: evil.tld"), true],
    ["two links are a message", () => m.isMessageText("a.tld\nb.tld"), true],
    ["plain words are a message", () => m.isMessageText("Мама, это я, срочно нужны деньги"), true],
    ["empty is not a message", () => m.isMessageText(""), false],

    // ── which hosts leave the phone ─────────────────────────────────
    [
      "only unknown, non-shortener, non-messenger hosts are sent; listed/allowed/system never",
      () => m.planServerChecks([
        link("listed.tld", { status: "blocked" }),
        link("allowed.tld", { status: "allowed_by_user" }),
        link("docs.google.com", { status: "system" }),
        link("clck.ru", { shortener: true }),
        link("t.me", { messenger: true }),
        link("new.tld"),
      ]),
      { "new.tld": { kind: "pending" } },
    ],
    [
      "duplicates collapse; beyond the cap is not sent",
      () => m.planServerChecks([link("a.tld"), link("a.tld"), link("b.tld"), link("c.tld"), link("d.tld")]),
      {
        "a.tld": { kind: "pending" }, "b.tld": { kind: "pending" },
        "c.tld": { kind: "pending" }, "d.tld": { kind: "not_sent" },
      },
    ],
    [
      "an IP address is not a domain: never sent, and does not use up the cap",
      () => m.planServerChecks([link("192.168.1.10"), link("a.tld"), link("b.tld"), link("c.tld")]),
      {
        "192.168.1.10": { kind: "not_sent" },
        "a.tld": { kind: "pending" }, "b.tld": { kind: "pending" }, "c.tld": { kind: "pending" },
      },
    ],
    [
      "pendingHosts lists only what waits for the server",
      () => m.pendingHosts({ "a.tld": { kind: "pending" }, "b.tld": { kind: "not_sent" } }),
      ["a.tld"],
    ],

    // ── folding server answers in ───────────────────────────────────
    [
      "a dangerous site makes a no-signals message dangerous, reason first",
      () => m.mergeVerdict(
        { verdict: "no_signals", reasons: [] },
        { "a.tld": { kind: "checked", level: "dangerous" } },
      ),
      { verdict: "dangerous", reasons: ["link_checked_dangerous"] },
    ],
    [
      "a clean site never clears a message that asks for a code",
      () => m.mergeVerdict(
        { verdict: "dangerous", reasons: ["asks_for_code"] },
        { "a.tld": { kind: "checked", level: "safe" } },
      ),
      { verdict: "dangerous", reasons: ["asks_for_code"] },
    ],
    [
      "a suspicious site raises no-signals to caution",
      () => m.mergeVerdict(
        { verdict: "no_signals", reasons: [] },
        { "a.tld": { kind: "checked", level: "caution" } },
      ),
      { verdict: "caution", reasons: ["link_checked_caution"] },
    ],
    [
      "a listed link already says it: no second 'dangerous site' reason",
      () => m.mergeVerdict(
        { verdict: "dangerous", reasons: ["link_blocklisted"] },
        { "a.tld": { kind: "checked", level: "dangerous" } },
      ),
      { verdict: "dangerous", reasons: ["link_blocklisted"] },
    ],
    [
      "failed and pending checks change nothing",
      () => m.mergeVerdict(
        { verdict: "caution", reasons: ["threat_or_urgency"] },
        { "a.tld": { kind: "failed", why: "rate_limited" }, "b.tld": { kind: "pending" } },
      ),
      { verdict: "caution", reasons: ["threat_or_urgency"] },
    ],
    ["escalation: caution → dangerous", () => m.isEscalation("caution", "dangerous"), true],
    ["no escalation: dangerous → caution", () => m.isEscalation("dangerous", "caution"), false],

    // ── one link row ────────────────────────────────────────────────
    ["listed wins over everything", () => m.linkVerdict(link("x.tld", { status: "blocked", shortener: true }), {}), "blocked"],
    ["a shortener is never shown as clean", () => m.linkVerdict(link("clck.ru", { shortener: true }), {}), "shortener"],
    ["a person-allowed site reads 'allowed'", () => m.linkVerdict(link("mine.tld", { status: "allowed_by_user" }), {}), "allowed"],
    ["a system host is its own neutral row, never 'allowed'", () => m.linkVerdict(link("sites.google.com", { status: "system" }), {}), "system"],
    ["server said safe → clean", () => m.linkVerdict(link("a.tld"), { "a.tld": { kind: "checked", level: "safe" } }), "clean"],
    ["rate limit is named", () => m.linkVerdict(link("a.tld"), { "a.tld": { kind: "failed", why: "rate_limited" } }), "rate_limited"],
    ["an unknown error is 'failed'", () => m.linkVerdict(link("a.tld"), { "a.tld": { kind: "failed", why: "error" } }), "failed"],
    ["over the cap reads 'not checked'", () => m.linkVerdict(link("d.tld"), { "d.tld": { kind: "not_sent" } }), "not_checked"],

    // ── a calm verdict is not a link check ──────────────────────────
    ["no links: nothing to say about links", () => m.linksState([], {}), "none"],
    [
      "a link still waiting for the server: checking",
      () => m.linksState([link("a.tld"), link("b.tld")], { "a.tld": { kind: "checked", level: "safe" }, "b.tld": { kind: "pending" } }),
      "checking",
    ],
    [
      "a link the server could not answer for: unchecked",
      () => m.linksState([link("a.tld")], { "a.tld": { kind: "failed", why: "rate_limited" } }),
      "unchecked",
    ],
    [
      "a short link or a shared Google host is never counted as checked",
      () => [
        m.linksState([link("clck.ru", { shortener: true })], {}),
        m.linksState([link("sites.google.com", { status: "system" })], {}),
      ],
      ["unchecked", "unchecked"],
    ],
    [
      "every link answered by the server or allowed by the person: checked",
      () => m.linksState(
        [link("a.tld"), link("mine.tld", { status: "allowed_by_user" })],
        { "a.tld": { kind: "checked", level: "safe" } },
      ),
      "checked",
    ],

    // ── what to do ──────────────────────────────────────────────────
    [
      "no signals: the two rules that always apply",
      () => m.adviceFor({ verdict: "no_signals", reasons: [], hasLinks: true, hasPhones: true }),
      ["no_code", "call_yourself"],
    ],
    [
      "no signals with a link we could not check: don't open it comes first",
      () => m.adviceFor({ verdict: "no_signals", reasons: [], hasLinks: true, hasPhones: false, linksUnchecked: true }),
      ["no_link", "no_code", "call_yourself"],
    ],
    [
      "dangerous callback scam: don't reply, call yourself, delete",
      () => m.adviceFor({
        verdict: "dangerous", reasons: ["claims_organisation", "threat_or_urgency", "call_unknown_number"],
        hasLinks: false, hasPhones: true,
      }),
      ["no_reply", "call_yourself", "delete"],
    ],
    [
      "relative in trouble: call them back on the old number, never 'call the bank'",
      () => m.adviceFor({ verdict: "dangerous", reasons: ["relative_in_trouble"], hasLinks: false, hasPhones: false }),
      ["no_money", "call_relative", "delete"],
    ],
    [
      "never more than four lines: the costliest mistakes first, the closing steps always survive",
      () => m.adviceFor({
        verdict: "dangerous", reasons: ["asks_for_code", "safe_account", "install_app"],
        hasLinks: true, hasPhones: true,
      }),
      ["no_code", "no_money", "call_yourself", "delete"],
    ],
    [
      "a phishing link under a bank's name: don't open it",
      () => m.adviceFor({
        verdict: "caution", reasons: ["claims_organisation", "link_not_official"], hasLinks: true, hasPhones: false,
      }),
      ["no_link", "call_yourself"],
    ],

    // ── what history keeps ──────────────────────────────────────────
    [
      "history keeps hosts, verdict and codes — never the link as written",
      () => m.historyEntry(
        [link("a.tld"), link("a.tld"), link("b.tld")],
        { verdict: "dangerous", reasons: ["link_blocklisted"] },
      ),
      { hosts: ["a.tld", "b.tld"], level: "dangerous", reasons: ["link_blocklisted"] },
    ],
    ["stored verdicts are recognised", () => m.isMessageVerdict("no_signals"), true],
    ["'safe' is not a message verdict", () => m.isMessageVerdict("safe"), false],
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
  if (failed > 0) {
    console.error(`\n${failed} of ${CASES.length} cases failed`);
    process.exitCode = 1;
  } else {
    console.log(`\nall ${CASES.length} cases pass`);
  }
} finally {
  rmSync(out, { recursive: true, force: true });
}
