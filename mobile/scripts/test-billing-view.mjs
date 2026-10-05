#!/usr/bin/env node
/**
 * Table test for src/utils/billing-view.ts — run with `node scripts/test-billing-view.mjs`.
 *
 * Every row of the subscription state → screen table (billing plan §2.5):
 * flag off hides everything; the pass's clock outranks a stale server
 * snapshot (a trial that ended offline is "ended", not "3 days left"); the
 * grace window shows its days; cancel says plainly when protection changes
 * and to what; the payer alone sees the seat screens and the cancel button.
 */
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { deepStrictEqual } from "node:assert";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const appRequire = createRequire(join(root, "package.json"));
const ts = appRequire("typescript");

// config/billing.ts reads expo-constants, a native module; the pure helpers take env + extra as arguments.
const STUBS = { "expo-constants": { __esModule: true, default: { expoConfig: null } } };

function loadTs(file) {
  const { outputText } = ts.transpileModule(readFileSync(file, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, esModuleInterop: true },
    fileName: file,
  });
  const module = { exports: {} };
  const requireHere = (spec) => {
    if (spec in STUBS) return STUBS[spec];
    return spec.startsWith(".") ? loadTs(resolve(dirname(file), `${spec}.ts`)) : appRequire(spec);
  };
  new Function("require", "module", "exports", outputText)(requireHere, module, module.exports);
  return module.exports;
}

const { billingView, cancelOutcome, modeHold, canManageSeats, canCancel, offersPlans, effectiveMode, daysLeft } =
  loadTs(join(root, "src/utils/billing-view.ts"));
const { billingFlagOn, billingApiBaseFrom, passPublicKeysFrom } = loadTs(join(root, "src/config/billing.ts"));
const { normalizeRuPhone, maskPhone, formatPhone, failureCopyKey, errorCopyKey, planLabel } = loadTs(join(root, "src/utils/billing-copy.ts"));

const NOW = 1_800_000_000;
const DAY = 86_400;

const pass = (o = {}) => ({
  v: 1, dev: "dev-1", mode: "full", src: "subscription", plan: "family3", until: NOW + 20 * DAY, grace_until: NOW + 27 * DAY,
  lapse_policy: "basic", iat: NOW, exp: NOW + 7 * DAY, ...o,
});
const sub = (o = {}) => ({
  id: "sub-1", status: "active", plan: "family3", seats_total: 3, seats_used: 2, price_kopecks: 27000, period_end: NOW + 20 * DAY,
  next_charge_at: NOW + 20 * DAY, grace_until: null, cancel_requested_at: null, is_payer: true, provider: "fake", ...o,
});
const status = (o = {}) => ({
  mode: "full", source: "subscription", plan: "family3", lapse_policy: "basic", until: NOW + 20 * DAY, grace_until: NOW + 27 * DAY,
  trial_ends_at: null, trial_used: true, subscription: sub(), notices: [], ...o,
});
const snap = (o = {}) => ({ enabled: true, status: null, claims: null, hadSubscription: false, nowSec: NOW, ...o });

const trialPass = pass({ src: "trial", plan: null, until: NOW + 14 * DAY, grace_until: null });
const trialStatus = status({ source: "trial", plan: null, until: NOW + 14 * DAY, grace_until: null, trial_ends_at: NOW + 14 * DAY, subscription: null });

const CASES = [
  ["flag off: hidden whatever the server says", () => billingView(snap({ enabled: false, status: status(), claims: pass() })), { kind: "hidden" }],
  ["flag on, never reached the server: unknown", () => billingView(snap()), { kind: "unknown" }],
  ["registered, no trial yet: the moment before the trial starts", () => billingView(snap({
    status: status({ source: "none", plan: null, until: null, grace_until: null, trial_used: false, subscription: null, mode: "basic" }),
    claims: pass({ src: "none", plan: null, until: null, grace_until: null, mode: "basic" }),
  })), { kind: "no_trial" }],
  ["trial: 'осталось N дней' from the server's end date", () => billingView(snap({ status: trialStatus, claims: trialPass, nowSec: NOW + 2 * DAY + 100 })),
    { kind: "trial", endsAt: NOW + 14 * DAY, daysLeft: 11, ending: false }],
  ["trial: the last three days are 'ending'", () => billingView(snap({ status: trialStatus, claims: trialPass, nowSec: NOW + 11 * DAY + 1 })).ending, true],
  ["trial: the last day reads 0 days left", () => billingView(snap({ status: trialStatus, claims: trialPass, nowSec: NOW + 14 * DAY - 10 })).daysLeft, 0],
  ["trial ended while offline: the pass's clock wins over the snapshot", () => billingView(snap({ status: trialStatus, claims: trialPass, nowSec: NOW + 14 * DAY })),
    { kind: "lapsed", after: "trial", mode: "basic" }],
  ["trial ended, lapse policy off: protection off", () => billingView(snap({ status: trialStatus, claims: { ...trialPass, lapse_policy: "off" }, nowSec: NOW + 15 * DAY })),
    { kind: "lapsed", after: "trial", mode: "off" }],
  ["trial offline, no snapshot yet: the pass alone", () => billingView(snap({ claims: trialPass, nowSec: NOW + DAY })),
    { kind: "trial", endsAt: NOW + 14 * DAY, daysLeft: 13, ending: false }],
  ["active subscription: plan, seats, price in roubles, next charge, who pays", () => billingView(snap({ status: status(), claims: pass() })),
    { kind: "active", source: "subscription", plan: "family3", seatsUsed: 2, seatsTotal: 3, priceRub: 270, nextChargeAt: NOW + 20 * DAY, periodEnd: NOW + 20 * DAY, isPayer: true }],
  ["a relative's phone on the same subscription is not the payer", () => billingView(snap({ status: status({ subscription: sub({ is_payer: false }) }), claims: pass() })).isPayer, false],
  ["grace: the server says so, days until the window closes", () => billingView(snap({
    status: status({ subscription: sub({ status: "grace", grace_until: NOW + 27 * DAY }) }), claims: pass(), nowSec: NOW + 21 * DAY,
  })), { kind: "grace", plan: "family3", graceUntil: NOW + 27 * DAY, daysLeft: 6, isPayer: true, priceRub: 270 }],
  ["grace reached offline: the snapshot still says active, the pass says the period is over", () => billingView(snap({
    status: status(), claims: pass(), nowSec: NOW + 20 * DAY + 5,
  })), { kind: "grace", plan: "family3", graceUntil: NOW + 27 * DAY, daysLeft: 6, isPayer: true, priceRub: 270 }],
  ["grace over offline: lapsed after a subscription, basic", () => billingView(snap({ status: status(), claims: pass(), hadSubscription: true, nowSec: NOW + 27 * DAY })),
    { kind: "lapsed", after: "subscription", mode: "basic" }],
  ["cancelled: protection runs to the period end", () => billingView(snap({
    status: status({ subscription: sub({ status: "cancel_at_period_end", cancel_requested_at: NOW, next_charge_at: null }) }),
    claims: pass({ grace_until: null }),
  })), { kind: "cancelled", plan: "family3", periodEnd: NOW + 20 * DAY, isPayer: true }],
  ["cancelled and the period ended: lapsed", () => billingView(snap({
    status: status({ subscription: sub({ status: "cancel_at_period_end" }) }), claims: pass({ grace_until: null }), hadSubscription: true, nowSec: NOW + 20 * DAY,
  })), { kind: "lapsed", after: "subscription", mode: "basic" }],
  ["a checkout waiting for the SMS", () => billingView(snap({
    status: status({ source: "none", mode: "basic", subscription: sub({ status: "pending", period_end: null, next_charge_at: null }) }),
    claims: pass({ src: "none", mode: "basic", until: null, grace_until: null, plan: null }),
  })), { kind: "pending", plan: "family3" }],
  ["installed before the paid launch: legacy, nothing changes", () => billingView(snap({
    status: status({ source: "legacy", plan: null, until: null, grace_until: null, trial_used: false, subscription: null }),
    claims: pass({ src: "legacy", plan: null, until: null, grace_until: null }), nowSec: NOW + 3650 * DAY,
  })), { kind: "legacy" }],
  ["a promo grant is active without a price or seats", () => billingView(snap({ claims: pass({ src: "promo", plan: "solo" }) })),
    { kind: "active", source: "promo", plan: "solo", seatsUsed: null, seatsTotal: null, priceRub: null, nextChargeAt: null, periodEnd: NOW + 20 * DAY, isPayer: false }],
  ["lapsed server-side, trial used: after the trial", () => billingView(snap({
    status: status({ source: "none", mode: "basic", plan: null, until: null, grace_until: null, subscription: null, notices: ["basic_mode"] }),
    claims: pass({ src: "none", mode: "basic", plan: null, until: null, grace_until: null }),
  })), { kind: "lapsed", after: "trial", mode: "basic" }],

  // ── what the buttons do ──
  ["cancel from active: covered until the period end, then basic", () => cancelOutcome(billingView(snap({ status: status(), claims: pass() })), "basic"),
    { protectedUntil: NOW + 20 * DAY, then: "basic" }],
  ["cancel from grace with policy off: covered until the window closes, then off", () => cancelOutcome(billingView(snap({
    status: status({ subscription: sub({ status: "grace", grace_until: NOW + 27 * DAY }) }), claims: pass(), nowSec: NOW + 21 * DAY,
  })), "off"), { protectedUntil: NOW + 27 * DAY, then: "off" }],
  ["only the payer manages seats and cancels; a trial offers the plans", () => {
    const active = billingView(snap({ status: status(), claims: pass() }));
    const member = billingView(snap({ status: status({ subscription: sub({ is_payer: false }) }), claims: pass() }));
    const trial = billingView(snap({ status: trialStatus, claims: trialPass }));
    const promo = billingView(snap({ claims: pass({ src: "promo" }) }));
    return {
      active: [canManageSeats(active), canCancel(active), offersPlans(active)],
      member: [canManageSeats(member), canCancel(member), offersPlans(member)],
      trial: [canManageSeats(trial), canCancel(trial), offersPlans(trial)],
      promo: [canManageSeats(promo), canCancel(promo), offersPlans(promo)],
    };
  }, { active: [true, true, false], member: [false, false, false], trial: [false, false, true], promo: [false, false, false] }],
  ["the shield hold per mode", () => ["full", "basic", "off"].map(modeHold), [null, "basic", "off"]],
  ["effective mode: full until a pass says otherwise", () => [effectiveMode(null, NOW), effectiveMode(pass(), NOW + 30 * DAY)], ["full", "basic"]],
  ["days left counts whole days, the last day is 0, never negative", () => [daysLeft(NOW + 1, NOW), daysLeft(NOW + DAY, NOW), daysLeft(NOW + 2 * DAY - 1, NOW), daysLeft(NOW - 5, NOW)], [0, 1, 1, 0]],

  // ── the switch ──
  ["the flag is off unless it is explicitly on", () => [
    billingFlagOn({}, undefined), billingFlagOn({ EXPO_PUBLIC_BILLING_RU_ENABLED: "0" }, {}), billingFlagOn({ EXPO_PUBLIC_BILLING_RU_ENABLED: "yes" }, {}),
    billingFlagOn({ EXPO_PUBLIC_BILLING_RU_ENABLED: "1" }, {}), billingFlagOn({ EXPO_PUBLIC_BILLING_RU_ENABLED: " true " }, {}),
    billingFlagOn({}, { billingRuEnabled: true }), billingFlagOn({}, { billingRuEnabled: "true" }),
  ], [false, false, false, true, true, true, false]],
  ["the billing host comes from the env, without a trailing slash", () => [
    billingApiBaseFrom({}, undefined), billingApiBaseFrom({ EXPO_PUBLIC_BILLING_API_URL: "https://b.example/" }, {}), billingApiBaseFrom({}, { billingApiUrl: "https://x.example" }),
  ], ["https://billing.cleanway.ai", "https://b.example", "https://x.example"]],
  // ── the words ──
  ["a Russian mobile number, however it is typed; anything else is refused", () => [
    "8 915 123-45-67", "9151234567", "+7 (915) 123 45 67", "79151234567", "+7 495 123 45 67", "915123456", "+1 212 555 0100", "",
  ].map(normalizeRuPhone), ["+79151234567", "+79151234567", "+79151234567", "+79151234567", null, null, null, null]],
  ["the number shown back masked, and in full", () => [maskPhone("+79151234567"), formatPhone("+79151234567"), maskPhone("odd")], ["+7 915 ***-**-67", "+7 915 123-45-67", "odd"]],
  ["every operator failure has its words; an unknown one reads as 'other'", () =>
    ["no_money", "passport", "user_declined", "timeout", "weird", null].map(failureCopyKey),
    ["mobile.billing.fail_no_money", "mobile.billing.fail_passport", "mobile.billing.fail_user_declined", "mobile.billing.fail_timeout", "mobile.billing.fail_other", "mobile.billing.fail_other"]],
  ["error codes with words of their own; the rest fall to the generic line", () =>
    ["network", "timeout", "already_subscribed", "code_invalid", "no_free_seats", "not_owner", "keys_missing", "http_500", null].map(errorCopyKey),
    ["mobile.billing.error_network", "mobile.billing.error_network", "mobile.billing.checkout_already", "mobile.billing.join_invalid", "mobile.billing.add_no_seats", "mobile.billing.devices_not_payer", "mobile.billing.keys_missing", null, null]],
  ["plan names go through i18n; an unknown code is shown as is", () => {
    const t = (k) => `<${k}>`;
    return [planLabel(t, "family3"), planLabel(t, "enterprise9"), planLabel(t, null)];
  }, ["<mobile.billing.plan_family3>", "enterprise9", ""]],
  ["pass keys: a JSON object of base64 strings, or nothing", () => [
    passPublicKeysFrom({ EXPO_PUBLIC_BILLING_PASS_PUBLIC_KEYS: '{"2026-09":"AAAA","bad":3}' }, {}), passPublicKeysFrom({ EXPO_PUBLIC_BILLING_PASS_PUBLIC_KEYS: "[1]" }, {}),
    passPublicKeysFrom({ EXPO_PUBLIC_BILLING_PASS_PUBLIC_KEYS: "{oops" }, {}), passPublicKeysFrom({}, {}),
  ], [{ "2026-09": "AAAA" }, {}, {}, {}]],
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
