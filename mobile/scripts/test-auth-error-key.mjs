#!/usr/bin/env node
/**
 * Table test for src/utils/auth-error-key.ts — which translated sentence the
 * sign-in screen shows for a failed GoTrue call.
 *
 * Run: node --experimental-strip-types mobile/scripts/test-auth-error-key.mjs
 *
 * No jest in mobile/ (see test-host-parser.mjs); the module imports nothing
 * from react-native, so node's TS stripper loads it as-is.
 *
 * Pinned:
 *   • captcha_failed splits on whether THIS build sends a token — "try again"
 *     when it does, "update the app" when it does not (the server switch is
 *     project-wide);
 *   • 429 and over_*_rate_limit → the wait message, on both calls;
 *   • a wrong and an expired code share one sentence (GoTrue returns the same
 *     403 otp_expired for both);
 *   • network_error / timeout → the offline sentence, never "wrong code";
 *   • anything unrecognised, including a non-Error throw, → the generic one.
 *
 * Also pins src/utils/otp-code.ts (the code field), here because CI already
 * runs this file for the sign-in screen:
 *   • any code of 6 to 8 digits is accepted — 1.0.4 took exactly six, so the
 *     Supabase OTP length could never be raised without locking it out;
 *   • a paste of the email's sentence yields the code, not the code glued to
 *     the "10 minutes" after it;
 *   • the field never holds more than 8 digits or anything but ASCII digits.
 *
 * And pins src/utils/supabase-key.ts (the apikey every sign-in call sends):
 *   • the publishable key (sb_publishable_…, not a JWT) wins over the legacy
 *     anon JWT and is never rejected for not being a JWT;
 *   • a server-only secret (sb_secret_…, a service_role JWT) never becomes
 *     the app's key, in either slot.
 *
 * And pins src/utils/review-login.ts (the store reviewers' password sign-in,
 * docs/runbooks/app-review-account.md):
 *   • EXPO_PUBLIC_REVIEW_EMAILS unset, empty or an unexpanded "$…" → the
 *     feature is off; otherwise an exact, case-insensitive match after trim —
 *     a lookalike, a +tag, a longer domain never switches to a password;
 *   • every other address keeps the email code: the OTP request is sent with
 *     the same bytes as before, the password grant is never called, and the
 *     screen renders the password field only under `reviewMode`;
 *   • the allowlisted address signs in with the password (captcha on demand,
 *     like the code request), and its errors get their own sentences
 *     (wrong password, too many attempts, offline);
 *   • only cleanway.ai addresses are allowlisted in the EAS profiles, and the
 *     screen never logs anything.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  authFailure,
  otpSendErrorKey,
  otpVerifyErrorKey,
  passwordSignInErrorKey,
} from "../src/utils/auth-error-key.ts";
import { createOtpRequester, otpRequestBody } from "../src/utils/otp-request.ts";
import {
  createReviewSignIn,
  isReviewEmail,
  parseReviewEmails,
  passwordSignInBody,
} from "../src/utils/review-login.ts";
import {
  OTP_CODE_MAX_LEN,
  OTP_CODE_MIN_LEN,
  isValidOtpCode,
  normalizeOtpInput,
} from "../src/utils/otp-code.ts";
import {
  cleanSupabaseValue,
  resolveSupabaseClientKey,
  supabaseKeyKind,
} from "../src/utils/supabase-key.ts";

let failures = 0;
function check(name, fn) {
  try {
    fn();
    console.log(`  ok   ${name}`);
  } catch (err) {
    failures += 1;
    console.log(`  FAIL ${name}\n       ${err.message}`);
  }
}
async function checkAsync(name, fn) {
  try {
    await fn();
    console.log(`  ok   ${name}`);
  } catch (err) {
    failures += 1;
    console.log(`  FAIL ${name}\n       ${err.message}`);
  }
}

console.log("otpSendErrorKey");
for (const [error, captcha, key] of [
  [{ status: 400, code: "captcha_failed" }, true, "mobile.auth.err_captcha"],
  [{ status: 400, code: "captcha_failed" }, false, "mobile.auth.err_captcha_update"],
  [{ status: 429, code: "over_email_send_rate_limit" }, false, "mobile.auth.err_rate_limited"],
  [{ status: 429 }, true, "mobile.auth.err_rate_limited"],
  [{ status: 400, code: "over_request_rate_limit" }, false, "mobile.auth.err_rate_limited"],
  [{ status: 0, code: "network_error" }, false, "mobile.auth.err_network"],
  [{ status: 0, code: "timeout" }, false, "mobile.auth.err_network"],
  [{ status: 500, code: "unexpected_failure" }, false, "mobile.auth.generic_error"],
  [{ status: 422, code: "email_address_invalid" }, false, "mobile.auth.generic_error"],
  [{}, false, "mobile.auth.generic_error"],
]) {
  check(`${JSON.stringify(error)} captcha=${captcha} → ${key}`, () => {
    assert.equal(otpSendErrorKey(error, captcha), key);
  });
}

console.log("otpVerifyErrorKey");
for (const [error, key] of [
  [{ status: 403, code: "otp_expired" }, "mobile.auth.err_code_wrong"],
  [{ status: 400, code: "validation_failed" }, "mobile.auth.err_code_wrong"],
  [{ status: 401 }, "mobile.auth.err_code_wrong"],
  [{ status: 0, code: "otp_expired" }, "mobile.auth.err_code_wrong"],
  [{ status: 429, code: "over_request_rate_limit" }, "mobile.auth.err_rate_limited"],
  [{ status: 0, code: "network_error" }, "mobile.auth.err_network"],
  [{ status: 0, code: "timeout" }, "mobile.auth.err_network"],
  [{ status: 500 }, "mobile.auth.generic_error"],
  [{ status: 200, code: "bad_response" }, "mobile.auth.generic_error"],
]) {
  check(`${JSON.stringify(error)} → ${key}`, () => assert.equal(otpVerifyErrorKey(error), key));
}

console.log("authFailure");
check("reads code/status off an AuthError-shaped object", () => {
  assert.deepEqual(authFailure({ code: "otp_expired", status: 403, message: "x" }), { code: "otp_expired", status: 403 });
});
check("ignores wrong types and non-objects", () => {
  assert.deepEqual(authFailure({ code: 403, status: "403" }), { code: undefined, status: undefined });
  assert.deepEqual(authFailure(null), {});
  assert.deepEqual(authFailure("boom"), {});
  assert.deepEqual(authFailure(undefined), {});
});
check("a thrown string ends up generic, not 'wrong code'", () => {
  assert.equal(otpVerifyErrorKey(authFailure("boom")), "mobile.auth.generic_error");
  assert.equal(otpSendErrorKey(authFailure(new TypeError("fetch failed")), false), "mobile.auth.generic_error");
});

console.log("otp code length range");
check("6 to 8 digits — today's 6 and the audit's 8", () => {
  assert.equal(OTP_CODE_MIN_LEN, 6);
  assert.equal(OTP_CODE_MAX_LEN, 8);
});
for (const [code, ok] of [
  ["123456", true],
  ["1234567", true],
  ["12345678", true],
  [" 12345678 ", true],
  ["12345", false],
  ["123456789", false],
  ["12345a", false],
  ["", false],
  ["12３456", false],
]) {
  check(`isValidOtpCode(${JSON.stringify(code)}) → ${ok}`, () => assert.equal(isValidOtpCode(code), ok));
}

console.log("otp code input");
for (const [raw, want] of [
  ["1", "1"],
  ["123456", "123456"],
  ["12345678", "12345678"],
  ["123456789", "12345678"],
  [" 12 34-56 ", "123456"],
  ["1234 5678", "12345678"],
  [" 482139 ", "482139"],
  ["Your code: 48213907. It expires in 10 minutes.", "48213907"],
  ["Код входа: 482139 (действует 10 минут)", "482139"],
  ["abc", ""],
  ["12３4", "124"],
]) {
  check(`normalizeOtpInput(${JSON.stringify(raw)}) → ${JSON.stringify(want)}`, () => {
    assert.equal(normalizeOtpInput(raw), want);
  });
}
check("whatever goes in, what comes out is a valid code or a prefix of one", () => {
  for (const raw of ["Code 123456789012", "x".repeat(50), "9".repeat(40), "1 2 3 4 5 6 7 8 9"]) {
    const out = normalizeOtpInput(raw);
    assert.match(out, /^\d{0,8}$/);
  }
});

const ENV_PREFIX = "EXPO_PUBLIC";
console.log("supabase client key");
{
  const b64url = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const jwt = (claims) => `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url(claims)}.c2ln`;
  const ANON = jwt({ iss: "supabase", ref: "bpyqgzzclsbfvxthyfsf", role: "anon" });
  const SERVICE = jwt({ iss: "supabase", ref: "bpyqgzzclsbfvxthyfsf", role: "service_role" });
  const PUBLISHABLE = "sb_publishable_AbCdEf0123456789_xyz";
  // Assembled at runtime and low-entropy so secret scanners do not take the
  // fixture for a leaked key.
  const SERVER_ONLY = ["sb", "secret", "x".repeat(20)].join("_");

  check("kinds: publishable, legacy JWT, secret by prefix or role, unknown", () => {
    assert.equal(supabaseKeyKind(PUBLISHABLE), "publishable");
    assert.equal(supabaseKeyKind(ANON), "legacy_jwt");
    assert.equal(supabaseKeyKind(SERVICE), "secret");
    assert.equal(supabaseKeyKind(SERVER_ONLY), "secret");
    assert.equal(supabaseKeyKind("e2e-public-anon-key"), "unknown");
    assert.equal(supabaseKeyKind("a.b.c"), "unknown");
  });
  check("publishable preferred over the anon JWT", () => {
    assert.equal(resolveSupabaseClientKey({ publishable: PUBLISHABLE, anon: ANON }), PUBLISHABLE);
    assert.equal(resolveSupabaseClientKey({ publishable: ` ${PUBLISHABLE}\n`, anon: ANON }), PUBLISHABLE);
  });
  check("falls back to the anon key when the publishable one is unset", () => {
    assert.equal(resolveSupabaseClientKey({ publishable: undefined, anon: ANON }), ANON);
    assert.equal(resolveSupabaseClientKey({ publishable: "", anon: ANON }), ANON);
    assert.equal(resolveSupabaseClientKey({ publishable: `$${ENV_PREFIX}_SUPABASE_PUBLISHABLE_KEY`, anon: ANON }), ANON);
    assert.equal(resolveSupabaseClientKey({ publishable: "sb_publishable_REPLACE_WITH_PUBLISHABLE_KEY", anon: ANON }), ANON);
  });
  check("a publishable key alone is enough (not a JWT, still accepted)", () => {
    assert.equal(resolveSupabaseClientKey({ publishable: PUBLISHABLE }), PUBLISHABLE);
    assert.equal(resolveSupabaseClientKey({ anon: PUBLISHABLE }), PUBLISHABLE);
  });
  check("unknown formats pass through (the landing e2e build's fake key)", () => {
    assert.equal(resolveSupabaseClientKey({ anon: "e2e-public-anon-key" }), "e2e-public-anon-key");
  });
  check("a server-only secret in either slot is never used", () => {
    assert.equal(resolveSupabaseClientKey({ publishable: SERVER_ONLY, anon: ANON }), ANON);
    assert.equal(resolveSupabaseClientKey({ publishable: SERVICE, anon: ANON }), ANON);
    assert.equal(resolveSupabaseClientKey({ anon: SERVICE }), "");
    assert.equal(resolveSupabaseClientKey({ anon: SERVER_ONLY }), "");
  });
  check("unset / placeholders → empty (sign-in honestly unavailable)", () => {
    assert.equal(resolveSupabaseClientKey({}), "");
    assert.equal(resolveSupabaseClientKey({ anon: "eyJ_REPLACE_WITH_PUBLIC_ANON_KEY" }), "");
    assert.equal(cleanSupabaseValue("  "), "");
    assert.equal(cleanSupabaseValue(null), "");
  });
}

console.log("passwordSignInErrorKey (store reviewers' password sign-in)");
for (const [error, captcha, key] of [
  [{ status: 400, code: "invalid_credentials" }, false, "mobile.auth.err_password_wrong"],
  [{ status: 400, code: "invalid_grant" }, true, "mobile.auth.err_password_wrong"],
  [{ status: 429, code: "over_request_rate_limit" }, false, "mobile.auth.err_password_rate_limited"],
  [{ status: 429 }, true, "mobile.auth.err_password_rate_limited"],
  [{ status: 0, code: "network_error" }, false, "mobile.auth.err_network"],
  [{ status: 0, code: "timeout" }, false, "mobile.auth.err_network"],
  [{ status: 400, code: "captcha_failed" }, true, "mobile.auth.err_captcha"],
  [{ status: 400, code: "captcha_failed" }, false, "mobile.auth.err_captcha_update"],
  [{ status: 400, code: "user_banned" }, false, "mobile.auth.generic_error"],
  [{ status: 400, code: "email_not_confirmed" }, false, "mobile.auth.generic_error"],
  [{ status: 500, code: "unexpected_failure" }, false, "mobile.auth.generic_error"],
  [{}, false, "mobile.auth.generic_error"],
]) {
  check(`${JSON.stringify(error)} captcha=${captcha} → ${key}`, () => {
    assert.equal(passwordSignInErrorKey(error, captcha), key);
  });
}
check("a thrown string ends up generic, not 'wrong password'", () => {
  assert.equal(passwordSignInErrorKey(authFailure("boom"), false), "mobile.auth.generic_error");
});

const REVIEW = "review@cleanway.ai";
const REVIEW_ENV = `${ENV_PREFIX}_REVIEW_EMAILS`;
console.log("review sign-in: the allowlist (EXPO_PUBLIC_REVIEW_EMAILS)");
for (const [raw, want] of [
  [undefined, []],
  [null, []],
  ["", []],
  ["   ", []],
  [`$${REVIEW_ENV}`, []],
  [REVIEW, [REVIEW]],
  [" Review@Cleanway.AI ", [REVIEW]],
  [`${REVIEW}, apple-review@cleanway.ai`, [REVIEW, "apple-review@cleanway.ai"]],
  [`${REVIEW},,REVIEW@cleanway.ai, `, [REVIEW]],
  [`not-an-address, ${REVIEW}, $OTHER_VAR`, [REVIEW]],
]) {
  check(`parseReviewEmails(${JSON.stringify(raw)}) → ${JSON.stringify(want)}`, () => {
    assert.deepEqual(parseReviewEmails(raw), want);
  });
}
{
  const allow = parseReviewEmails(REVIEW);
  for (const email of [REVIEW, "REVIEW@cleanway.ai", "  review@cleanway.ai\n", "Review@CleanWay.ai"]) {
    check(`isReviewEmail(${JSON.stringify(email)}) → true`, () => assert.equal(isReviewEmail(email, allow), true));
  }
  for (const email of [
    "",
    "review",
    "review@cleanway",
    "review@cleanway.ai.evil.com",
    "xreview@cleanway.ai",
    "review+1@cleanway.ai",
    "review@cleanway.ai.",
    "re view@cleanway.ai",
    "rеview@cleanway.ai", // Cyrillic е
    "review@сleanway.ai", // Cyrillic с
    `${REVIEW},grandma@mail.ru`,
    "grandma@mail.ru",
  ]) {
    check(`isReviewEmail(${JSON.stringify(email)}) → false`, () => assert.equal(isReviewEmail(email, allow), false));
  }
  check("feature off (variable unset): not even the review address gets a password field", () => {
    assert.equal(isReviewEmail(REVIEW, parseReviewEmails(undefined)), false);
    assert.equal(isReviewEmail(REVIEW, []), false);
  });
}

/** A review sign-in wired to fakes; `script` answers each signIn call in turn. */
function reviewFixture({ allowlist = [REVIEW], captchaConfigured = true, script = [], token = "captcha-tok" } = {}) {
  const signIns = [];
  let challenges = 0;
  const run = createReviewSignIn(allowlist, {
    captchaConfigured,
    async signIn(email, password, captchaToken) {
      signIns.push([email, password, captchaToken]);
      const step = script.shift() ?? { ok: { accessToken: "access" } };
      if (step.throw) throw step.throw;
      return step.ok;
    },
    async getCaptchaToken() {
      challenges += 1;
      return token;
    },
  });
  return { run, signIns, challenges: () => challenges };
}

console.log("review sign-in: everyone else keeps the email code");
await checkAsync("other addresses: the code request goes out as before, the password grant never runs", async () => {
  const allowlist = parseReviewEmails(REVIEW);
  const sent = [];
  const requestOtp = createOtpRequester({
    captchaConfigured: false,
    async send(email, captchaToken) {
      sent.push([email, captchaToken]);
    },
    async getCaptchaToken() {
      throw new Error("no challenge expected");
    },
  });
  const f = reviewFixture({ allowlist });
  const others = ["grandma@mail.ru", "Review+1@cleanway.ai", "review@cleanway.ai.evil.com", "rеview@cleanway.ai"];
  for (const email of others) {
    assert.equal(isReviewEmail(email, allowlist), false, email);
    assert.deepEqual(await requestOtp(email), { kind: "sent" });
    assert.deepEqual(await f.run(email, "Pw0rdPw0rdPw0rdPw0rdPw0rd"), { kind: "not_review_email" });
  }
  assert.deepEqual(sent, others.map((email) => [email, undefined]));
  assert.equal(f.signIns.length, 0);
  assert.equal(f.challenges(), 0);
  assert.equal(JSON.stringify(otpRequestBody("grandma@mail.ru")), '{"email":"grandma@mail.ru","create_user":true}');
});
await checkAsync("feature off: even the review address is refused by the password path", async () => {
  const f = reviewFixture({ allowlist: parseReviewEmails("") });
  assert.deepEqual(await f.run(REVIEW, "Pw0rdPw0rdPw0rdPw0rdPw0rd"), { kind: "not_review_email" });
  assert.equal(f.signIns.length, 0);
});

console.log("review sign-in: the allowlisted address");
check("password body: no token → exactly {email, password}", () => {
  assert.equal(JSON.stringify(passwordSignInBody(REVIEW, "x")), '{"email":"review@cleanway.ai","password":"x"}');
});
check("password body: token → gotrue_meta_security.captcha_token", () => {
  assert.deepEqual(passwordSignInBody(REVIEW, "x", "tok"), {
    email: REVIEW,
    password: "x",
    gotrue_meta_security: { captcha_token: "tok" },
  });
});
await checkAsync("signs in with the lowercased address and the password (a pasted newline dropped)", async () => {
  const f = reviewFixture({ script: [{ ok: { accessToken: "a1" } }] });
  const out = await f.run(" Review@Cleanway.ai ", "Pw0rdPw0rdPw0rdPw0rdPw0rd\n");
  assert.deepEqual(out, { kind: "signed_in", session: { accessToken: "a1" } });
  assert.deepEqual(f.signIns, [[REVIEW, "Pw0rdPw0rdPw0rdPw0rdPw0rd", undefined]]);
  assert.equal(f.challenges(), 0);
});
await checkAsync("server asks for a captcha → solve once, retry with the token", async () => {
  const f = reviewFixture({ script: [{ throw: { status: 400, code: "captcha_failed" } }, { ok: { accessToken: "a2" } }] });
  const out = await f.run(REVIEW, "pw");
  assert.deepEqual(out, { kind: "signed_in", session: { accessToken: "a2" } });
  assert.deepEqual(f.signIns, [[REVIEW, "pw", undefined], [REVIEW, "pw", "captcha-tok"]]);
  assert.equal(f.challenges(), 1);
});
await checkAsync("challenge not completed → captcha_cancelled, no second attempt", async () => {
  const f = reviewFixture({ token: null, script: [{ throw: { status: 400, code: "captcha_failed" } }] });
  assert.deepEqual(await f.run(REVIEW, "pw"), { kind: "captcha_cancelled" });
  assert.equal(f.signIns.length, 1);
});
await checkAsync("build without a challenge page → captcha_failed is rethrown (screen: update the app)", async () => {
  const f = reviewFixture({ captchaConfigured: false, script: [{ throw: { status: 400, code: "captcha_failed" } }] });
  await assert.rejects(f.run(REVIEW, "pw"), (e) => e.code === "captcha_failed");
  assert.equal(f.challenges(), 0);
});
await checkAsync("a wrong password is rethrown once — no retry, no challenge", async () => {
  const f = reviewFixture({ script: [{ throw: { status: 400, code: "invalid_credentials" } }] });
  await assert.rejects(f.run(REVIEW, "wrong"), (e) => e.code === "invalid_credentials");
  assert.equal(f.signIns.length, 1);
  assert.equal(f.challenges(), 0);
});

console.log("review sign-in: the screen and the build profiles");
{
  const screen = readFileSync(new URL("../app/auth.tsx", import.meta.url), "utf8");
  const helper = readFileSync(new URL("../src/utils/review-login.ts", import.meta.url), "utf8");
  const OPEN = "{reviewMode && (";

  /** [start, end] of every `{reviewMode && ( … )}` block of the screen. */
  function reviewOnlyBlocks(src) {
    const blocks = [];
    for (let at = src.indexOf(OPEN); at !== -1; at = src.indexOf(OPEN, at + 1)) {
      let depth = 0;
      let end = -1;
      for (let i = at + OPEN.length - 1; i < src.length; i += 1) {
        if (src[i] === "(") depth += 1;
        else if (src[i] === ")" && (depth -= 1) === 0) {
          end = i;
          break;
        }
      }
      assert.ok(end > at, "unbalanced {reviewMode && ( block in app/auth.tsx");
      blocks.push([at, end]);
    }
    return blocks;
  }
  const allIndexes = (src, needle) => {
    const out = [];
    for (let i = src.indexOf(needle); i !== -1; i = src.indexOf(needle, i + 1)) out.push(i);
    return out;
  };

  check("the allowlist is the literal build-time variable (Metro inlines only literal reads)", () => {
    assert.match(screen, new RegExp(`parseReviewEmails\\(process\\.env\\.${REVIEW_ENV}\\)`));
  });
  check("the password field renders only inside {reviewMode && ( … )}", () => {
    const blocks = reviewOnlyBlocks(screen);
    const inside = (i) => blocks.some(([a, b]) => i > a && i < b);
    for (const needle of ["secureTextEntry", '"mobile.auth.password_ph"']) {
      const hits = allIndexes(screen, needle);
      assert.ok(hits.length > 0, `${needle} not found in app/auth.tsx`);
      for (const i of hits) assert.ok(inside(i), `${needle} outside a {reviewMode && ( block`);
    }
  });
  check("the email step's button still requests a code unless reviewMode", () => {
    assert.match(screen, /reviewMode\s*\?\s*submitPassword\(\)\s*:\s*requestCode\(\)/);
    assert.match(screen, /reviewMode\s*\?\s*passwordRef\.current\?\.focus\(\)\s*:\s*void requestCode\(\)/);
  });
  check("the screen never calls the password grant directly (only through createReviewSignIn)", () => {
    assert.doesNotMatch(screen, /\bsignIn\(/);
    assert.match(screen, /createReviewSignIn\(/);
  });
  check("nothing on the sign-in path logs (the password must never reach a log)", () => {
    assert.doesNotMatch(screen, /\bconsole\./);
    assert.doesNotMatch(helper, /\bconsole\./);
  });
  check("EAS store profiles allowlist only cleanway.ai addresses, the review one included", () => {
    const eas = JSON.parse(readFileSync(new URL("../eas.json", import.meta.url), "utf8")).build;
    for (const name of ["preview", "production"]) {
      const list = parseReviewEmails(eas[name].env[REVIEW_ENV]);
      assert.ok(list.includes(REVIEW), `${name}: ${REVIEW} missing`);
      for (const email of list) assert.ok(email.endsWith("@cleanway.ai"), `${name}: ${email} is not ours`);
    }
  });
}

if (failures) {
  console.log(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nall auth-error-key + otp-code + supabase-key + review-login checks passed");
