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
 */
import assert from "node:assert/strict";

import { authFailure, otpSendErrorKey, otpVerifyErrorKey } from "../src/utils/auth-error-key.ts";
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

if (failures) {
  console.log(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nall auth-error-key + otp-code + supabase-key checks passed");
