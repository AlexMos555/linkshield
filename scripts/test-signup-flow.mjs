#!/usr/bin/env node
/**
 * Table test for landing/lib/signup-flow.ts — the decisions behind /signup's
 * email → code flow and the /auth/callback error hand-off.
 *
 * Run: node --experimental-strip-types scripts/test-signup-flow.mjs
 *
 * Pinned:
 *   • which sentence a failed request / failed code / failed link gets, so a
 *     Russian reader never sees GoTrue's English;
 *   • a wrong code and an expired code are the same message (GoTrue cannot
 *     tell them apart either), and only a REJECTED token triggers the
 *     "signup" retry — never a network error;
 *   • the code input holds six digits and nothing else;
 *   • a failed link lands on the signup page of the reader's locale.
 */
import assert from "node:assert/strict";

import {
  OTP_CODE_LEN,
  OTP_VERIFY_TYPES,
  RESEND_COOLDOWN_S,
  callbackPrecheck,
  isCompleteOtpCode,
  isTokenRejected,
  normalizeOtpInput,
  queryErrorKey,
  safeSignupNext,
  sendErrorKey,
  signupErrorPath,
  verifyErrorKey,
} from "../landing/lib/signup-flow.ts";
import {
  connectPath,
  extensionErrorKey,
  isMintedSession,
  isValidConnectState,
  mintOutcome,
  signupForConnectPath,
} from "../landing/lib/extension-connect.ts";

const LOCALES = ["en", "es", "hi", "pt", "ru", "ar", "fr", "de", "it", "id"];

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

console.log("constants shared with the app");
check("6 digits, 62 s cooldown, email then signup", () => {
  assert.equal(OTP_CODE_LEN, 6);
  assert.equal(RESEND_COOLDOWN_S, 62);
  assert.deepEqual([...OTP_VERIFY_TYPES], ["email", "signup"]);
});

console.log("sendErrorKey");
for (const [error, key] of [
  [{ status: 429 }, "error_rate_limited"],
  [{ status: 400, code: "over_email_send_rate_limit" }, "error_rate_limited"],
  [{ status: 500, code: "unexpected_failure" }, "error_send_failed"],
  [{}, "error_send_failed"],
]) {
  check(`${JSON.stringify(error)} → ${key}`, () => assert.equal(sendErrorKey(error), key));
}

console.log("verifyErrorKey");
for (const [error, key] of [
  [{ status: 403, code: "otp_expired" }, "error_code_wrong"],
  [{ status: 400, code: "validation_failed" }, "error_code_wrong"],
  [{ status: 401 }, "error_code_wrong"],
  [{ status: 429, code: "over_request_rate_limit" }, "error_rate_limited"],
  [{ status: 0, code: "network_error" }, "error_send_failed"],
  [{ status: 500 }, "error_send_failed"],
]) {
  check(`${JSON.stringify(error)} → ${key}`, () => assert.equal(verifyErrorKey(error), key));
}

console.log("isTokenRejected (drives the signup-type retry)");
check("4xx token errors retry, everything else does not", () => {
  assert.equal(isTokenRejected({ status: 403, code: "otp_expired" }), true);
  assert.equal(isTokenRejected({ status: 400 }), true);
  assert.equal(isTokenRejected({ code: "otp_expired" }), true);
  assert.equal(isTokenRejected({ status: 429 }), false);
  assert.equal(isTokenRejected({ status: 0, code: "network_error" }), false);
  assert.equal(isTokenRejected({ status: 500 }), false);
});

console.log("code input");
check("keeps digits only, caps at six", () => {
  assert.equal(normalizeOtpInput(" 12 34-56 "), "123456");
  assert.equal(normalizeOtpInput("1234567"), "123456");
  assert.equal(normalizeOtpInput("abc"), "");
  assert.equal(normalizeOtpInput("12３4"), "124"); // full-width digit is not \d
});
check("complete means exactly six digits", () => {
  assert.equal(isCompleteOtpCode("123456"), true);
  assert.equal(isCompleteOtpCode("12345"), false);
  assert.equal(isCompleteOtpCode("1234567"), false);
  assert.equal(isCompleteOtpCode("12345a"), false);
});

console.log("callbackPrecheck");
for (const [query, expected] of [
  ["?code=abc&next=%2F", null],
  ["?error=access_denied&error_code=otp_expired&error_description=Email+link+is+invalid+or+has+expired", "otp_expired"],
  ["?next=%2Fru", "missing_code"],
  ["", "missing_code"],
]) {
  check(`${query || "(empty)"} → ${expected}`, () => assert.equal(callbackPrecheck(new URLSearchParams(query)), expected));
}

console.log("queryErrorKey");
for (const [value, expected] of [
  ["otp_expired", "error_link_expired"],
  ["exchange_failed", "error_link_failed"],
  ["missing_code", "error_link_failed"],
  ["<script>", null],
  [null, null],
  [undefined, null],
]) {
  check(`${String(value)} → ${expected}`, () => assert.equal(queryErrorKey(value), expected));
}

console.log("signupErrorPath keeps the locale");
for (const [next, expected] of [
  ["/ru/pricing?plan=family&interval=monthly", "/ru/signup?error=otp_expired"],
  ["/ru", "/ru/signup?error=otp_expired"],
  ["/", "/signup?error=otp_expired"],
  ["/pricing", "/signup?error=otp_expired"],
  ["/de/", "/de/signup?error=otp_expired"],
  ["/zz/pricing", "/signup?error=otp_expired"],
  ["", "/signup?error=otp_expired"],
]) {
  check(`${next || "(empty)"} → ${expected}`, () => assert.equal(signupErrorPath(next, "otp_expired", LOCALES, "en"), expected));
}

// The browser extension's connect page: the state it waits for must survive
// a trip through /signup, and nothing else may ride along.
const STATE = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde"; // 43 base64url chars
assert.equal(STATE.length, 43);

console.log("signupErrorPath keeps a destination the form honours");
check("a dead link on the way to the connect page keeps the state", () => {
  assert.equal(
    signupErrorPath(`/ru/extension/connect?state=${STATE}`, "otp_expired", LOCALES, "en"),
    `/ru/signup?error=otp_expired&next=${encodeURIComponent(`/ru/extension/connect?state=${STATE}`)}`,
  );
});

console.log("safeSignupNext — an allowlist, not any same-origin path");
for (const [raw, expected] of [
  [`/extension/connect?state=${STATE}`, `/extension/connect?state=${STATE}`],
  [`/ru/extension/connect?state=${STATE}`, `/ru/extension/connect?state=${STATE}`],
  [`/ar/extension/connect/?state=${STATE}`, `/ar/extension/connect?state=${STATE}`],
  ["/account/restore", "/account/restore"],
  ["/account", "/account"],
  ["/hi/account", "/hi/account"],
  ["/account?x=1", null],
  ["/de/account/restore?reason=locked", "/de/account/restore?reason=locked"],
  [`/extension/connect?state=${STATE}&evil=1`, null],
  [`/extension/connect?state=${STATE.slice(1)}`, null],
  [`/extension/connect?state=${STATE}#x`, null],
  ["/extension/connect", null],
  [`//evil.example/extension/connect?state=${STATE}`, null],
  [`/\\evil.example/extension/connect?state=${STATE}`, null],
  [`https://evil.example/extension/connect?state=${STATE}`, null],
  [`/zz/extension/connect?state=${STATE}`, null],
  ["/account/restore?reason=other", null],
  ["/pricing", null],
  ["/", null],
  ["", null],
  [null, null],
]) {
  check(`${raw} → ${expected}`, () => assert.equal(safeSignupNext(raw, LOCALES), expected));
}

console.log("extension connect page");
check("the state is exactly what the extension makes", () => {
  assert.ok(isValidConnectState(STATE));
  for (const bad of [STATE.slice(1), `${STATE}x`, `${STATE.slice(1)}!`, "", null, 42]) assert.ok(!isValidConnectState(bad), String(bad));
});
check("not signed in → /signup and back, in the reader's locale", () => {
  assert.equal(connectPath("en", STATE, "en"), `/extension/connect?state=${STATE}`);
  assert.equal(signupForConnectPath("ru", STATE, "en"), `/ru/signup?next=${encodeURIComponent(`/ru/extension/connect?state=${STATE}`)}`);
  // …and /signup accepts what it is given.
  const next = new URL(signupForConnectPath("ru", STATE, "en"), "https://cleanway.ai").searchParams.get("next");
  assert.equal(safeSignupNext(next, LOCALES), `/ru/extension/connect?state=${STATE}`);
});
check("the API's answer", () => {
  assert.equal(mintOutcome(200), "ok");
  assert.equal(mintOutcome(401), "signin");
  assert.equal(mintOutcome(410), "error_locked");
  for (const s of [429, 500, 502, 503, 409, 404]) assert.equal(mintOutcome(s), "error_failed", String(s));
  assert.ok(isMintedSession({ access_token: "a", refresh_token: "r", expires_at: 1 }));
  for (const bad of [null, {}, { access_token: "a", refresh_token: "", expires_at: 1 }, { access_token: "a", refresh_token: "r" }]) {
    assert.ok(!isMintedSession(bad), JSON.stringify(bad));
  }
});
check("the extension's refusal", () => {
  assert.equal(extensionErrorKey("state_mismatch"), "error_state");
  assert.equal(extensionErrorKey("state_expired"), "error_state");
  for (const code of ["invalid_session", "bad_sender", "wrong_project", "extension_error", null]) {
    assert.equal(extensionErrorKey(code), "error_failed", String(code));
  }
});

if (failures) {
  console.log(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nall signup-flow checks passed");
