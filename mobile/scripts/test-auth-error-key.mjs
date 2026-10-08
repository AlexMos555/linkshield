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
 */
import assert from "node:assert/strict";

import { authFailure, otpSendErrorKey, otpVerifyErrorKey } from "../src/utils/auth-error-key.ts";

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

if (failures) {
  console.log(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nall auth-error-key checks passed");
