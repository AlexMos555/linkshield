#!/usr/bin/env node
/**
 * Table test for landing/lib/turnstile.ts — the pure half of the Turnstile
 * captcha flow (the React widget is not exercised here).
 *
 * Run: node --experimental-strip-types scripts/test-turnstile-lib.mjs
 *
 * The two things worth pinning:
 *   1. /auth/captcha builds a `cleanway://captcha-return?...` deep link and
 *      hands it to the OS. That URL must be assembled ONLY from an allowlisted
 *      scheme, a nonce that matches the mobile client's 32-hex format, and the
 *      provider token — never from arbitrary query input, or the page becomes
 *      an open redirector into any app scheme on the device.
 *   2. The sitekey fallback: Cloudflare's always-pass TEST key is used only
 *      when NEXT_PUBLIC_TURNSTILE_SITE_KEY is unset, and that state must be
 *      reported as test mode so the UI can say so out loud.
 */
import assert from "node:assert/strict";

import {
  TURNSTILE_TEST_SITE_KEY,
  buildCaptchaReturnUrl,
  parseCaptchaRequest,
  resolveTurnstileSiteKey,
} from "../landing/lib/turnstile.ts";

const NONCE = "0123456789abcdef0123456789abcdef";

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

console.log("resolveTurnstileSiteKey");
check("unset env → test key + testMode", () => {
  assert.deepEqual(resolveTurnstileSiteKey(undefined), { key: TURNSTILE_TEST_SITE_KEY, testMode: true });
});
check("blank env → test key + testMode", () => {
  assert.deepEqual(resolveTurnstileSiteKey("   "), { key: TURNSTILE_TEST_SITE_KEY, testMode: true });
});
check("configured env → that key, not test mode", () => {
  assert.deepEqual(resolveTurnstileSiteKey(" 0x4AAAAAAAExample "), { key: "0x4AAAAAAAExample", testMode: false });
});

console.log("parseCaptchaRequest");
check("valid nonce, no scheme → ok with default scheme", () => {
  assert.deepEqual(parseCaptchaRequest(`?nonce=${NONCE}`), { ok: true, nonce: NONCE, scheme: "cleanway" });
});
check("explicit allowlisted scheme → ok", () => {
  assert.deepEqual(parseCaptchaRequest(`?nonce=${NONCE}&scheme=cleanway`), { ok: true, nonce: NONCE, scheme: "cleanway" });
});
check("missing nonce → missing_nonce", () => {
  assert.deepEqual(parseCaptchaRequest(""), { ok: false, reason: "missing_nonce" });
});
check("uppercase / wrong length / non-hex nonce → bad_nonce", () => {
  for (const bad of [NONCE.toUpperCase(), NONCE.slice(1), `${NONCE}0`, "zz23456789abcdef0123456789abcdef", "../x"]) {
    assert.deepEqual(parseCaptchaRequest(`?nonce=${encodeURIComponent(bad)}`), { ok: false, reason: "bad_nonce" }, bad);
  }
});
check("unknown scheme → bad_scheme (never echoed back)", () => {
  for (const bad of ["evil", "javascript", "https", "cleanway-dev", "CLEANWAY"]) {
    assert.deepEqual(parseCaptchaRequest(`?nonce=${NONCE}&scheme=${bad}`), { ok: false, reason: "bad_scheme" }, bad);
  }
});

console.log("buildCaptchaReturnUrl");
check("valid inputs → cleanway://captcha-return with nonce + encoded token", () => {
  assert.equal(
    buildCaptchaReturnUrl("cleanway", NONCE, "XXXX.DUMMY.TOKEN.XXXX"),
    `cleanway://captcha-return?nonce=${NONCE}&token=XXXX.DUMMY.TOKEN.XXXX`,
  );
});
check("token is percent-encoded, never spliced raw", () => {
  const url = buildCaptchaReturnUrl("cleanway", NONCE, "a b&c=d#e");
  assert.equal(url, `cleanway://captcha-return?nonce=${NONCE}&token=a%20b%26c%3Dd%23e`);
});
check("unknown scheme → null", () => {
  assert.equal(buildCaptchaReturnUrl("evil", NONCE, "tok"), null);
});
check("bad nonce → null", () => {
  assert.equal(buildCaptchaReturnUrl("cleanway", "not-a-nonce", "tok"), null);
});
check("empty token → null", () => {
  assert.equal(buildCaptchaReturnUrl("cleanway", NONCE, ""), null);
  assert.equal(buildCaptchaReturnUrl("cleanway", NONCE, "   "), null);
});

if (failures > 0) {
  console.error(`\n${failures} turnstile-lib check(s) failed`);
  process.exit(1);
}
console.log("\nall turnstile-lib checks passed");
