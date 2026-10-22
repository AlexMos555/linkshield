#!/usr/bin/env node
/**
 * Unit tests for src/services/captcha.ts — the client half of the optional
 * Supabase captcha gate.
 *
 * Run: node --experimental-test-module-mocks --experimental-strip-types \
 *        mobile/scripts/test-captcha-service.mjs
 *
 * No jest in mobile/ (see test-host-parser.mjs). Node's built-in TS stripper
 * loads the service as-is, and node:test's module mocks stand in for
 * react-native / expo-constants, which cannot be imported outside Metro. Each
 * case imports a FRESH module instance (`?case=N`) because CAPTCHA_URL is
 * resolved once, at import time, from the environment.
 *
 * What is pinned, and why it matters:
 *   • a non-https URL disables the feature instead of reaching Linking.openURL
 *     — the value is a build-time env var that anyone can typo into an
 *     `intent://` or `javascript:` string;
 *   • the deep link is accepted ONLY with the nonce this request minted, so a
 *     foreign app firing our scheme cannot inject a token into a sign-in;
 *   • every non-completion (timeout, back-out, no browser, cancel) resolves
 *     null exactly once and drops its listener — the sign-in screen has one
 *     branch to write and can never hang;
 *   • on iPhone the page opens in the in-app sheet, never in Safari (App
 *     Review 4.0), its returned URL passes the same nonce check, and a
 *     timeout or cancel dismisses the sheet.
 */
import assert from "node:assert/strict";
import { mock, test } from "node:test";

// captcha.ts reads __DEV__ (a Metro global) at import time.
globalThis.__DEV__ = false;

// ─── react-native / expo stand-ins ────────────────────────────────

const openedUrls = [];
let openUrlImpl = async () => {};
let appStateHandler = null;
let removedListeners = 0;
const expoExtra = {};

// The iPhone's in-app sheet (captcha.ts AuthSheet; modules/cleanway-safari →
// ASWebAuthenticationSession). authSessionImpl null = not available (Android,
// or an iPhone binary without the native half): the Linking + deep-link path.
let authSessionImpl = null;
const sheetCalls = [];
let sheetCancels = 0;
const fakeSheet = {
  available: () => authSessionImpl !== null,
  open(url, scheme) {
    sheetCalls.push({ url, scheme });
    return authSessionImpl(url, scheme);
  },
  cancel() {
    sheetCancels += 1;
  },
};

mock.module("react-native-get-random-values", { namedExports: {} });
mock.module("expo-constants", { defaultExport: { expoConfig: { extra: expoExtra } } });
mock.module("react-native", {
  namedExports: {
    AppState: {
      addEventListener: (_event, handler) => {
        appStateHandler = handler;
        return {
          remove() {
            removedListeners += 1;
            appStateHandler = null;
          },
        };
      },
    },
    Linking: {
      openURL: (url) => {
        openedUrls.push(url);
        return openUrlImpl(url);
      },
    },
  },
});

const HTTPS_URL = "https://cleanway.ai/auth/captcha";
const SOLVE_TIMEOUT_MS = 180_000;
const RETURN_GRACE_MS = 4_000;

let importCounter = 0;
async function loadCaptcha(envUrl) {
  if (envUrl === undefined) delete process.env.EXPO_PUBLIC_CAPTCHA_URL;
  else process.env.EXPO_PUBLIC_CAPTCHA_URL = envUrl;
  importCounter += 1;
  return import(`../src/services/captcha.ts?case=${importCounter}`);
}

/** Let promise callbacks run without depending on (possibly mocked) setTimeout. */
const flush = () => new Promise((resolve) => setImmediate(resolve));

async function startRequest(captcha) {
  const pending = captcha.requestCaptchaToken();
  await flush();
  const nonce = new URL(openedUrls.at(-1)).searchParams.get("nonce");
  return { pending, nonce };
}

async function isStillPending(promise) {
  const marker = Symbol("pending");
  const outcome = await Promise.race([promise, flush().then(() => marker)]);
  return outcome === marker;
}

// ─── Configuration gate ───────────────────────────────────────────

test("unset URL → feature off, nothing opened", async () => {
  const captcha = await loadCaptcha(undefined);
  const before = openedUrls.length;
  assert.equal(captcha.CAPTCHA_URL, "");
  assert.equal(captcha.isCaptchaRequired(), false);
  assert.equal(await captcha.requestCaptchaToken(), null);
  assert.equal(openedUrls.length, before);
});

test("non-https / placeholder URL → feature off, nothing opened", async () => {
  const REJECTED = [
    "http://cleanway.ai/auth/captcha",
    "intent://cleanway.ai/auth/captcha#Intent;end",
    "javascript:alert(1)",
    "cleanway.ai/auth/captcha",
    "https://example.com/auth/captcha",
    "https://YOUR_CAPTCHA_URL",
    "https://cleanway.ai/auth captcha",
    "   ",
  ];
  for (const url of REJECTED) {
    const captcha = await loadCaptcha(url);
    const before = openedUrls.length;
    assert.equal(captcha.CAPTCHA_URL, "", url);
    assert.equal(captcha.isCaptchaRequired(), false, url);
    assert.equal(await captcha.requestCaptchaToken(), null, url);
    assert.equal(openedUrls.length, before, url);
  }
});

test("https URL → opens CAPTCHA_URL?nonce=<32 hex>", async () => {
  const captcha = await loadCaptcha(HTTPS_URL);
  assert.equal(captcha.CAPTCHA_URL, HTTPS_URL);
  assert.equal(captcha.isCaptchaRequired(), true);
  const { pending, nonce } = await startRequest(captcha);
  const opened = new URL(openedUrls.at(-1));
  assert.equal(opened.origin + opened.pathname, HTTPS_URL);
  assert.match(nonce, /^[0-9a-f]{32}$/);
  captcha.cancelCaptcha();
  assert.equal(await pending, null);
});

test("base URL that already has a query keeps it and appends &nonce=", async () => {
  const captcha = await loadCaptcha(`${HTTPS_URL}?scheme=cleanway`);
  const { pending } = await startRequest(captcha);
  const opened = new URL(openedUrls.at(-1));
  assert.equal(opened.searchParams.get("scheme"), "cleanway");
  assert.match(opened.searchParams.get("nonce"), /^[0-9a-f]{32}$/);
  captcha.cancelCaptcha();
  await pending;
});

test("expoConfig.extra.captchaUrl is honoured when the env var is unset", async () => {
  expoExtra.captchaUrl = HTTPS_URL;
  try {
    const captcha = await loadCaptcha(undefined);
    assert.equal(captcha.CAPTCHA_URL, HTTPS_URL);
  } finally {
    delete expoExtra.captchaUrl;
  }
});

test("each request mints a different nonce", async () => {
  const captcha = await loadCaptcha(HTTPS_URL);
  const first = await startRequest(captcha);
  const second = await startRequest(captcha);
  assert.notEqual(first.nonce, second.nonce);
  assert.equal(await first.pending, null, "superseded request resolves null");
  captcha.cancelCaptcha();
  await second.pending;
});

// ─── Nonce check on the deep link ─────────────────────────────────

test("nonce mismatch is rejected and the request stays pending", async () => {
  const captcha = await loadCaptcha(HTTPS_URL);
  const { pending, nonce } = await startRequest(captcha);
  const flipped = `${nonce.slice(0, -1)}${nonce.endsWith("0") ? "1" : "0"}`;
  for (const wrong of ["", flipped, nonce.toUpperCase(), `${nonce}0`, nonce.slice(1)]) {
    assert.equal(captcha.deliverCaptchaToken(wrong, "tok"), false, JSON.stringify(wrong));
  }
  assert.equal(await isStillPending(pending), true);
  captcha.cancelCaptcha();
  assert.equal(await pending, null);
});

test("matching nonce delivers the trimmed token, once", async () => {
  const captcha = await loadCaptcha(HTTPS_URL);
  const { pending, nonce } = await startRequest(captcha);
  assert.equal(captcha.deliverCaptchaToken(nonce, "  tok-123  "), true);
  assert.equal(await pending, "tok-123");
  assert.equal(captcha.deliverCaptchaToken(nonce, "again"), false, "nothing pending any more");
});

test("blank token is accepted as a delivery but resolves null", async () => {
  const captcha = await loadCaptcha(HTTPS_URL);
  const { pending, nonce } = await startRequest(captcha);
  assert.equal(captcha.deliverCaptchaToken(nonce, "   "), true);
  assert.equal(await pending, null);
});

test("delivery with nothing pending is dropped", async () => {
  const captcha = await loadCaptcha(HTTPS_URL);
  assert.equal(captcha.deliverCaptchaToken("0123456789abcdef0123456789abcdef", "tok"), false);
});

// ─── Timeout / grace → null ───────────────────────────────────────

test("hard timeout resolves null", async () => {
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    const captcha = await loadCaptcha(HTTPS_URL);
    const { pending } = await startRequest(captcha);
    mock.timers.tick(SOLVE_TIMEOUT_MS - 1);
    assert.equal(await isStillPending(pending), true);
    mock.timers.tick(1);
    assert.equal(await pending, null);
  } finally {
    mock.timers.reset();
  }
});

test("back in the app with no deep link → null after the grace window", async () => {
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    const captcha = await loadCaptcha(HTTPS_URL);
    const { pending } = await startRequest(captcha);
    assert.ok(appStateHandler, "AppState listener registered");
    appStateHandler("background");
    appStateHandler("active");
    mock.timers.tick(RETURN_GRACE_MS - 1);
    assert.equal(await isStillPending(pending), true);
    mock.timers.tick(1);
    assert.equal(await pending, null);
  } finally {
    mock.timers.reset();
  }
});

test("grace window never starts if the app was not backgrounded", async () => {
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    const captcha = await loadCaptcha(HTTPS_URL);
    const { pending } = await startRequest(captcha);
    appStateHandler("active");
    mock.timers.tick(RETURN_GRACE_MS * 2);
    assert.equal(await isStillPending(pending), true);
    captcha.cancelCaptcha();
    assert.equal(await pending, null);
  } finally {
    mock.timers.reset();
  }
});

test("deep link inside the grace window wins", async () => {
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    const captcha = await loadCaptcha(HTTPS_URL);
    const { pending, nonce } = await startRequest(captcha);
    appStateHandler("background");
    appStateHandler("active");
    mock.timers.tick(RETURN_GRACE_MS / 2);
    assert.equal(captcha.deliverCaptchaToken(nonce, "tok"), true);
    assert.equal(await pending, "tok");
    mock.timers.tick(RETURN_GRACE_MS);
    assert.equal(captcha.deliverCaptchaToken(nonce, "late"), false);
  } finally {
    mock.timers.reset();
  }
});

test("Linking.openURL rejection (no browser) resolves null", async () => {
  openUrlImpl = async () => {
    throw new Error("no activity found to handle intent");
  };
  try {
    const captcha = await loadCaptcha(HTTPS_URL);
    assert.equal(await captcha.requestCaptchaToken(), null);
  } finally {
    openUrlImpl = async () => {};
  }
});

// ─── Cancel settles once ──────────────────────────────────────────

test("cancel settles exactly once, releases the listener, and closes the door", async () => {
  const captcha = await loadCaptcha(HTTPS_URL);
  const removedBefore = removedListeners;
  const { pending, nonce } = await startRequest(captcha);
  captcha.cancelCaptcha();
  captcha.cancelCaptcha();
  assert.equal(await pending, null);
  assert.equal(removedListeners, removedBefore + 1, "listener removed once, not twice");
  assert.equal(appStateHandler, null);
  assert.equal(captcha.deliverCaptchaToken(nonce, "late"), false);
});

test("cancel with nothing pending is a no-op", async () => {
  const captcha = await loadCaptcha(HTTPS_URL);
  const removedBefore = removedListeners;
  captcha.cancelCaptcha();
  assert.equal(removedListeners, removedBefore);
});

// ─── iPhone: the in-app sheet, never a trip to Safari ─────────────
//
// App Review 4.0: a sign-in step must not leave the app for Safari. With the
// native sheet (ASWebAuthenticationSession) the challenge opens inside the
// app, and the sheet itself catches the page's cleanway://captcha-return
// redirect — no deep link, no AppState guessing. The nonce check still
// decides, and every way out resolves exactly once.

/** Run [fn] with the sheet present; [impl] answers each openAuthSession call. */
async function withSheet(impl, fn) {
  authSessionImpl = impl;
  try {
    return await fn();
  } finally {
    authSessionImpl = null;
  }
}

/** A sheet that stays open until the test closes it with a URL (or null). */
function controllableSheet() {
  const opened = [];
  const impl = () => new Promise((resolve) => opened.push(resolve));
  return { impl, close: (url, i = opened.length - 1) => opened[i](url), opened };
}

const returnUrl = (nonce, token) =>
  `cleanway://captcha-return?nonce=${encodeURIComponent(nonce)}&token=${encodeURIComponent(token)}`;

test("iPhone: the challenge opens in the in-app sheet for the cleanway scheme, not in Safari", async () => {
  const sheet = controllableSheet();
  await withSheet(sheet.impl, async () => {
    const captcha = await loadCaptcha(HTTPS_URL);
    const linkingBefore = openedUrls.length;
    const pending = captcha.requestCaptchaToken(fakeSheet);
    await flush();
    assert.equal(openedUrls.length, linkingBefore, "Linking.openURL not used");
    assert.equal(appStateHandler, null, "no AppState guessing");
    const { url, scheme } = sheetCalls.at(-1);
    assert.equal(scheme, "cleanway");
    const opened = new URL(url);
    assert.equal(opened.origin + opened.pathname, HTTPS_URL);
    const nonce = opened.searchParams.get("nonce");
    assert.match(nonce, /^[0-9a-f]{32}$/);
    const cancelsBefore = sheetCancels;
    sheet.close(returnUrl(nonce, "tok/+=.~ 1"));
    assert.equal(await pending, "tok/+=.~ 1");
    assert.equal(sheetCancels, cancelsBefore, "the sheet closed itself; nothing to cancel");
  });
});

test("a sheet that is not available (Android, older iPhone binary) → the browser path, as before", async () => {
  const captcha = await loadCaptcha(HTTPS_URL);
  const sheetBefore = sheetCalls.length;
  const { pending, nonce } = await (async () => {
    const p = captcha.requestCaptchaToken(fakeSheet);
    await flush();
    return { pending: p, nonce: new URL(openedUrls.at(-1)).searchParams.get("nonce") };
  })();
  assert.equal(sheetCalls.length, sheetBefore, "no sheet opened");
  assert.ok(appStateHandler, "AppState listener registered for the browser hop");
  assert.equal(captcha.deliverCaptchaToken(nonce, "tok"), true);
  assert.equal(await pending, "tok");
});

test("iPhone: a sheet answer with another nonce, another URL or none resolves null", async () => {
  for (const answer of [
    (nonce) => returnUrl(`${nonce.slice(1)}0`, "tok"),
    (nonce) => `cleanway://other?nonce=${nonce}&token=tok`,
    (nonce) => `https://cleanway.ai/captcha-return?nonce=${nonce}&token=tok`,
    (nonce) => returnUrl(nonce, "   "),
    () => null,
    () => "",
  ]) {
    const sheet = controllableSheet();
    await withSheet(sheet.impl, async () => {
      const captcha = await loadCaptcha(HTTPS_URL);
      const pending = captcha.requestCaptchaToken(fakeSheet);
      await flush();
      const nonce = new URL(sheetCalls.at(-1).url).searchParams.get("nonce");
      sheet.close(answer(nonce));
      assert.equal(await pending, null, String(answer(nonce)));
    });
  }
});

test("iPhone: the sheet failing to open resolves null", async () => {
  await withSheet(() => Promise.reject(new Error("no window")), async () => {
    const captcha = await loadCaptcha(HTTPS_URL);
    assert.equal(await captcha.requestCaptchaToken(fakeSheet), null);
  });
});

test("iPhone: cancel closes the sheet; its late answer is ignored", async () => {
  const sheet = controllableSheet();
  await withSheet(sheet.impl, async () => {
    const captcha = await loadCaptcha(HTTPS_URL);
    const pending = captcha.requestCaptchaToken(fakeSheet);
    await flush();
    const nonce = new URL(sheetCalls.at(-1).url).searchParams.get("nonce");
    const cancelsBefore = sheetCancels;
    captcha.cancelCaptcha();
    assert.equal(await pending, null);
    assert.equal(sheetCancels, cancelsBefore + 1, "the sheet is dismissed");
    sheet.close(returnUrl(nonce, "late"));
    await flush();
    assert.equal(captcha.deliverCaptchaToken(nonce, "late"), false);
  });
});

test("iPhone: the hard timeout closes the sheet and resolves null", async () => {
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    const sheet = controllableSheet();
    await withSheet(sheet.impl, async () => {
      const captcha = await loadCaptcha(HTTPS_URL);
      const pending = captcha.requestCaptchaToken(fakeSheet);
      await flush();
      const cancelsBefore = sheetCancels;
      mock.timers.tick(SOLVE_TIMEOUT_MS);
      assert.equal(await pending, null);
      assert.equal(sheetCancels, cancelsBefore + 1);
    });
  } finally {
    mock.timers.reset();
  }
});

test("iPhone: a second request supersedes the first; the first sheet's answer cannot settle it", async () => {
  const sheet = controllableSheet();
  await withSheet(sheet.impl, async () => {
    const captcha = await loadCaptcha(HTTPS_URL);
    const first = captcha.requestCaptchaToken(fakeSheet);
    await flush();
    const firstNonce = new URL(sheetCalls.at(-1).url).searchParams.get("nonce");
    const second = captcha.requestCaptchaToken(fakeSheet);
    await flush();
    const secondNonce = new URL(sheetCalls.at(-1).url).searchParams.get("nonce");
    assert.equal(await first, null);
    sheet.close(returnUrl(firstNonce, "stale"), 0);
    assert.equal(await isStillPending(second), true);
    sheet.close(returnUrl(secondNonce, "fresh"), 1);
    assert.equal(await second, "fresh");
  });
});

test("parseCaptchaReturn: only cleanway://captcha-return, first value wins, bad escapes refused", async () => {
  const { parseCaptchaReturn } = await loadCaptcha(HTTPS_URL);
  assert.deepEqual(parseCaptchaReturn("cleanway://captcha-return?nonce=ab&token=t%2Bk%20x"), { nonce: "ab", token: "t+k x" });
  assert.deepEqual(parseCaptchaReturn("cleanway://captcha-return?token=t&nonce=n&nonce=evil"), { nonce: "n", token: "t" });
  assert.deepEqual(parseCaptchaReturn("cleanway://captcha-return?nonce=n#token=t"), { nonce: "n", token: "" });
  for (const bad of [null, "", "cleanway://captcha-return", "cleanway://captcha-returnx?nonce=n&token=t",
    "evil://captcha-return?nonce=n&token=t", "cleanway://captcha-return?nonce=%E0%A4%A&token=t"]) {
    assert.equal(parseCaptchaReturn(bad), null, String(bad));
  }
});

// ─── OTP request: captcha on demand (src/utils/otp-request.ts) ────
//
// Pinned here, next to the captcha service it drives:
//   • the request body is byte-identical to the pre-captcha one without a
//     token, and carries it as gotrue_meta_security.captcha_token with one
//     (the field GoTrue reads; supabase-js's options.captchaToken maps to it);
//   • a build WITHOUT a challenge URL never asks for a token — today's flow;
//   • a build WITH one sends the plain request first and solves a captcha only
//     when GoTrue answers captcha_failed, so shipping the URL in 1.0.5 costs
//     nobody a browser hop until the Supabase switch is actually flipped;
//   • once the server has asked, later requests (resend) go captcha-first;
//   • a cancelled captcha is an outcome, not a throw; any other error is
//     rethrown untouched for the screen's error mapping.

const otp = await import("../src/utils/otp-request.ts");

const CAPTCHA_FAILED = Object.assign(new Error("captcha protection: request disallowed"), {
  code: "captcha_failed",
  status: 400,
});

function fakeDeps({ configured, tokens = [], failures = [] }) {
  const sent = [];
  let captchaCalls = 0;
  return {
    sent,
    get captchaCalls() {
      return captchaCalls;
    },
    deps: {
      captchaConfigured: configured,
      async send(email, captchaToken) {
        sent.push({ email, captchaToken });
        const next = failures.shift();
        if (next) throw next;
      },
      async getCaptchaToken() {
        captchaCalls += 1;
        return tokens.shift() ?? null;
      },
    },
  };
}

test("otp body: no token → exactly {email, create_user}", () => {
  assert.deepEqual(otp.otpRequestBody("a@b.co"), { email: "a@b.co", create_user: true });
  assert.deepEqual(otp.otpRequestBody("a@b.co", ""), { email: "a@b.co", create_user: true });
  assert.equal(JSON.stringify(otp.otpRequestBody("a@b.co")), '{"email":"a@b.co","create_user":true}');
});

test("otp body: token → gotrue_meta_security.captcha_token", () => {
  assert.deepEqual(otp.otpRequestBody("a@b.co", "tok"), {
    email: "a@b.co",
    create_user: true,
    gotrue_meta_security: { captcha_token: "tok" },
  });
});

test("isCaptchaRejection: only GoTrue's captcha_failed", () => {
  assert.equal(otp.isCaptchaRejection(CAPTCHA_FAILED), true);
  assert.equal(otp.isCaptchaRejection({ code: "over_email_send_rate_limit", status: 429 }), false);
  assert.equal(otp.isCaptchaRejection(new Error("captcha_failed")), false);
  assert.equal(otp.isCaptchaRejection(null), false);
});

test("captcha not configured → one plain send, never a challenge", async () => {
  const f = fakeDeps({ configured: false });
  const request = otp.createOtpRequester(f.deps);
  assert.deepEqual(await request("a@b.co"), { kind: "sent" });
  assert.deepEqual(f.sent, [{ email: "a@b.co", captchaToken: undefined }]);
  assert.equal(f.captchaCalls, 0);
});

test("captcha not configured → captcha_failed is rethrown (screen says: update the app)", async () => {
  const f = fakeDeps({ configured: false, failures: [CAPTCHA_FAILED] });
  const request = otp.createOtpRequester(f.deps);
  await assert.rejects(request("a@b.co"), (e) => e === CAPTCHA_FAILED);
  assert.equal(f.captchaCalls, 0);
});

test("configured, server not asking → plain send, no browser hop", async () => {
  const f = fakeDeps({ configured: true });
  const request = otp.createOtpRequester(f.deps);
  assert.deepEqual(await request("a@b.co"), { kind: "sent" });
  assert.deepEqual(await request("a@b.co"), { kind: "sent" });
  assert.equal(f.captchaCalls, 0);
  assert.deepEqual(f.sent.map((s) => s.captchaToken), [undefined, undefined]);
});

test("configured, server asks → solve once, resend with the token", async () => {
  const f = fakeDeps({ configured: true, tokens: ["tok-1"], failures: [CAPTCHA_FAILED] });
  const request = otp.createOtpRequester(f.deps);
  assert.deepEqual(await request("a@b.co"), { kind: "sent" });
  assert.equal(f.captchaCalls, 1);
  assert.deepEqual(f.sent, [
    { email: "a@b.co", captchaToken: undefined },
    { email: "a@b.co", captchaToken: "tok-1" },
  ]);
});

test("after the server asked once, the next request goes captcha-first", async () => {
  const f = fakeDeps({ configured: true, tokens: ["tok-1", "tok-2"], failures: [CAPTCHA_FAILED] });
  const request = otp.createOtpRequester(f.deps);
  await request("a@b.co");
  assert.deepEqual(await request("a@b.co"), { kind: "sent" });
  assert.deepEqual(f.sent.map((s) => s.captchaToken), [undefined, "tok-1", "tok-2"]);
});

test("cancelled challenge → captcha_cancelled, nothing more sent", async () => {
  const f = fakeDeps({ configured: true, tokens: [null], failures: [CAPTCHA_FAILED] });
  const request = otp.createOtpRequester(f.deps);
  assert.deepEqual(await request("a@b.co"), { kind: "captcha_cancelled" });
  assert.equal(f.sent.length, 1);
});

test("captcha-first and cancelled → nothing sent at all", async () => {
  const f = fakeDeps({ configured: true, tokens: ["tok-1", null], failures: [CAPTCHA_FAILED] });
  const request = otp.createOtpRequester(f.deps);
  await request("a@b.co");
  const before = f.sent.length;
  assert.deepEqual(await request("a@b.co"), { kind: "captcha_cancelled" });
  assert.equal(f.sent.length, before);
});

test("a rejected token is rethrown, not retried in a loop", async () => {
  const f = fakeDeps({ configured: true, tokens: ["bad"], failures: [CAPTCHA_FAILED, CAPTCHA_FAILED] });
  const request = otp.createOtpRequester(f.deps);
  await assert.rejects(request("a@b.co"), (e) => e === CAPTCHA_FAILED);
  assert.equal(f.captchaCalls, 1);
  assert.equal(f.sent.length, 2);
});

test("other errors pass through untouched and never open a challenge", async () => {
  const rate = Object.assign(new Error("rate"), { code: "over_email_send_rate_limit", status: 429 });
  const f = fakeDeps({ configured: true, failures: [rate] });
  const request = otp.createOtpRequester(f.deps);
  await assert.rejects(request("a@b.co"), (e) => e === rate);
  assert.equal(f.captchaCalls, 0);
});
