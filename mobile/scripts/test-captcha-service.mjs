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
 *     branch to write and can never hang.
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
