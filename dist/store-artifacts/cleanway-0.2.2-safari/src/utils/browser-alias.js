/**
 * Firefox namespace alias: `chrome` → `browser`.
 *
 * Our code calls chrome.* and uses the returned promises. Firefox ships the
 * promise-based API as `browser.*`. In a Manifest V2 add-on (ours,
 * extension-firefox/) its `chrome.*` on extension pages and in the
 * background is the callback-flavoured compatibility copy: a call without a
 * callback returns undefined, not a Promise. Content scripts get one object
 * for both names, so they are fine; everything else needs this file.
 *
 * Without it the popup threw on `tabs[0]` of undefined, GET_STATS answered
 * nothing, and Settings threw on `data.skill_level` of undefined.
 *
 * Loaded FIRST everywhere it is needed:
 *   - every extension page (popup, welcome, Settings, the block page and the
 *     block preview) with a plain <script src> before any other script;
 *     scripts/test-extension-core.mjs fails CI on a page that does not;
 *   - the background, as its first static import (background/index.js). An
 *     imported module evaluates before the importing file's own code, and a
 *     `var chrome` there would be module-local, so this sets the real global.
 * Classic script with no import/export, so both ways load the same file.
 *
 * runtime.getBrowserInfo() exists only in Firefox, so Chrome (which also has
 * a `browser` alias since 148), Yandex and Safari are left untouched. The
 * callback style keeps working: Firefox's `browser.*` takes a callback too.
 */

try {
  const isFirefox = typeof browser !== "undefined"
    && browser.runtime
    && typeof browser.runtime.getBrowserInfo === "function";
  if (isFirefox && globalThis.chrome !== browser) {
    globalThis.chrome = browser;
  }
} catch (e) {
  // A non-writable global would throw in module (strict) code. Carry on
  // with Firefox's own chrome.*, which beats a page that never loads.
}
