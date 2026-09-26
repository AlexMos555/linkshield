/**
 * Firefox namespace alias for the background.
 *
 * Our code calls chrome.* and uses the returned promises. Firefox ships the
 * promise-based API as `browser.*`; its `chrome.*` is the callback-flavoured
 * compatibility copy. So in Firefox we point the global `chrome` at `browser`.
 *
 * This used to be text that build-extensions.sh prepended to the Firefox copy
 * of background/index.js. Now that the background is an ES module with static
 * imports, that could not work any more: imported modules evaluate BEFORE the
 * importing file's own code, and a `var chrome` in a module is module-local.
 * So the alias is its own module, imported first by background/index.js, and
 * it sets the real global.
 *
 * runtime.getBrowserInfo() exists only in Firefox, so Chrome (which also has
 * a `browser` alias since 148), Yandex and Safari are left untouched.
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
  // with Firefox's own chrome.*, which beats a background that never loads.
}
