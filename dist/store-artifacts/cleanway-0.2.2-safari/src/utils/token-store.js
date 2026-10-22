/**
 * Where the signed-in session's ACCESS token lives.
 *
 * chrome.storage.local is readable by content scripts, which run inside
 * every web page, a hostile one included. The access token (`auth_token`)
 * therefore lives in chrome.storage.session, locked to TRUSTED_CONTEXTS:
 * the background and the extension's own pages (popup, settings) read it,
 * content scripts cannot. It is kept in memory and gone when the browser
 * quits; the background mints a new one from the refresh token at start-up
 * (utils/auth-session.js, ensureFresh) before anything needs it.
 *
 * The refresh token stays in chrome.storage.local: a session that must
 * survive a browser restart cannot live in memory. It is only ever sent to
 * the pinned Supabase project, never by a content script (none reads it),
 * and a refused refresh signs the extension out (auth-session.js).
 *
 * Browser support — feature-detected, never assumed:
 *   Chrome / Edge / Opera 102+  storage.session + setAccessLevel.
 *   Firefox 115+                storage.session (MV2 too); no setAccessLevel,
 *                               and Firefox does not hand storage.session to
 *                               content scripts anyway.
 *   Safari 16.4+                storage.session; setAccessLevel where present.
 *   Older (Firefox 112–114,     no storage.session: the access token stays in
 *   Safari < 16.4)              chrome.storage.local as it always did.
 *
 * Classic script with no imports, like utils/api-base.js: the popup and the
 * settings page load it with <script src>, the background and utils/api.js
 * import it for its side effect. It publishes `self.cleanwayTokens`.
 */
(function (root) {
  "use strict";

  var ACCESS_KEY = "auth_token";

  function browserApi(api) {
    return api || root.chrome;
  }

  /** chrome.storage.session when this browser has it, else null. */
  function sessionArea(api) {
    try {
      var s = browserApi(api).storage.session;
      if (s && typeof s.get === "function" && typeof s.set === "function" && typeof s.remove === "function") {
        return s;
      }
    } catch (e) { /* no storage at all (tests, odd contexts) */ }
    return null;
  }

  /** The storage area holding the access token. */
  function accessArea(api) {
    return sessionArea(api) || browserApi(api).storage.local;
  }

  /** storage.onChanged's area name for the access token. */
  function accessAreaName(api) {
    return sessionArea(api) ? "session" : "local";
  }

  /** The access token, or null (signed out, or not refreshed yet). */
  async function readAccessToken(api) {
    try {
      var data = await accessArea(api).get([ACCESS_KEY]);
      var token = data && data[ACCESS_KEY];
      return typeof token === "string" && token ? token : null;
    } catch (e) {
      return null;
    }
  }

  /** True when a storage.onChanged event changed the access token. */
  function isAccessTokenChange(changes, areaName, api) {
    return Boolean(changes) && areaName === accessAreaName(api) &&
      Object.prototype.hasOwnProperty.call(changes, ACCESS_KEY);
  }

  /**
   * Keep storage.session away from content scripts. Chrome's default is
   * already TRUSTED_CONTEXTS; saying so explicitly pins it. Only the
   * background may call this. Resolves true when the browser applied it.
   */
  async function restrictToTrustedContexts(api) {
    var s = sessionArea(api);
    if (!s || typeof s.setAccessLevel !== "function") return false;
    try {
      await s.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
      return true;
    } catch (e) {
      return false;
    }
  }

  /**
   * An install signed in before this version kept the access token in
   * chrome.storage.local. Move it to storage.session and delete the copy
   * content scripts could read. No storage.session → nothing to move.
   */
  async function migrateLegacyAccessToken(api) {
    var s = sessionArea(api);
    if (!s) return false;
    var local = browserApi(api).storage.local;
    try {
      var old = await local.get([ACCESS_KEY]);
      if (!old || !old[ACCESS_KEY]) return false;
      var cur = await s.get([ACCESS_KEY]);
      if (!cur || !cur[ACCESS_KEY]) {
        var put = {};
        put[ACCESS_KEY] = old[ACCESS_KEY];
        await s.set(put);
      }
      await local.remove(ACCESS_KEY);
      return true;
    } catch (e) {
      return false;
    }
  }

  root.cleanwayTokens = {
    ACCESS_KEY: ACCESS_KEY,
    sessionArea: sessionArea,
    accessArea: accessArea,
    accessAreaName: accessAreaName,
    readAccessToken: readAccessToken,
    isAccessTokenChange: isAccessTokenChange,
    restrictToTrustedContexts: restrictToTrustedContexts,
    migrateLegacyAccessToken: migrateLegacyAccessToken,
  };
})(typeof self !== "undefined" ? self : globalThis);
