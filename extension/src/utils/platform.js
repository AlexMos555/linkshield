// Which browser and device the extension is running in.
//
// One question matters today: is this Safari on an iPhone or iPad? The same
// extension-safari/ tree ships in the Mac's Safari and, inside the Cleanway
// iPhone app, in Safari on iOS (docs/IOS.md). On iOS:
//   • the webmail scanner is not offered — docs/MOBILE_AUTO_PROTECTION.md
//     keeps it off on phones (the Gmail / Outlook / Yahoo apps are not web
//     pages, and their mobile sites are not what the scanner reads);
//   • extension pages get a phone layout (the popup opens as a sheet the
//     width of the screen, not a 380 px box).
//
// Safari tells the background through runtime.getPlatformInfo() (os "ios",
// "ipados" on newer versions); pages and older builds fall back to the user
// agent. An iPad in desktop-class browsing says "Macintosh" there, so a Mac
// user agent with a touch screen counts as an iPad (no Mac has one).
//
// Shipped as UMD, like link-target.js: a classic script sets
// self.cleanwayPlatform for pages, the background module imports it for its
// side effect, and the Node tests load it directly.
(function (root, factory) {
  var api = factory();
  if (typeof module === "object" && module && module.exports) module.exports = api;
  if (root) root.cleanwayPlatform = api;
})(typeof self !== "undefined" ? self : globalThis, function () {
  "use strict";

  var MOBILE_OS = { ios: true, ipados: true };

  /** True for an extension base URL Safari hands out (macOS and iOS alike). */
  function isSafariBase(baseUrl) {
    return typeof baseUrl === "string" && baseUrl.indexOf("safari-web-extension:") === 0;
  }

  /** True for a user agent of an iPhone, iPod or iPad (desktop-class iPad too). */
  function isAppleMobileUserAgent(userAgent, maxTouchPoints) {
    var ua = typeof userAgent === "string" ? userAgent : "";
    if (/\b(iPhone|iPad|iPod)\b/.test(ua)) return true;
    return /\bMacintosh\b/.test(ua) && Number(maxTouchPoints) > 1;
  }

  /**
   * Pure decision. env: { baseUrl, platformOs, userAgent, maxTouchPoints }.
   * Only Safari counts: Chrome or Firefox on an iPhone cannot load this
   * extension anyway, and a Mac's Safari reports os "mac".
   */
  function isMobileSafari(env) {
    var e = env || {};
    if (!isSafariBase(e.baseUrl)) return false;
    if (typeof e.platformOs === "string" && e.platformOs) return MOBILE_OS[e.platformOs] === true;
    return isAppleMobileUserAgent(e.userAgent, e.maxTouchPoints);
  }

  function baseUrlOf(api) {
    try {
      return api && api.runtime && typeof api.runtime.getURL === "function" ? api.runtime.getURL("") : "";
    } catch (e) {
      return "";
    }
  }

  function navigatorEnv() {
    var nav = typeof navigator !== "undefined" ? navigator : {};
    return { userAgent: nav.userAgent || "", maxTouchPoints: nav.maxTouchPoints || 0 };
  }

  /** Synchronous guess for pages (popup, settings, welcome): user agent only. */
  function isMobileSafariNow(api) {
    var nav = navigatorEnv();
    return isMobileSafari({ baseUrl: baseUrlOf(api), userAgent: nav.userAgent, maxTouchPoints: nav.maxTouchPoints });
  }

  /** Background: asks the browser first (getPlatformInfo), then the user agent. */
  function detectMobileSafari(api) {
    var base = baseUrlOf(api);
    if (!isSafariBase(base)) return Promise.resolve(false);
    var nav = navigatorEnv();
    var env = { baseUrl: base, userAgent: nav.userAgent, maxTouchPoints: nav.maxTouchPoints };
    var getInfo = api && api.runtime && api.runtime.getPlatformInfo;
    if (typeof getInfo !== "function") return Promise.resolve(isMobileSafari(env));
    return Promise.resolve()
      .then(function () { return getInfo.call(api.runtime); })
      .then(function (info) {
        env.platformOs = info && typeof info.os === "string" ? info.os : "";
        return isMobileSafari(env);
      })
      .catch(function () { return isMobileSafari(env); });
  }

  /**
   * Marks a page <html> with `cw-ios` on Safari for iPhone / iPad and hides
   * every element with `data-hide-on-ios` (removes it, so a hidden switch
   * can never be reached by keyboard or screen reader either).
   */
  function applyToPage(api, doc) {
    var d = doc || (typeof document !== "undefined" ? document : null);
    if (!d || !isMobileSafariNow(api)) return false;
    if (d.documentElement && d.documentElement.classList) d.documentElement.classList.add("cw-ios");
    var hidden = d.querySelectorAll ? d.querySelectorAll("[data-hide-on-ios]") : [];
    for (var i = 0; i < hidden.length; i++) {
      if (hidden[i].parentNode) hidden[i].parentNode.removeChild(hidden[i]);
    }
    return true;
  }

  return {
    isSafariBase: isSafariBase,
    isAppleMobileUserAgent: isAppleMobileUserAgent,
    isMobileSafari: isMobileSafari,
    isMobileSafariNow: isMobileSafariNow,
    detectMobileSafari: detectMobileSafari,
    applyToPage: applyToPage,
  };
});
