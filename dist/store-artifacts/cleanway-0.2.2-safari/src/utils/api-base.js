// Which API server the extension may talk to.
//
// Every signed-in call carries the account's access token to API_BASE (and
// the webmail scanner sends whole messages there). The Settings page used to accept any
// http(s) URL as an "API server" override, so one pasted value — a support
// "fix", a malicious how-to — sent the tokens to a stranger's server. Now
// only the production API is accepted, plus loopback (http://localhost:PORT,
// http://127.0.0.1:PORT) in a development install: the extension loaded
// unpacked, whose manifest has no store-injected `update_url`. Loopback never
// leaves the machine, and the browser-driven tests point the extension at a
// mock API on 127.0.0.1 that way.
//
// Shipped as UMD, like link-target.js: the background module and the ES
// modules it imports load it for its side effect (self.cleanwayApiBase), the
// Settings page loads it with a <script> tag, and the Node tests load it
// directly. The two classic content scripts that read api_url (webmail.js,
// credential-guardian.js) carry a three-line copy of the same rule.
(function (root, factory) {
  var api = factory();
  if (typeof module === "object" && module && module.exports) module.exports = api;
  if (root) root.cleanwayApiBase = api;
})(typeof self !== "undefined" ? self : globalThis, function () {
  "use strict";

  var DEFAULT_API_BASE = "https://api.cleanway.ai";
  var LOOPBACK = /^http:\/\/(localhost|127\.0\.0\.1)(:[0-9]{1,5})?$/;

  function currentManifest() {
    try {
      return chrome.runtime.getManifest();
    } catch (e) {
      return null;
    }
  }

  // Chrome Web Store / Edge Add-ons installs get `update_url` injected into
  // the manifest; an unpacked (developer) install has none.
  function isDevInstall(manifest) {
    return !!manifest && typeof manifest === "object" && !("update_url" in manifest);
  }

  // The normalised base when `value` is allowed, else null.
  function allowedApiBase(value, manifest) {
    if (typeof value !== "string") return null;
    var v = value.trim().replace(/\/+$/, "");
    if (v === DEFAULT_API_BASE) return v;
    var m = arguments.length > 1 ? manifest : currentManifest();
    if (isDevInstall(m) && LOOPBACK.test(v)) return v;
    return null;
  }

  // What to actually use: the allowed override, else production.
  function resolveApiBase(value, manifest) {
    var m = arguments.length > 1 ? manifest : currentManifest();
    return allowedApiBase(value, m) || DEFAULT_API_BASE;
  }

  return {
    DEFAULT_API_BASE: DEFAULT_API_BASE,
    allowedApiBase: allowedApiBase,
    resolveApiBase: resolveApiBase,
    isDevInstall: isDevInstall,
  };
});
