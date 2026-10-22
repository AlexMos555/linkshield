/**
 * The extension's ear on https://cleanway.ai/<locale>/extension/connect.
 *
 * The manifests inject this file on that path of that origin only; it checks
 * both again here, because a match pattern is easy to widen by accident.
 *
 * The page (landing/app/[locale]/extension/connect) talks to it with
 * window.postMessage on its own window:
 *   page → us   {source: "cleanway-web", type: "cleanway:hello"}
 *   us → page   {source: "cleanway-extension", type: "cleanway:extension-ready"}
 *   page → us   {source: "cleanway-web", type: "cleanway:connect", state, session}
 *   us → page   {source: "cleanway-extension", type: "cleanway:connect-result", ok, error}
 *
 * Only a message from this very window (event.source) on this exact origin
 * is read, and only the known fields are copied before it goes to the
 * background, which checks the sender and the state once more
 * (utils/auth-session.js). Nothing here is logged.
 *
 * Why not externally_connectable: Firefox does not support it for web pages,
 * and this relay works the same in Chrome, Edge, Firefox and Safari.
 */
(function () {
  "use strict";

  var ORIGIN = "https://cleanway.ai";
  var PATH_RE = /^\/(?:(?:en|ru|es|pt|fr|de|it|id|hi|ar)\/)?extension\/connect\/?$/;

  if (window.top !== window) return;
  if (location.origin !== ORIGIN || !PATH_RE.test(location.pathname)) return;
  if (window.__cleanwayConnectRelay) return;
  window.__cleanwayConnectRelay = true;

  function post(message) {
    message.source = "cleanway-extension";
    window.postMessage(message, ORIGIN);
  }

  function str(value, max) {
    return typeof value === "string" && value.length <= max ? value : "";
  }

  var busy = false;

  window.addEventListener("message", function (event) {
    if (event.source !== window || event.origin !== ORIGIN) return;
    var data = event.data;
    if (!data || typeof data !== "object" || data.source !== "cleanway-web") return;

    if (data.type === "cleanway:hello") {
      post({ type: "cleanway:extension-ready" });
      return;
    }
    if (data.type !== "cleanway:connect" || busy) return;

    var session = data.session && typeof data.session === "object" ? data.session : {};
    var message = {
      type: "AUTH_CONNECT",
      state: str(data.state, 128),
      session: {
        access_token: str(session.access_token, 8192),
        refresh_token: str(session.refresh_token, 512),
        expires_at: typeof session.expires_at === "number" ? session.expires_at : 0,
        anon_key: str(session.anon_key, 2048),
      },
    };

    busy = true;
    function done(result) {
      busy = false;
      var ok = Boolean(result && result.ok === true);
      post({
        type: "cleanway:connect-result",
        ok: ok,
        error: ok ? null : str(result && result.error, 64) || "extension_error",
      });
    }
    try {
      // Callback form: the same call works in Chrome, Firefox (MV2) and Safari.
      chrome.runtime.sendMessage(message, function (result) {
        if (chrome.runtime.lastError) {
          done(null);
          return;
        }
        done(result);
      });
    } catch (e) {
      done(null);
    }
  });

  // Announce ourselves too, in case the page asked before we were injected.
  post({ type: "cleanway:extension-ready" });
})();
