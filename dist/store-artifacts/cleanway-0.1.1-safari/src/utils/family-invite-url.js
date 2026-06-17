// Cleanway family-invite URL helpers.
//
// Both the extension's options page (browser context, <script> tag) and our
// Node smoke tests need this logic, so the file ships as UMD: it attaches to
// globalThis.familyInviteUrl in the browser and to module.exports in Node.
// The functions themselves are pure — no DOM, no chrome.* — so they're easy
// to test.
//
// Wire format (also used by the landing /family/join route):
//   https://cleanway.ai/family/join#code=<urlencoded-code>&pin=<4-digit-pin>
//
// The hash fragment never reaches the server, which preserves the
// server-blind invariant for the invite secret.
(function (root, factory) {
  if (typeof module === "object" && module && module.exports) {
    module.exports = factory();
  } else {
    root.familyInviteUrl = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  var SHARE_BASE = "https://cleanway.ai/family/join";

  // Build the canonical share URL. Inputs are not validated here — the caller
  // (the extension's invite handler) trusts the API response shape.
  function buildInviteUrl(code, pin) {
    return (
      SHARE_BASE +
      "#code=" +
      encodeURIComponent(code) +
      "&pin=" +
      encodeURIComponent(pin)
    );
  }

  // Try to interpret arbitrary user input as a Cleanway invite URL. Returns
  // { code, pin } when the input is recognizable, else null.
  //
  // Hostname is locked to "cleanway.ai" or "*.cleanway.ai" — a substring
  // match like /cleanway\./ would accept "evilcleanway.attacker.com" and
  // anything else with the brand name baked in, making the paste-flow a
  // phishing vector for an attacker-controlled invite.
  //
  // The actual security check still happens server-side when the extension
  // submits the code+pin to /api/v1/family/accept; this client check just
  // keeps us from surfacing somebody else's URL as a "real Cleanway invite"
  // in the join form.
  function parseInviteUrl(input) {
    if (!input) return null;
    var url;
    try {
      url = new URL(String(input).trim());
    } catch (e) {
      return null;
    }
    var host = (url.hostname || "").toLowerCase();
    var hostOk = host === "cleanway.ai" || host.endsWith(".cleanway.ai");
    if (!hostOk) return null;
    if (!/\/family\/join\b/.test(url.pathname)) return null;
    var hash = (url.hash || "").replace(/^#/, "");
    if (!hash) return null;
    var params = new URLSearchParams(hash);
    var code = params.get("code");
    var pin = params.get("pin");
    if (!code || !pin) return null;
    return { code: code, pin: pin };
  }

  return {
    buildInviteUrl: buildInviteUrl,
    parseInviteUrl: parseInviteUrl,
  };
});
