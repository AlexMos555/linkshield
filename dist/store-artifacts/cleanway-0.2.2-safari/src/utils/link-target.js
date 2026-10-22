// Where a link really goes.
//
// Search engines, social networks and mail services wrap outbound links in
// their own redirector: google.com/url?q=…, vk.com/away.php?to=…,
// bing.com/ck/a?…&u=… A link badge used to judge the WRAPPER's hostname —
// an official site — so a phishing link wrapped by Google got a green ✓.
// Only the hostname ever leaves the browser, so nothing downstream can see
// the destination; the unwrapping has to happen here, before the check.
//
// resolveLinkHost(href) returns
//   { host: "evil.example" }  the real destination (wrappers peeled, nested
//                             ones too, up to MAX_HOPS)
//   { hidden: true }          a known redirector whose destination is not in
//                             the link at all (LinkedIn /slink, an
//                             undecodable Bing /ck/a). There is nothing honest
//                             to say about such a link, so callers skip it.
//   null                      not an http(s) link.
//
// Shipped as UMD, like family-invite-url.js: a classic content script sets
// the global, the background module imports it for the context-menu check,
// and the Node tests load it directly. Pure functions — no DOM, no chrome.*.
(function (root, factory) {
  var api = factory();
  if (typeof module === "object" && module && module.exports) module.exports = api;
  if (root) root.cleanwayLinkTarget = api;
})(typeof self !== "undefined" ? self : globalThis, function () {
  "use strict";

  var MAX_HOPS = 3;
  var HIDDEN = { hidden: true };

  function param(url, name) {
    var value = url.searchParams.get(name);
    return value ? value.trim() : "";
  }

  // Bing: u = "a1" + base64url(destination URL).
  function bingTarget(url) {
    var u = param(url, "u");
    if (u.indexOf("a1") !== 0) return "";
    try {
      var binary = atob(u.slice(2).replace(/-/g, "+").replace(/_/g, "/"));
      var bytes = Uint8Array.from(binary, function (c) { return c.charCodeAt(0); });
      return new TextDecoder().decode(bytes);
    } catch (e) {
      return "";
    }
  }

  // Google Translate's proxy host spells the site's own name in one label:
  // "." becomes "-" and a real "-" becomes "--" (evil--site-com → evil-site.com).
  function translateProxyTarget(url) {
    var label = url.hostname.slice(0, -".translate.goog".length);
    if (!label) return "";
    var host = label.split("--").map(function (part) { return part.replace(/-/g, "."); }).join("-");
    return url.protocol + "//" + host + url.pathname;
  }

  // Each rule: which wrapper it recognises, and how to read its destination.
  // A rule that matches but reads "" means "a redirect we cannot see through".
  var RULES = [
    {
      host: /^(www\.)?google\.[a-z]{2,3}(\.[a-z]{2})?$/,
      path: /^\/url$/,
      target: function (url) { return param(url, "q") || param(url, "url"); },
    },
    {
      host: /^(www\.)?google\.[a-z]{2,3}(\.[a-z]{2})?$/,
      path: /^\/amp\/./,
      target: function (url) {
        var secure = url.pathname.indexOf("/amp/s/") === 0;
        var rest = url.pathname.slice(secure ? "/amp/s/".length : "/amp/".length);
        return (secure ? "https://" : "http://") + rest + url.search;
      },
    },
    {
      host: /^translate\.google\.[a-z]{2,3}(\.[a-z]{2})?$/,
      path: /^\/(translate|website)$/,
      target: function (url) {
        var u = param(url, "u");
        return !u || /^https?:\/\//i.test(u) ? u : "http://" + u;
      },
    },
    { host: /\.translate\.goog$/, path: /^\//, target: translateProxyTarget },
    { host: /^(www\.)?bing\.com$/, path: /^\/ck\/a$/, target: bingTarget },
    {
      host: /^(www\.|m\.)?youtube\.com$/,
      path: /^\/redirect$/,
      target: function (url) { return param(url, "q"); },
    },
    {
      host: /^(m\.)?vk\.com$/,
      path: /^\/away(\.php)?$/,
      target: function (url) { return param(url, "to"); },
    },
    {
      host: /^(m\.)?ok\.ru$/,
      path: /^\/dk$/,
      target: function (url) { return param(url, "st.rfn"); },
    },
    {
      host: /^(l|lm)\.facebook\.com$/,
      path: /^\/l\.php$/,
      target: function (url) { return param(url, "u"); },
    },
    {
      host: /^(www\.)?linkedin\.com$/,
      path: /^\/redir\/redirect$/,
      target: function (url) { return param(url, "url"); },
    },
    // A short code resolved on LinkedIn's server: the destination is not in the link.
    { host: /^(www\.)?linkedin\.com$/, path: /^\/slink/, target: function () { return ""; } },
  ];

  function parseWeb(href) {
    try {
      var url = new URL(href);
      return url.protocol === "http:" || url.protocol === "https:" ? url : null;
    } catch (e) {
      return null;
    }
  }

  function matchingRule(url) {
    var host = url.hostname.toLowerCase();
    for (var i = 0; i < RULES.length; i++) {
      if (RULES[i].host.test(host) && RULES[i].path.test(url.pathname)) return RULES[i];
    }
    return null;
  }

  function resolveLinkHost(href) {
    var url = parseWeb(href);
    if (!url) return null;
    for (var hop = 0; hop < MAX_HOPS; hop++) {
      var rule = matchingRule(url);
      if (!rule) break;
      var next = parseWeb(rule.target(url));
      if (!next || !next.hostname) return HIDDEN;
      url = next;
    }
    // Still a wrapper after MAX_HOPS: a redirect chain built to hide its end.
    if (matchingRule(url)) return HIDDEN;
    return url.hostname ? { host: url.hostname.toLowerCase() } : null;
  }

  return { resolveLinkHost: resolveLinkHost };
});
