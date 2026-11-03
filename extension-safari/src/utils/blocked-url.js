/**
 * The block page's address: src/blocked/blocked.html?d=<domain>&u=<url>&…
 *
 * A dangerous page is no longer covered by an overlay inside its own DOM
 * (the page could simply remove it): the background navigates the tab to
 * the extension's own blocked.html (background/block-redirect.js). The
 * verdict travels in the query string, every value encodeURIComponent'd
 * here and validated again by parse() on the other side; blocked.js puts it
 * on screen with textContent only.
 *
 * Only the extension can open blocked.html — it is not a
 * web_accessible_resource — but parse() trusts nothing: a domain that isn't
 * a hostname is dropped, the "open anyway" address must be http(s) on that
 * very host, reason codes are snake_case words, lengths are capped.
 *
 * A verdict resting on Google's lists carries the end of Google's window
 * (`x`, epoch ms: background/google-verdict.js advisoryUntil). The address
 * outlives it — a restored tab, Forward after "Go back to safety", the
 * browser history — and Web Risk allows a warning only while Google's
 * answer is valid, so past `x` (or with none) the page draws nothing from
 * its address and asks again (needsRecheck; blocked/blocked.js, the popup).
 *
 * Classic script with no imports (like utils/api-base.js): blocked.html
 * loads it with <script src>, the background imports it for its side
 * effect, scripts/test-extension-core.mjs runs it in a vm. It publishes
 * `self.cleanwayBlockedUrl`.
 */
(function (root) {
  "use strict";

  var PAGE_PATH = "src/blocked/blocked.html";
  var MAX_REASONS = 8;
  var MAX_DETAIL = 200;
  var MAX_URL = 2048;
  var HOST_RE = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)*\.?$/;
  var SIGNAL_RE = /^[a-z0-9_]{1,64}$/;
  var UNTIL_RE = /^\d{1,16}$/;
  var GOOGLE_REASON = "safe_browsing"; // background/google-verdict.js

  function cleanHost(value) {
    if (typeof value !== "string") return "";
    var h = value.trim().toLowerCase();
    return HOST_RE.test(h) ? h : "";
  }

  /** The http(s) address on exactly `host`, rebuilt from its parts; else "". */
  function cleanUrl(value, host) {
    if (typeof value !== "string" || !host || value.length > MAX_URL) return "";
    var u;
    try {
      u = new URL(value);
    } catch (e) {
      return "";
    }
    if (u.protocol !== "https:" && u.protocol !== "http:") return "";
    if (u.username || u.password) return "";
    if (u.hostname.toLowerCase() !== host) return "";
    return u.protocol + "//" + u.host + u.pathname + u.search + u.hash;
  }

  function cleanReasons(list) {
    if (!Array.isArray(list)) return [];
    var out = [];
    for (var i = 0; i < list.length && out.length < MAX_REASONS; i++) {
      var r = list[i];
      if (!r || typeof r !== "object") continue;
      var signal = typeof r.signal === "string" && SIGNAL_RE.test(r.signal) ? r.signal : "";
      var detail = typeof r.detail === "string" ? r.detail.slice(0, MAX_DETAIL) : "";
      if (signal || detail) out.push({ signal: signal, detail: detail });
    }
    return out;
  }

  function cleanConfidence(value) {
    var n = typeof value === "number" ? value : parseInt(value, 10);
    return Number.isInteger(n) && n >= 50 && n <= 99 ? n : null;
  }

  /** An epoch-ms time: a positive safe integer (a number is floored), else null. */
  function cleanUntil(value) {
    var n = typeof value === "number" && Number.isFinite(value) ? Math.floor(value)
      : typeof value === "string" && UNTIL_RE.test(value) ? Number(value) : NaN;
    return Number.isSafeInteger(n) && n > 0 ? n : null;
  }

  /**
   * The block page's full address for `verdict` (domain, reasons,
   * confidence_pct, advisory_until) blocked at `pageUrl`. `base` is
   * chrome.runtime.getURL(""). Null when the domain isn't a hostname.
   */
  function build(base, verdict, pageUrl) {
    var v = verdict || {};
    var host = cleanHost(v.domain);
    if (!host) return null;
    var parts = ["d=" + encodeURIComponent(host)];
    var url = cleanUrl(pageUrl, host);
    if (url) parts.push("u=" + encodeURIComponent(url));
    var conf = cleanConfidence(v.confidence_pct);
    if (conf !== null) parts.push("c=" + encodeURIComponent(String(conf)));
    var reasons = cleanReasons(v.reasons).map(function (r) {
      return { s: r.signal, t: r.detail };
    });
    if (reasons.length) parts.push("r=" + encodeURIComponent(JSON.stringify(reasons)));
    var until = cleanUntil(v.advisory_until);
    if (until !== null) parts.push("x=" + until);
    return String(base || "") + PAGE_PATH + "?" + parts.join("&");
  }

  /**
   * The verdict back out of a block page's query string (location.search,
   * or a full blocked.html address). Every field validated; never throws.
   * @returns {{domain: string, url: string, confidence_pct: (number|null), reasons: Array<{signal: string, detail: string}>, advisory_until: (number|null)}}
   */
  function parse(search) {
    var out = { domain: "", url: "", confidence_pct: null, reasons: [], advisory_until: null };
    if (typeof search !== "string") return out;
    var q = search;
    var at = q.indexOf("?");
    if (at >= 0) q = q.slice(at + 1);
    var hash = q.indexOf("#");
    if (hash >= 0) q = q.slice(0, hash);
    var params;
    try {
      params = new URLSearchParams(q);
    } catch (e) {
      return out;
    }
    out.domain = cleanHost(params.get("d"));
    out.url = cleanUrl(params.get("u"), out.domain);
    out.confidence_pct = cleanConfidence(params.get("c"));
    out.advisory_until = cleanUntil(params.get("x"));
    var raw = params.get("r");
    if (raw) {
      try {
        var list = JSON.parse(raw);
        if (Array.isArray(list)) {
          out.reasons = cleanReasons(list.map(function (r) {
            return r && typeof r === "object" ? { signal: r.s, detail: r.t } : null;
          }));
        }
      } catch (e) { /* malformed: no reasons */ }
    }
    return out;
  }

  /**
   * Whether a verdict (parse()'s, or the background's) rests on Google's
   * lists: it has Google's window, or one of its reasons is Google's.
   */
  function restsOnGoogle(shown) {
    if (!shown) return false;
    if (typeof shown.advisory_until === "number") return true;
    return Array.isArray(shown.reasons) && shown.reasons.some(function (r) {
      return Boolean(r) && r.signal === GOOGLE_REASON;
    });
  }

  /**
   * True when a block page may not draw its verdict from its own address: it
   * rests on Google and Google's window is over at `nowMs`, or was never
   * given. The page asks the background again instead.
   */
  function needsRecheck(shown, nowMs) {
    if (!restsOnGoogle(shown)) return false;
    return !(typeof shown.advisory_until === "number" && shown.advisory_until > nowMs);
  }

  /** True when `url` is the block page of the extension at `base`. */
  function isBlockedPageUrl(url, base) {
    if (typeof url !== "string" || !base) return false;
    var page = String(base) + PAGE_PATH;
    return url === page || url.indexOf(page + "?") === 0 || url.indexOf(page + "#") === 0;
  }

  root.cleanwayBlockedUrl = {
    PAGE_PATH: PAGE_PATH,
    build: build,
    parse: parse,
    cleanHost: cleanHost,
    cleanUrl: cleanUrl,
    isBlockedPageUrl: isBlockedPageUrl,
    restsOnGoogle: restsOnGoogle,
    needsRecheck: needsRecheck,
  };
})(typeof self !== "undefined" ? self : globalThis);
