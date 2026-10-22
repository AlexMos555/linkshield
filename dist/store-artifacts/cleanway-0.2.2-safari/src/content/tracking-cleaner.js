/**
 * Tracking Parameter Cleaner
 *
 * Removes tracking parameters from URLs automatically:
 * - Facebook: fbclid, fb_action_ids, fb_action_types, fb_ref, fb_source
 * - Google: gclid, gclsrc, utm_source, utm_medium, utm_campaign, utm_term, utm_content
 * - Microsoft: msclkid
 * - Other: mc_cid, mc_eid, _openstat, yclid, _hsenc, _hsmi, vero_id
 *
 * Privacy benefit: prevents cross-site tracking via URL parameters.
 * Works transparently — user doesn't notice, URLs just get cleaner.
 */

var TRACKING_PARAMS = [
  // Facebook
  "fbclid", "fb_action_ids", "fb_action_types", "fb_ref", "fb_source",
  // Google Ads
  "gclid", "gclsrc", "dclid",
  // UTM (analytics)
  "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
  // Microsoft
  "msclkid",
  // Mailchimp
  "mc_cid", "mc_eid",
  // Yandex
  "yclid", "_openstat",
  // HubSpot
  "_hsenc", "_hsmi",
  // Vero
  "vero_id",
  // General
  "ref", "ref_src", "ref_url",
  // Twitter/X
  "twclid",
  // Adobe
  "s_cid",
  // Other
  "igshid", "si", "feature",
];

var _cleanedCount = 0;

function cleanTrackingParams() {
  var url = new URL(window.location.href);
  var params = url.searchParams;
  var removed = [];

  for (var p of TRACKING_PARAMS) {
    if (params.has(p)) {
      removed.push(p);
      params.delete(p);
    }
  }

  if (removed.length > 0) {
    var cleanUrl = url.toString();
    // Only update if URL actually changed
    if (cleanUrl !== window.location.href) {
      window.history.replaceState(null, "", cleanUrl);
      _cleanedCount += removed.length;
      console.debug("[Cleanway] Cleaned tracking params:", removed.join(", "));
    }
  }
}

// Clean on page load
cleanTrackingParams();

// Clean on navigation (SPA).
//
// The previous version used a MutationObserver on document.body with
// subtree:true and reacted to ANY mutation just to spot a URL change.
// On heavy SPAs (Twitter, Facebook, modern dashboards) the body
// mutates many times per second — that observer was burning CPU on
// every keystroke / scroll-induced lazy-load just to do an O(1) URL
// comparison.
//
// History API hooks are O(1) and fire exactly once per navigation:
//   - popstate covers back/forward navigation
//   - pushState/replaceState are wrapped to cover programmatic SPA nav
// The "did URL change" guard inside cleanTrackingParams() doubles as
// the base case for the recursion that wrapping replaceState would
// otherwise cause (we call replaceState ourselves to write the
// cleaned URL — without the guard it'd loop).
window.addEventListener("popstate", cleanTrackingParams);

(function wrapHistoryMethod(method) {
  var original = window.history[method];
  if (typeof original !== "function") return;
  window.history[method] = function() {
    var ret = original.apply(this, arguments);
    cleanTrackingParams();
    return ret;
  };
})("pushState");
(function wrapHistoryMethod(method) {
  var original = window.history[method];
  if (typeof original !== "function") return;
  window.history[method] = function() {
    var ret = original.apply(this, arguments);
    cleanTrackingParams();
    return ret;
  };
})("replaceState");
