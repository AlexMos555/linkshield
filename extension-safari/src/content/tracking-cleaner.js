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

// Clean on navigation (SPA)
var _lastUrl = window.location.href;
var _cleanObserver = new MutationObserver(function() {
  if (window.location.href !== _lastUrl) {
    _lastUrl = window.location.href;
    cleanTrackingParams();
  }
});
_cleanObserver.observe(document.body, { childList: true, subtree: true });
