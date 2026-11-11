/**
 * Reason lines under a badge, in the browser's language.
 *
 * Both scorers and the API explain a verdict with an English `detail`
 * ("Impersonates paypal.com", "Contains 'login'", "Google lists this site as
 * possibly unsafe") plus a machine-readable `signal` code. A Russian user used to
 * read «Опасно» followed by English. This maps the code to a plain-language
 * line from packages/i18n-strings (extension.reason) and keeps the English
 * detail only for a code nobody has mapped yet, so a line never renders
 * blank or as a raw key.
 *
 * The API codes and most groups mirror mobile/src/utils/reason-label.ts, and
 * many texts are the app's own translations: a person does not need to know
 * whether malware intel came from URLhaus or ThreatFox, only that the site
 * is "known to spread malware". Three codes have their own group here and
 * not (yet) in the app: ipqs_high_risk, new_certificate, invalid_certificate.
 *
 * The block page (content/block-page.js) groups its evidence cards by the
 * same codes: the card title is the reason line and its body is the matching
 * extension.evidence text.
 *
 * Classic content script (manifest content_scripts, before block-page.js and
 * index.js). The only thing it publishes on the shared isolated-world global
 * is window.__cleanwayReasons. scripts/test-extension-core.mjs checks that
 * every key below exists in all ten locales, and that every code the API and
 * both offline scorers can emit is mapped here.
 */
(function () {
  "use strict";

  // A group is one badge line and one block-page card, so its text must be
  // true of EVERY code in it: the card can be the whole visible reason for a
  // block. When a code only resembles its neighbours (a risk score is not a
  // report; a renewed certificate is not a new site), it gets its own group.
  var REASON_KEYS = Object.freeze({
    // Threat-intelligence blocklists (API)
    safe_browsing: "flagged_dangerous",
    ipqs_phishing: "flagged_phishing",
    // A numeric IPQualityScore estimate above 75, not a report of phishing
    ipqs_high_risk: "high_risk_score",
    phishtank: "flagged_phishing",
    phishstats: "flagged_phishing",
    surbl: "on_blocklists",
    spamhaus_dbl: "on_blocklists",
    multi_blocklist: "on_blocklists",
    alienvault_otx: "threat_reports",
    alienvault_otx_high: "threat_reports",
    urlhaus: "spreads_malware",
    malware_bazaar: "spreads_malware",
    feodo: "spreads_malware",
    threatfox: "spreads_malware",
    // Impersonation (API + both offline scorers)
    typosquatting: "imitates_brand",
    watchtower_typosquat: "imitates_brand",
    combosquatting: "imitates_brand",
    similar: "imitates_brand",
    homograph_attack: "lookalike_letters",
    brand_subdomain_abuse: "fake_brand_address",
    brand_subdomain: "fake_brand_address",
    brand_sub: "fake_brand_address",
    fake_tld_subdomain: "fake_brand_address",
    fake_tld: "fake_brand_address",
    favicon_brand_clone: "copies_brand_icon",
    // Connection / setup
    no_https: "no_https",
    missing_headers: "missing_protections",
    ip_based: "raw_ip_address",
    non_standard_port: "unusual_connection",
    url_shortener: "hidden_destination",
    at_symbol: "hidden_destination",
    // Freshness
    domain_new: "very_new_site",
    domain_very_new: "very_new_site",
    free_ssl_new_domain: "very_new_site",
    // Certificate issued under 7 days ago: an old site that renewed its
    // Let's Encrypt certificate gets this too, so it is not "a new site"
    new_certificate: "new_certificate",
    // Address shape
    suspicious_keyword: "scam_words",
    keyword: "scam_words",
    url_pii_leak: "carries_personal_data",
    long_url: "long_complex_address",
    very_long_url: "long_complex_address",
    long_domain_name: "long_complex_address",
    long_domain: "long_complex_address",
    long: "long_complex_address",
    many_hyphens: "long_complex_address",
    hyphens: "long_complex_address",
    deep_path: "long_complex_address",
    excessive_redirects: "many_redirects",
    multiple_redirects: "many_redirects",
    cross_domain_redirect: "many_redirects",
    double_slash_redirect: "many_redirects",
    risky_tld_high: "risky_ending",
    risky_tld_medium: "risky_ending",
    risky_tld: "risky_ending",
    abused_registrar: "risky_registrar",
    risky_registrar: "risky_registrar",
    hosting_platform: "shared_hosting",
    // Randomly-generated-looking names
    high_entropy: "random_name",
    medium_entropy: "random_name",
    suspicious_ngram: "random_name",
    unnatural_ngram: "random_name",
    consonant_cluster: "random_name",
    abnormal_vowel_ratio: "random_name",
    high_digit_ratio: "random_name",
    high_digits: "random_name",
    excessive_special_chars: "random_name",
    many_special_chars: "random_name",
    hex_encoding: "random_name",
    // Suspicious infrastructure
    no_mx_record: "not_a_real_business",
    // Both are also how CDNs run; the line says "scam networks ALSO use it"
    low_dns_ttl: "shifty_setup",
    dynamic_dns_host: "shifty_setup",
    many_a_records: "shifty_setup",
    excessive_subdomains: "padded_address",
    deep_subdomains: "padded_address",
    subdomains: "padded_address",
    // Detector
    ml_suspicious: "detector_suspicious",
    ml_high_risk: "detector_suspicious",
    // Trust (safe)
    known_legitimate: "well_known_site",
    tranco_popularity: "popular_site",
    ml_safe_override: "detector_safe",
    user_whitelist: "on_your_trusted_list",
    // Our own list (the API aliases it to multi_blocklist for this client,
    // api/routers/public.py _LEGACY_CODE_ALIASES, but a newer build may not)
    cleanway_blocklist: "on_cleanway_list",
    // Expired, self-signed or issued for another name. The API sends it as
    // no_https to clients without X-Cleanway-Install (api/routers/public.py
    // _LEGACY_CODE_ALIASES); a site with a broken certificate still HAS https.
    invalid_certificate: "broken_certificate",
    // What a verdict could not see (api/services/verdict_basis.py
    // INFORMATIONAL_REASONS). The public API sends one of these to this
    // client when nothing else explains the verdict.
    domain_not_found: "site_not_found",
    unreachable_from_scanner: "unreachable_abroad",
    checks_incomplete: "checks_incomplete",
    partial_analysis: "checks_incomplete",
    analysis_error: "checks_incomplete",
    user_content_platform: "user_content_platform",
    // The analyzer refused the address itself
    invalid_domain: "invalid_address",
    invalid: "invalid_address",
    ssrf_blocked: "private_network",
    // The AI second opinion on a borderline verdict; its detail is the
    // model's own English sentence, so it gets a neutral line instead
    llm_judge: "ai_second_look",
  });

  /**
   * @param {{ signal?: string }} reason
   * @returns {string|null} the reason group (a key of extension.reason and
   *   extension.evidence), or null for a code nobody has mapped yet
   */
  function reasonGroup(reason) {
    var signal = reason && reason.signal;
    if (typeof signal !== "string" || !Object.prototype.hasOwnProperty.call(REASON_KEYS, signal)) {
      return null;
    }
    return REASON_KEYS[signal];
  }

  /**
   * @param {{ signal?: string, detail?: string }} reason
   * @returns {string} the localized line, or the English detail if the code
   *   is unmapped or the catalog lacks the key
   */
  function reasonText(reason) {
    var detail = (reason && reason.detail) || "";
    var group = reasonGroup(reason);
    if (!group) return detail;
    // Built at run time, so the static key scan in test-extension-core.mjs
    // cannot see it; that suite checks every REASON_KEYS value instead.
    var messageKey = "reason_" + group;
    try {
      return chrome.i18n.getMessage(messageKey) || detail;
    } catch (e) {
      return detail;
    }
  }

  // ── Google's credit ──────────────────────────────────────────────────
  // The API's code for a hit on Google's lists: Safe Browsing v4 once, Google
  // Web Risk in production since 2026-11-03 (api/services/web_risk.py keeps
  // the code). Web Risk's rules for warnings (docs.cloud.google.com/web-risk/
  // docs/user-warnings, read 2026-11-03): a warning about a page Google
  // flagged carries "Advisory provided by Google" linked to the Web Risk
  // Advisory and lets people learn more about its threat type (antiphishing.org
  // for phishing, Google Search Central for malware, Google's policy for
  // unwanted software — the server asks about all three); a warning built on
  // other sources must not carry Google's name. The app (mobile/src/utils/
  // google-advisory.ts) and the site (landing/lib/google-advisory.ts) link
  // the same pages.
  var GOOGLE_SIGNAL = "safe_browsing";
  var GOOGLE_LINKS = Object.freeze({
    advisory: "https://docs.cloud.google.com/web-risk/docs/advisory",
    phishing: "https://www.antiphishing.org/",
    malware: "https://developers.google.com/search/docs/advanced/security/malware",
    unwanted: "https://www.google.com/about/company/unwanted-software-policy.html",
  });

  /**
   * @param {Array<{ signal?: string }>} reasons a verdict's reasons
   * @returns {boolean} whether one of them is Google's
   */
  function fromGoogle(reasons) {
    if (!Array.isArray(reasons)) return false;
    for (var i = 0; i < reasons.length; i++) {
      if (reasons[i] && reasons[i].signal === GOOGLE_SIGNAL) return true;
    }
    return false;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function message(key, english) {
    try {
      return chrome.i18n.getMessage(key) || english;
    } catch (e) {
      return english;
    }
  }

  function link(href, text) {
    return '<a href="' + href + '" target="_blank" rel="noopener noreferrer">' + escapeHtml(text) + "</a>";
  }

  /**
   * "Advisory provided by Google" and the learn-more links, as markup for the
   * block page, a link badge's tooltip and the context-menu check — or "" when
   * none of the reasons is Google's. Styled by .ls-google-advisory (the block
   * page's own <style>, styles/badges.css on web pages).
   */
  function googleAdvisoryHtml(reasons) {
    if (!fromGoogle(reasons)) return "";
    // Literal keys: scripts/test-extension-core.mjs finds each advisory_* key
    // and checks it in every locale.
    var credit = message("advisory_google", "Advisory provided by Google");
    var more = message("advisory_learn_more", "Learn more:");
    var phishing = message("advisory_learn_phishing", "phishing");
    var malware = message("advisory_learn_malware", "malware");
    var unwanted = message("advisory_learn_unwanted", "unwanted software");
    return '<div class="ls-google-advisory">' +
      '<div class="ls-google-advisory-credit">' + link(GOOGLE_LINKS.advisory, credit) + "</div>" +
      '<div class="ls-google-advisory-more">' + escapeHtml(more) + " " +
      link(GOOGLE_LINKS.phishing, phishing) + " · " + link(GOOGLE_LINKS.malware, malware) + " · " +
      link(GOOGLE_LINKS.unwanted, unwanted) + "</div>" +
      "</div>";
  }

  window.__cleanwayReasons = Object.freeze({
    text: reasonText,
    group: reasonGroup,
    keys: REASON_KEYS,
    fromGoogle: fromGoogle,
    googleAdvisoryHtml: googleAdvisoryHtml,
    googleLinks: GOOGLE_LINKS,
  });
})();
