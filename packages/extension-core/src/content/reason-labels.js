/**
 * Reason lines under a badge, in the browser's language.
 *
 * Both scorers and the API explain a verdict with an English `detail`
 * ("Impersonates paypal.com", "Contains 'login'", "Flagged by Google Safe
 * Browsing") plus a machine-readable `signal` code. A Russian user used to
 * read «Опасно» followed by English. This maps the code to a plain-language
 * line from packages/i18n-strings (extension.reason) and keeps the English
 * detail only for a code nobody has mapped yet, so a line never renders
 * blank or as a raw key.
 *
 * The API codes and their grouping mirror mobile/src/utils/reason-label.ts,
 * and the texts are the app's own translations: a person does not need to
 * know whether malware intel came from URLhaus or ThreatFox, only that the
 * site is "known to spread malware".
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

  var REASON_KEYS = Object.freeze({
    // Threat-intelligence blocklists (API)
    safe_browsing: "flagged_dangerous",
    ipqs_phishing: "flagged_phishing",
    ipqs_high_risk: "flagged_phishing",
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
    new_certificate: "very_new_site",
    free_ssl_new_domain: "very_new_site",
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
    low_dns_ttl: "shifty_setup",
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
    // The API's own legacy alias for a bad certificate
    invalid_certificate: "no_https",
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
   * @param {{ signal?: string, detail?: string }} reason
   * @returns {string} the localized line, or the English detail if the code
   *   is unmapped or the catalog lacks the key
   */
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

  window.__cleanwayReasons = Object.freeze({ text: reasonText, group: reasonGroup, keys: REASON_KEYS });
})();
