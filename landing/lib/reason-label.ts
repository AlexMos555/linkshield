/**
 * Plain-language label key for a verdict reason code from the public check API.
 *
 * The API returns each reason as an English `detail` plus a machine-readable
 * code. The /check scorecard used to print the English detail on every locale
 * ("Site does not use HTTPS encryption" on the Russian page). The labels
 * themselves are the app's (mobile.reason.*, exposed to the landing as the
 * `Reasons` namespace by scripts/build-i18n.py); this is the code → label map.
 *
 * It mirrors mobile/src/utils/reason-label.ts — scripts/test-landing-honesty.mjs
 * fails if the two drift apart. An unmapped code returns null and the caller
 * falls back to the API's English detail, so nothing renders blank.
 */
const CODE_TO_KEY: Readonly<Record<string, string>> = {
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
  typosquatting: "imitates_brand",
  watchtower_typosquat: "imitates_brand",
  homograph_attack: "lookalike_letters",
  brand_subdomain_abuse: "fake_brand_address",
  fake_tld_subdomain: "fake_brand_address",
  favicon_brand_clone: "copies_brand_icon",
  no_https: "no_https",
  missing_headers: "missing_protections",
  ip_based: "raw_ip_address",
  non_standard_port: "unusual_connection",
  url_shortener: "hidden_destination",
  at_symbol: "hidden_destination",
  domain_new: "very_new_site",
  domain_very_new: "very_new_site",
  new_certificate: "very_new_site",
  free_ssl_new_domain: "very_new_site",
  suspicious_keyword: "scam_words",
  url_pii_leak: "carries_personal_data",
  long_url: "long_complex_address",
  very_long_url: "long_complex_address",
  long_domain_name: "long_complex_address",
  deep_path: "long_complex_address",
  excessive_redirects: "many_redirects",
  multiple_redirects: "many_redirects",
  cross_domain_redirect: "many_redirects",
  double_slash_redirect: "many_redirects",
  risky_tld_high: "risky_ending",
  risky_tld_medium: "risky_ending",
  abused_registrar: "risky_registrar",
  risky_registrar: "risky_registrar",
  high_entropy: "random_name",
  medium_entropy: "random_name",
  suspicious_ngram: "random_name",
  unnatural_ngram: "random_name",
  consonant_cluster: "random_name",
  abnormal_vowel_ratio: "random_name",
  high_digit_ratio: "random_name",
  excessive_special_chars: "random_name",
  many_special_chars: "random_name",
  hex_encoding: "random_name",
  no_mx_record: "not_a_real_business",
  low_dns_ttl: "shifty_setup",
  many_a_records: "shifty_setup",
  excessive_subdomains: "padded_address",
  ml_suspicious: "detector_suspicious",
  ml_high_risk: "detector_suspicious",
  known_legitimate: "well_known_site",
  tranco_popularity: "popular_site",
  ml_safe_override: "detector_safe",
};

export function reasonLabelKey(code: string | undefined | null): string | null {
  if (!code) return null;
  return Object.prototype.hasOwnProperty.call(CODE_TO_KEY, code) ? CODE_TO_KEY[code] : null;
}

/** Exported for the drift test only. */
export const REASON_CODE_TO_KEY = CODE_TO_KEY;
