import type { TFunction } from "i18next";

/**
 * A localized, grandma-grade label for a check reason.
 *
 * The public API returns each reason as an English `detail` string plus a
 * machine-readable `code`. Showing the English detail to a Russian or Arabic
 * user broke the whole grandma-grade promise (they saw "Site does not use
 * HTTPS encryption" in English). We map the code to a plain-language label in
 * the user's language and fall back to the English `detail` for any code we
 * don't cover yet — so nothing ever renders blank or as a raw code.
 *
 * Many codes share one label on purpose: a person does not need to know
 * whether malware intel came from URLhaus or ThreatFox, only that the site is
 * "known to spread malware". The technical distinctions live in the reason's
 * detail for anyone who wants them; the label is for deciding "do I trust
 * this?".
 */
const CODE_TO_KEY: Record<string, string> = {
  // Threat-intelligence blocklists
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
  // Malware
  urlhaus: "spreads_malware",
  malware_bazaar: "spreads_malware",
  feodo: "spreads_malware",
  threatfox: "spreads_malware",
  // Impersonation
  typosquatting: "imitates_brand",
  watchtower_typosquat: "imitates_brand",
  homograph_attack: "lookalike_letters",
  brand_subdomain_abuse: "fake_brand_address",
  fake_tld_subdomain: "fake_brand_address",
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
  // Randomly-generated-looking names (all the entropy/ngram/char family)
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
  // Suspicious infrastructure (DNS/hosting shape)
  no_mx_record: "not_a_real_business",
  low_dns_ttl: "shifty_setup",
  many_a_records: "shifty_setup",
  excessive_subdomains: "padded_address",
  // ML
  ml_suspicious: "detector_suspicious",
  ml_high_risk: "detector_suspicious",
  // Trust (safe)
  known_legitimate: "well_known_site",
  tranco_popularity: "popular_site",
  ml_safe_override: "detector_safe",
};

/**
 * Localized label for one reason. `code` may be undefined (older API builds);
 * an unmapped or missing code falls back to the English `detail`.
 */
export function reasonLabel(
  reason: { detail: string; code?: string },
  t: TFunction,
): string {
  const key = reason.code ? CODE_TO_KEY[reason.code] : undefined;
  if (!key) return reason.detail;
  // defaultValue = the English detail, so a key we forgot to translate still
  // renders something real rather than the raw dotted key.
  return t(`mobile.reason.${key}`, { defaultValue: reason.detail });
}
