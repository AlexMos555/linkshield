/**
 * The open data Cleanway is built from, as /transparency/methodology credits it
 * (the "Data sources" section) and the app's Settings → About links to it.
 *
 * Since 2026-10-23 the popularity ranking — the allowlist, the popularity
 * signal of every check, and from their next releases the phone's veto list
 * and the extensions' tenant suffixes — and the model's real-site examples
 * come from the Majestic Million (CC BY 3.0) and the Chrome UX Report
 * (CC BY 4.0), and CC BY asks for credit where the adapted data is used in
 * public: who made it, the licence, a link, and that it was changed. The
 * changes are the section's text, the ranking's and the model's apart; the
 * full table of every source and its terms is docs/THIRD_PARTY_FEEDS.md.
 *
 * Names, makers and licence names are never translated: the credit is to
 * them. `id` is the name the build scripts use (data/top_domains_sources.json,
 * data/model_meta.json, scripts/refresh_dangerous_domains.py), so
 * tests/test_data_attribution.py can hold this list to every feed in use.
 */

/** The section's id; the app links to /transparency/methodology#data-sources. */
export const DATA_SOURCES_ANCHOR = "data-sources";

export const THIRD_PARTY_FEEDS_URL = "https://github.com/AlexMos555/linkshield/blob/main/docs/THIRD_PARTY_FEEDS.md";

export type DataSource = {
  id: string;
  name: string;
  /** Who made it, as the source credits itself. */
  by: string | null;
  url: string;
  /** null: no standard licence — the page links the source's own terms. */
  licence: string | null;
  licenceUrl: string;
  /** A cache we read the data through, credited after the licence. */
  via?: { name: string; url: string };
};

const CC0 = "https://creativecommons.org/publicdomain/zero/1.0/";

/** Which sites count as popular, and what a real site looks like to the model. */
export const POPULARITY_SOURCES: readonly DataSource[] = [
  {
    id: "Majestic Million",
    name: "Majestic Million",
    by: "Majestic-12 Ltd",
    url: "https://majestic.com/reports/majestic-million",
    licence: "CC BY 3.0",
    licenceUrl: "https://creativecommons.org/licenses/by/3.0/",
  },
  {
    id: "Chrome UX Report",
    name: "Chrome UX Report",
    by: "Google",
    url: "https://developer.chrome.com/docs/crux",
    licence: "CC BY 4.0",
    licenceUrl: "https://creativecommons.org/licenses/by/4.0/",
    via: { name: "crux-top-lists (Zakir Durumeric)", url: "https://github.com/zakird/crux-top-lists" },
  },
];

/** The blocklist (BLOCKLIST_LICENSED_ONLY, as production builds it) and the model's phishing examples. */
export const PHISHING_SOURCES: readonly DataSource[] = [
  {
    id: "PhishDestroy",
    name: "PhishDestroy DestroyList",
    by: null,
    url: "https://phishdestroy.io/dataset",
    licence: "CC0 1.0",
    licenceUrl: CC0,
  },
  {
    id: "CERT Polska",
    name: "CERT Polska, Lista Ostrzeżeń",
    by: null,
    url: "https://cert.pl/en/warning-list/",
    licence: null,
    licenceUrl: "https://hole.cert.pl/schema/certpl_lista_ostrzezen_api_v2.pdf",
  },
  {
    id: "TweetFeed",
    name: "TweetFeed",
    by: null,
    url: "https://tweetfeed.live/",
    licence: "CC0 1.0",
    licenceUrl: CC0,
  },
  {
    id: "Phishunt",
    name: "Phishunt.io",
    by: null,
    url: "https://phishunt.io/",
    licence: "CC0 1.0",
    licenceUrl: CC0,
  },
  // Not listed: Phishing.Database. MIT covers the maintainers' compilation,
  // but its data comes from upstream feeds they do not name (PhishStats, whose
  // terms bar redistribution, is one of the likely ones they did), so since
  // 2026-10-24 production builds without it (BLOCKLIST_LICENSED_ONLY;
  // docs/THIRD_PARTY_FEEDS.md §1). Back here only once its sources and their
  // terms are known in writing.
  // Not listed: CSIRT Italia (ACN). Its MISP feed states no licence (TLP:CLEAR
  // is a sharing label, not one) and ACN's Note legali bar commercial use, so
  // since 2026-10-23 production builds without it (BLOCKLIST_LICENSED_ONLY;
  // docs/THIRD_PARTY_FEEDS.md §1). Back here only with ACN's written permission.
];
