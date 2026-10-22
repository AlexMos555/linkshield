/**
 * Which /check/<site> pages search engines may index.
 *
 * /check/<anything> renders for every site name anyone types, so the route is
 * an infinite URL space: random strings, typos, live phishing hosts. Only the
 * curated list below is indexable (and listed in sitemap.xml); every other
 * /check page answers with noindex,follow — it still works and still passes
 * link equity, it just isn't a search landing page. /audit pages are never
 * indexed (a teaser with no data, the same for every site).
 *
 * Search demand for "is X safe" concentrates on these brands, and each one is
 * a localized landing page in 10 languages.
 */
export const INDEXED_CHECK_DOMAINS = [
  // Big tech / social
  "paypal.com", "facebook.com", "amazon.com", "netflix.com", "apple.com",
  "google.com", "microsoft.com", "instagram.com", "twitter.com", "x.com",
  "linkedin.com", "whatsapp.com", "tiktok.com", "youtube.com", "reddit.com",
  "github.com", "discord.com", "twitch.tv", "spotify.com", "snapchat.com",
  // Commerce
  "ebay.com", "walmart.com", "target.com", "etsy.com", "aliexpress.com",
  "shopify.com", "shein.com", "temu.com", "wish.com", "wayfair.com",
  // Banking / payments / crypto
  "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "capitalone.com",
  "americanexpress.com", "discover.com", "coinbase.com", "binance.com",
  "kraken.com", "robinhood.com", "venmo.com", "cashapp.com", "zellepay.com",
  "wise.com", "revolut.com",
  // Gaming / entertainment
  "steam.com", "steamcommunity.com", "epicgames.com", "roblox.com",
  "fortnite.com", "minecraft.net", "playstation.com", "xbox.com", "nintendo.com",
  // Logistics — heavily phished
  "usps.com", "fedex.com", "ups.com", "dhl.com", "royalmail.com",
  // Travel
  "booking.com", "airbnb.com", "expedia.com", "uber.com", "lyft.com",
  "delta.com", "united.com",
  // SaaS / productivity
  "dropbox.com", "slack.com", "zoom.us", "notion.so", "figma.com",
  "atlassian.com", "openai.com", "anthropic.com",
  // Russia — the launch market: the banks, marketplaces, delivery services and
  // state portals that scam SMS and fake sites imitate most. Each answered
  // "safe" with no warnings from the public check API when added (2026-10).
  "sberbank.ru", "gosuslugi.ru", "tbank.ru", "vtb.ru", "alfabank.ru",
  "ozon.ru", "wildberries.ru", "avito.ru", "vk.com", "ok.ru", "mail.ru",
  "yandex.ru", "pochta.ru", "cdek.ru", "mos.ru", "rzd.ru", "telegram.org",
];

const INDEXED = new Set<string>(INDEXED_CHECK_DOMAINS);

/** True when /check/<host> should be indexable. `host` is the normalized form (lib/check-host.ts). */
export function isIndexedCheckHost(host: string): boolean {
  return INDEXED.has(host);
}
