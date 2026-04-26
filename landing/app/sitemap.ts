import type { MetadataRoute } from "next";

import { routing, type Locale } from "@/i18n/routing";

const SITE = "https://cleanway.ai";
const LOCALES = routing.locales as readonly string[];
const DEFAULT_LOCALE = routing.defaultLocale;

/**
 * With `localePrefix: "as-needed"`, the default locale (en) lives at the
 * apex; every other locale is prefixed. Build a URL for any (locale, path).
 */
function urlFor(locale: Locale | string, path: string): string {
  const trimmed = path.startsWith("/") ? path : `/${path}`;
  return locale === DEFAULT_LOCALE ? `${SITE}${trimmed}` : `${SITE}/${locale}${trimmed}`;
}

/**
 * Build hreflang alternates for a path: maps every locale to its URL plus
 * an x-default pointing at the default locale. Next 15 emits this as
 * <xhtml:link rel="alternate" hreflang="..." /> in sitemap.xml.
 */
function alternatesFor(path: string): { languages: Record<string, string> } {
  const languages: Record<string, string> = {};
  for (const locale of LOCALES) {
    languages[locale] = urlFor(locale, path);
  }
  languages["x-default"] = urlFor(DEFAULT_LOCALE, path);
  return { languages };
}

/**
 * Pre-seed common phishing-target domains. Search demand for "is X safe"
 * is concentrated on these, and each becomes a localized landing page in
 * 10 languages = 10 SEO assets per scan-worthy entry.
 */
const TOP_DOMAINS = [
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
];

export default function sitemap(): MetadataRoute.Sitemap {
  const now = new Date();

  // Static homepage / index pages — one entry per (path × locale) with
  // mutual hreflang alternates so search engines pick the right variant.
  const staticPaths = [
    { path: "/", changeFrequency: "weekly" as const, priority: 1.0 },
    { path: "/check", changeFrequency: "daily" as const, priority: 0.9 },
    { path: "/pricing", changeFrequency: "weekly" as const, priority: 0.85 },
    { path: "/business", changeFrequency: "monthly" as const, priority: 0.6 },
    { path: "/privacy-policy", changeFrequency: "monthly" as const, priority: 0.3 },
    { path: "/terms", changeFrequency: "monthly" as const, priority: 0.3 },
  ];

  const staticEntries: MetadataRoute.Sitemap = staticPaths.flatMap(({ path, changeFrequency, priority }) =>
    LOCALES.map((locale) => ({
      url: urlFor(locale, path),
      lastModified: now,
      changeFrequency,
      priority,
      alternates: alternatesFor(path),
    })),
  );

  // /check/{domain} — one URL per (domain × locale) with mutual hreflang.
  const domainEntries: MetadataRoute.Sitemap = TOP_DOMAINS.flatMap((domain) => {
    const path = `/check/${domain}`;
    return LOCALES.map((locale) => ({
      url: urlFor(locale, path),
      lastModified: now,
      changeFrequency: "weekly" as const,
      priority: 0.7,
      alternates: alternatesFor(path),
    }));
  });

  // /audit/{domain} — same treatment for the privacy-audit deep-link page.
  // Subset of TOP_DOMAINS to keep sitemap under search-engine-friendly size.
  const auditEntries: MetadataRoute.Sitemap = TOP_DOMAINS.slice(0, 30).flatMap((domain) => {
    const path = `/audit/${domain}`;
    return LOCALES.map((locale) => ({
      url: urlFor(locale, path),
      lastModified: now,
      changeFrequency: "weekly" as const,
      priority: 0.5,
      alternates: alternatesFor(path),
    }));
  });

  return [...staticEntries, ...domainEntries, ...auditEntries];
}
