import type { MetadataRoute } from "next";

export default function sitemap(): MetadataRoute.Sitemap {
  const baseUrl = "https://linkshield.io";

  // Static pages
  const staticPages = [
    { url: baseUrl, lastModified: new Date(), changeFrequency: "weekly" as const, priority: 1.0 },
    { url: `${baseUrl}/check`, lastModified: new Date(), changeFrequency: "daily" as const, priority: 0.9 },
    { url: `${baseUrl}/privacy-policy`, lastModified: new Date(), changeFrequency: "monthly" as const, priority: 0.3 },
    { url: `${baseUrl}/terms`, lastModified: new Date(), changeFrequency: "monthly" as const, priority: 0.3 },
  ];

  // Top domains for SEO (most searched "is X safe?" queries)
  const topDomains = [
    "paypal.com", "facebook.com", "amazon.com", "netflix.com", "apple.com",
    "google.com", "microsoft.com", "instagram.com", "twitter.com", "linkedin.com",
    "whatsapp.com", "tiktok.com", "youtube.com", "reddit.com", "github.com",
    "discord.com", "twitch.tv", "spotify.com", "zoom.us", "ebay.com",
    "walmart.com", "target.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "coinbase.com", "binance.com", "robinhood.com", "venmo.com", "cashapp.com",
    "steam.com", "roblox.com", "fortnite.com", "minecraft.net",
    "usps.com", "fedex.com", "ups.com", "dhl.com",
  ];

  const domainPages = topDomains.map((domain) => ({
    url: `${baseUrl}/check/${domain}`,
    lastModified: new Date(),
    changeFrequency: "weekly" as const,
    priority: 0.7,
  }));

  const auditPages = topDomains.slice(0, 20).map((domain) => ({
    url: `${baseUrl}/audit/${domain}`,
    lastModified: new Date(),
    changeFrequency: "weekly" as const,
    priority: 0.5,
  }));

  return [...staticPages, ...domainPages, ...auditPages];
}
