import type { MetadataRoute } from "next";

import { routing } from "@/i18n/routing";
import { BILLING_ENABLED } from "@/lib/billing-config";
import { hreflangFor, localeUrl } from "@/lib/seo";
import { INDEXED_CHECK_DOMAINS } from "@/lib/seo-domains";

const LOCALES = routing.locales as readonly string[];

/** Sitemap alternates: the same hreflang set the pages emit (lib/seo.ts). */
function alternatesFor(path: string): { languages: Record<string, string> } {
  return { languages: hreflangFor(path) };
}

/*
 * No lastModified: the sitemap is rebuilt on every deploy, and stamping every
 * URL "modified now" each time teaches crawlers to ignore the field.
 */
export default function sitemap(): MetadataRoute.Sitemap {
  // Static homepage / index pages — one entry per (path × locale) with
  // mutual hreflang alternates so search engines pick the right variant.
  const staticPaths = [
    { path: "/", changeFrequency: "weekly" as const, priority: 1.0 },
    // The Android download page is the front door of the Tele2 funnel, and
    // /support is where its readers go when something goes wrong.
    { path: "/android", changeFrequency: "weekly" as const, priority: 0.95 },
    { path: "/support", changeFrequency: "monthly" as const, priority: 0.6 },
    { path: "/check", changeFrequency: "daily" as const, priority: 0.9 },
    { path: "/pricing", changeFrequency: "weekly" as const, priority: 0.85 },
    { path: "/transparency", changeFrequency: "weekly" as const, priority: 0.7 },
    { path: "/transparency/methodology", changeFrequency: "weekly" as const, priority: 0.7 },
    { path: "/dns", changeFrequency: "weekly" as const, priority: 0.7 },
    { path: "/business", changeFrequency: "monthly" as const, priority: 0.6 },
    { path: "/privacy-policy", changeFrequency: "monthly" as const, priority: 0.3 },
    { path: "/terms", changeFrequency: "monthly" as const, priority: 0.3 },
    // Google Play's "delete account URL" (docs/STORES.md).
    { path: "/delete-account", changeFrequency: "monthly" as const, priority: 0.3 },
    // The cancel/refund page exists only with the operator-billed subscription on.
    ...(BILLING_ENABLED ? [{ path: "/cancel", changeFrequency: "monthly" as const, priority: 0.4 }] : []),
  ];

  const staticEntries: MetadataRoute.Sitemap = staticPaths.flatMap(({ path, changeFrequency, priority }) =>
    LOCALES.map((locale) => ({
      url: localeUrl(locale, path),
      changeFrequency,
      priority,
      alternates: alternatesFor(path),
    })),
  );

  // /check/{domain} — one URL per (curated domain × locale) with mutual
  // hreflang. Exactly the set the pages themselves mark indexable.
  const domainEntries: MetadataRoute.Sitemap = INDEXED_CHECK_DOMAINS.flatMap((domain) => {
    const path = `/check/${domain}`;
    return LOCALES.map((locale) => ({
      url: localeUrl(locale, path),
      changeFrequency: "weekly" as const,
      priority: 0.7,
      alternates: alternatesFor(path),
    }));
  });

  // No /audit/{domain}: those pages are a teaser with no data, the same for
  // every site, so they are noindex (lib/seo-domains.ts) and stay out of here.

  return [...staticEntries, ...domainEntries];
}
