/**
 * Where Cleanway is listed in app stores, for the few places the app sends
 * people to one.
 *
 * Only the RuStore build checks every incoming SMS by itself (its manifest
 * asks for RECEIVE_SMS; the APK from cleanway.ai never may — Play Protect
 * blocks sideloaded apps that do). So the app from the website may point to
 * the RuStore listing for that, and the RuStore build is sent there for its
 * updates. Until the listing is live every such line stays hidden: no link to
 * a page that does not exist, no promise of a version nobody can install.
 *
 * To go live: set `available: true` and the listing's https URL, e.g.
 * https://www.rustore.ru/catalog/app/ai.cleanway.app — the same change as
 * flipping a store on in landing/lib/install-urls.ts.
 *
 * Pure — no React Native — so scripts/test-sms-shield-ui.mjs runs it.
 */

export interface StoreListing {
  /** The listing is live and installable. */
  available: boolean;
  /** Its https page; ignored while `available` is false. */
  url: string;
}

export const STORES: { readonly rustore: StoreListing } = {
  rustore: { available: false, url: "" },
};

/** https, on rustore.ru or a subdomain of it, no spaces: nothing else is opened. */
const RUSTORE_PAGE = /^https:\/\/([a-z0-9-]+\.)*rustore\.ru(\/[^\s]*)?$/i;

/**
 * The RuStore listing to open, or null while it is not live — or when the
 * configured URL is not an https rustore.ru page (a typo must hide the line,
 * not open something else).
 */
export function rustoreListingUrl(listing: StoreListing = STORES.rustore): string | null {
  if (!listing.available) return null;
  const url = listing.url.trim();
  return RUSTORE_PAGE.test(url) ? url : null;
}
