/**
 * Hosts the service worker may call "safe" without asking the API.
 *
 * The shortcut exists to save API calls (the public check endpoint is rate
 * limited per IP, and every page is full of links to the same big sites).
 * It must never answer for a page a stranger wrote.
 *
 * The previous version matched on the last two labels of the host, so it
 * trusted EVERY subdomain of google.com, yandex.ru, vk.com, wordpress.com,
 * notion.so, dropbox.com... Scammers live exactly there: sites.google.com
 * pages, docs.google.com and forms.yandex.ru forms that ask for card numbers,
 * disk.yandex.ru "documents", anything.wordpress.com fake logins. Those were
 * badged safe and never reached the analyzer.
 *
 * Rules for this list:
 *   - EXACT hosts only. A subdomain is a different host. The one exception is
 *     a leading "www.", which is always run by the owner of the name after it.
 *   - Only hosts whose pages the company itself writes. Anything where a user
 *     can publish their own page, form or file (docs, sites, forms, disk, blog
 *     platforms, code hosting, file sharing) stays out, apex included — for
 *     those the API decides, and it can grow path-level rules without an
 *     extension release.
 *   - Social feeds (vk.com, ok.ru, facebook.com...) stay in: a post is
 *     rendered by the platform, it cannot put a login form on that origin.
 */

// Every host dropped from the old suffix match now costs one API call (cached
// for an hour), so the company-authored product hosts people meet most stay.
const OFFICIAL_HOSTS = new Set([
  // Google — product front doors; never docs/sites/drive/forms/script/
  // photos/support (community posts), which strangers can publish on.
  "google.com", "accounts.google.com", "mail.google.com", "myaccount.google.com",
  "maps.google.com", "translate.google.com", "news.google.com", "play.google.com",
  "google.ru", "youtube.com", "m.youtube.com",
  // Russian services first-time users are most likely to meet daily.
  // Not forms/disk/cloud/dzen/sites: those are user-published.
  "yandex.ru", "ya.ru", "passport.yandex.ru", "mail.yandex.ru",
  "market.yandex.ru", "music.yandex.ru", "translate.yandex.ru",
  "mail.ru", "e.mail.ru", "account.mail.ru",
  "vk.com", "m.vk.com", "id.vk.com", "ok.ru", "m.ok.ru",
  "gosuslugi.ru", "esia.gosuslugi.ru", "nalog.gov.ru", "mos.ru",
  "pochta.ru", "rzd.ru",
  "sberbank.ru", "online.sberbank.ru", "vtb.ru", "tbank.ru", "alfabank.ru",
  "ozon.ru", "wildberries.ru",
  // International.
  "facebook.com", "m.facebook.com", "instagram.com", "whatsapp.com", "web.whatsapp.com",
  "twitter.com", "x.com", "linkedin.com", "reddit.com", "tiktok.com",
  "telegram.org", "web.telegram.org", "discord.com", "slack.com", "zoom.us",
  "wikipedia.org", "ru.wikipedia.org", "en.wikipedia.org",
  "apple.com", "microsoft.com", "bing.com", "yahoo.com", "netflix.com", "spotify.com",
  "twitch.tv", "stackoverflow.com", "cloudflare.com", "adobe.com",
  "amazon.com", "ebay.com", "walmart.com", "paypal.com", "stripe.com", "chase.com",
  "cnn.com", "bbc.com", "nytimes.com",
]);

/**
 * @param {unknown} host — hostname as the browser reports it
 * @returns {boolean} true only for an exact official host (or its www.)
 */
export function isKnownSafeHost(host) {
  if (typeof host !== "string" || host !== host.trim()) return false;
  const name = host.toLowerCase().replace(/\.$/, "");
  const bare = name.startsWith("www.") ? name.slice(4) : name;
  return OFFICIAL_HOSTS.has(bare);
}
