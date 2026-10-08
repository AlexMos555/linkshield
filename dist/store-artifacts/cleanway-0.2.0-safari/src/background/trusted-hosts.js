/**
 * Hosts the service worker answers for WITHOUT asking the API.
 *
 * Only the hostname of a link or page ever leaves the browser — never the
 * path, which can carry personal data (a form id, an e-mail, a token). So
 * neither the API nor this file can tell two pages on the same host apart.
 * That splits hosts into three kinds:
 *
 *   1. Official hosts (OFFICIAL_HOSTS): every page is written by the
 *      company itself. Answered "safe" locally, which also saves API calls —
 *      the public check endpoint is rate limited per IP, and every page is
 *      full of links to the same big sites.
 *   2. User-content hosts (USER_CONTENT_HOSTS): anyone can publish a page,
 *      form or file under the same hostname (docs.google.com/forms/…,
 *      forms.yandex.ru/u/…, disk.yandex.ru/d/…). A real form and a scam form
 *      look identical from the hostname, so no verdict about the host says
 *      anything about the page. The honest answer is neither green nor red:
 *      "anyone can publish here — don't enter card details or passwords".
 *      The API is not asked; it would only be judging the platform.
 *   3. Everything else goes to the API. That includes hosting where each
 *      author gets their OWN subdomain (anything.wordpress.com,
 *      someone.github.io): there the hostname does identify the page's
 *      owner, and blocklists list such hosts one by one.
 *
 * The previous version matched on the last two labels of the host, so it
 * trusted EVERY subdomain of google.com, yandex.ru, vk.com, wordpress.com,
 * notion.so, dropbox.com... Scammers live exactly there.
 *
 * Rules for both lists:
 *   - EXACT hosts only. A subdomain is a different host. The one exception is
 *     a leading "www.", which is always run by the owner of the name after it.
 *   - OFFICIAL_HOSTS: only hosts whose pages the company itself writes.
 *     Social feeds (vk.com, ok.ru, facebook.com...) stay in: a post is
 *     rendered by the platform, it cannot put a login form on that origin.
 *     Their outbound-link redirectors (vk.com/away.php…) are unwrapped
 *     before the check, see utils/link-target.js.
 *   - USER_CONTENT_HOSTS: only hosts where the author of a page is invisible
 *     in the hostname, and that are used to host scam forms, "documents" or
 *     download lures.
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

const USER_CONTENT_HOSTS = new Set([
  // Google: forms, documents, sites, files, Apps Script web apps.
  "docs.google.com", "drive.google.com", "sites.google.com", "forms.gle",
  "script.google.com", "script.googleusercontent.com",
  "storage.googleapis.com", "firebasestorage.googleapis.com",
  // Yandex and Mail.ru: forms and file sharing.
  "forms.yandex.ru", "forms.yandex.com", "disk.yandex.ru", "disk.yandex.com",
  "disk.360.yandex.ru", "yadi.sk", "cloud.mail.ru",
  // Microsoft: forms, files, Sway pages.
  "forms.office.com", "forms.microsoft.com", "onedrive.live.com", "1drv.ms",
  "sway.office.com", "sway.cloud.microsoft",
  // File sharing, page builders and publish-anything hosts.
  "dropbox.com", "dl.dropboxusercontent.com", "notion.so", "canva.com",
  "form.jotform.com", "telegra.ph", "graph.org", "teletype.in",
  "ipfs.io", "dweb.link", "cloudflare-ipfs.com",
]);

// Lower-cased host without a trailing dot or a leading "www.", or null.
function bareHost(host) {
  if (typeof host !== "string" || host !== host.trim()) return null;
  const name = host.toLowerCase().replace(/\.$/, "");
  return name.startsWith("www.") ? name.slice(4) : name;
}

/**
 * @param {unknown} host — hostname as the browser reports it
 * @returns {boolean} true only for an exact official host (or its www.)
 */
export function isKnownSafeHost(host) {
  const bare = bareHost(host);
  return bare !== null && OFFICIAL_HOSTS.has(bare);
}

/**
 * @param {unknown} host — hostname as the browser reports it
 * @returns {boolean} true for an exact host where anyone can publish a page,
 *   form or file under that same hostname (or its www.)
 */
export function isUserContentHost(host) {
  const bare = bareHost(host);
  return bare !== null && USER_CONTENT_HOSTS.has(bare);
}
