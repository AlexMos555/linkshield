/**
 * Bloom Filter — client-side known-safe domain lookup.
 *
 * Purpose: Check if a domain is in the Tranco Top 100K WITHOUT an API call.
 * If domain is in the bloom filter → mark as safe instantly (<1ms).
 * If not → send to API for full analysis.
 *
 * This means 95%+ of links on normal browsing are checked locally.
 * Only unknown/new domains hit the API.
 *
 * The filter is downloaded from CDN and cached locally.
 * False positive rate: ~0.1% (acceptable — just means extra API call).
 * False negatives: 0% (if domain is in the filter, it's always found).
 */

const BLOOM_STORAGE_KEY = "bloom_filter";
const BLOOM_META_KEY = "bloom_meta";
const BLOOM_CDN_URL = "https://cdn.cleanway.ai/bloom/top100k.json"; // TODO: setup CDN
const BLOOM_UPDATE_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours

// Bloom filter parameters for 100K items, 0.1% FP rate
const BLOOM_SIZE = 1_437_759; // bits (~175KB)
const BLOOM_HASH_COUNT = 10;

let _bloomBits = null;
let _bloomLoaded = false;

/**
 * MurmurHash3 — fast non-cryptographic hash
 */
function murmurhash3(key, seed) {
  let h = seed >>> 0;
  const len = key.length;

  for (let i = 0; i < len; i++) {
    let k = key.charCodeAt(i);
    k = Math.imul(k, 0xcc9e2d51);
    k = (k << 15) | (k >>> 17);
    k = Math.imul(k, 0x1b873593);
    h ^= k;
    h = (h << 13) | (h >>> 19);
    h = Math.imul(h, 5) + 0xe6546b64;
  }

  h ^= len;
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b);
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35);
  h ^= h >>> 16;

  return h >>> 0;
}

/**
 * Get hash positions for a key
 */
function getHashPositions(key) {
  const positions = [];
  for (let i = 0; i < BLOOM_HASH_COUNT; i++) {
    const hash = murmurhash3(key, i * 0x9e3779b9);
    positions.push(hash % BLOOM_SIZE);
  }
  return positions;
}

/**
 * Check if a domain might be in the bloom filter
 * Returns true if domain is PROBABLY in the set (safe domain)
 * Returns false if domain is DEFINITELY NOT in the set
 */
export function bloomCheck(domain) {
  if (!_bloomBits) return false; // Filter not loaded, assume unknown

  const positions = getHashPositions(domain.toLowerCase());
  for (const pos of positions) {
    const byteIdx = pos >>> 3;
    const bitIdx = pos & 7;
    if ((_bloomBits[byteIdx] & (1 << bitIdx)) === 0) {
      return false; // Definitely not in set
    }
  }
  return true; // Probably in set
}

/**
 * Build bloom filter from a list of domains (used by compiler)
 */
export function bloomBuild(domains) {
  const bits = new Uint8Array(Math.ceil(BLOOM_SIZE / 8));

  for (const domain of domains) {
    const positions = getHashPositions(domain.toLowerCase());
    for (const pos of positions) {
      const byteIdx = pos >>> 3;
      const bitIdx = pos & 7;
      bits[byteIdx] |= 1 << bitIdx;
    }
  }

  return bits;
}

/**
 * Load bloom filter from chrome.storage.local or CDN
 */
export async function loadBloomFilter() {
  if (_bloomLoaded) return;

  try {
    // Try loading from local storage first
    const stored = await chrome.storage.local.get([BLOOM_STORAGE_KEY, BLOOM_META_KEY]);

    if (stored[BLOOM_STORAGE_KEY] && stored[BLOOM_META_KEY]) {
      const meta = stored[BLOOM_META_KEY];
      const age = Date.now() - (meta.timestamp || 0);

      // Use cached version if less than 24h old
      if (age < BLOOM_UPDATE_INTERVAL_MS) {
        _bloomBits = new Uint8Array(stored[BLOOM_STORAGE_KEY]);
        _bloomLoaded = true;
        console.debug(`[Cleanway] Bloom filter loaded from cache (${_bloomBits.length} bytes, ${meta.domains} domains)`);
        return;
      }
    }

    // Download fresh from CDN
    await updateBloomFilter();
  } catch (e) {
    console.debug("[Cleanway] Bloom filter load failed:", e.message);

    // Fallback: build from local top domains list
    await buildLocalBloomFilter();
  }
}

/**
 * Download fresh bloom filter from CDN
 */
async function updateBloomFilter() {
  try {
    const resp = await fetch(BLOOM_CDN_URL);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

    const data = await resp.json();
    _bloomBits = new Uint8Array(data.bits);
    _bloomLoaded = true;

    // Cache locally
    await chrome.storage.local.set({
      [BLOOM_STORAGE_KEY]: Array.from(_bloomBits),
      [BLOOM_META_KEY]: {
        timestamp: Date.now(),
        domains: data.domain_count || 0,
        version: data.version || "unknown",
      },
    });

    console.debug(`[Cleanway] Bloom filter updated from CDN (${data.domain_count} domains)`);
  } catch (e) {
    console.debug("[Cleanway] CDN bloom filter unavailable:", e.message);
    await buildLocalBloomFilter();
  }
}

/**
 * Build bloom filter from a hardcoded list of top domains
 * Used as fallback when CDN is unavailable
 */
async function buildLocalBloomFilter() {
  // Minimal built-in list — enough for common browsing
  const topDomains = [
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
    "twitter.com", "instagram.com", "linkedin.com", "reddit.com", "apple.com",
    "microsoft.com", "github.com", "netflix.com", "whatsapp.com", "tiktok.com",
    "yahoo.com", "bing.com", "zoom.us", "paypal.com", "stripe.com",
    "shopify.com", "wordpress.com", "medium.com", "notion.so", "slack.com",
    "discord.com", "telegram.org", "spotify.com", "twitch.tv", "stackoverflow.com",
    "cloudflare.com", "dropbox.com", "adobe.com", "salesforce.com", "ebay.com",
    "walmart.com", "chase.com", "bankofamerica.com", "cnn.com", "bbc.com",
    "nytimes.com", "washingtonpost.com", "theguardian.com", "reuters.com",
    "forbes.com", "bloomberg.com", "x.com", "pinterest.com", "tumblr.com",
  ];

  _bloomBits = bloomBuild(topDomains);
  _bloomLoaded = true;

  console.debug(`[Cleanway] Bloom filter built locally (${topDomains.length} domains)`);
}

/**
 * Schedule periodic bloom filter updates
 */
export function scheduleBloomUpdate() {
  // Update every 24 hours
  chrome.alarms.create("bloom_update", {
    periodInMinutes: 24 * 60,
  });
}
