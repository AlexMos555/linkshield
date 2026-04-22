/**
 * Cleanway API Client
 *
 * Handles communication with the Cleanway backend.
 * Privacy: only domain names are sent — never full URLs or page content.
 */

// API base resolution: chrome.storage.local.api_url (dev override) → production Railway URL
// To use local dev: Options page → set API URL to http://localhost:8000 → Save
let API_BASE = "https://api.cleanway.ai";
try {
  chrome.storage.local.get("api_url").then(function(data) {
    if (data && typeof data.api_url === "string" && data.api_url.startsWith("http")) {
      API_BASE = data.api_url.replace(/\/$/, "");
    }
  }).catch(function() {});
  chrome.storage.onChanged.addListener(function(changes, area) {
    if (area === "local" && changes && changes.api_url && typeof changes.api_url.newValue === "string") {
      API_BASE = changes.api_url.newValue.replace(/\/$/, "");
    }
  });
} catch (e) { /* storage not available (tests, edge cases) */ }

/**
 * Check domains against Cleanway API
 * @param {string[]} domains - List of domain names to check
 * @param {string} [token] - Optional JWT auth token
 * @returns {Promise<{results: Array, checked_at: string, api_calls_remaining: number}>}
 */
export async function checkDomains(domains, token = null) {
  const headers = { "Content-Type": "application/json" };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  try {
    const resp = await fetch(`${API_BASE}/api/v1/check`, {
      method: "POST",
      headers,
      body: JSON.stringify({ domains }),
    });

    if (resp.status === 429) {
      const data = await resp.json();
      return { error: "rate_limit", detail: data.detail };
    }

    if (!resp.ok) {
      return { error: "api_error", status: resp.status };
    }

    return await resp.json();
  } catch (e) {
    return { error: "network_error", message: e.message };
  }
}

/**
 * Extract unique domains from a list of URLs
 * @param {string[]} urls
 * @returns {string[]}
 */
export function extractDomains(urls) {
  const domains = new Set();
  for (const url of urls) {
    try {
      const parsed = new URL(url.startsWith("http") ? url : `https://${url}`);
      if (parsed.hostname && parsed.hostname !== "localhost") {
        domains.add(parsed.hostname.toLowerCase());
      }
    } catch {
      // Skip invalid URLs
    }
  }
  return [...domains];
}
