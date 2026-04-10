/**
 * LinkShield API Client
 *
 * Handles communication with the LinkShield backend.
 * Privacy: only domain names are sent — never full URLs or page content.
 */

const API_BASE = "http://localhost:8000"; // TODO: change to https://api.linkshield.io in production

/**
 * Check domains against LinkShield API
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
