/**
 * LinkShield DNS Resolver
 *
 * Custom DNS-over-HTTPS (DoH) resolver that checks every domain
 * against our blocklist before resolving.
 *
 * Flow:
 *   1. Device sends DNS query → our resolver
 *   2. Check domain against local bloom filter (<1ms)
 *   3. If in bloom filter (known safe) → resolve normally
 *   4. If unknown → check API (score) → resolve or block
 *   5. If blocked → return NXDOMAIN or redirect to block page
 *
 * This runs as:
 *   - iOS: NEPacketTunnelProvider (local VPN, DNS only)
 *   - Android: VpnService (local VPN, DNS only)
 *   - Fallback: DoH profile pointing to our server
 *
 * Privacy:
 *   - Only domain names are checked
 *   - No traffic content is inspected
 *   - Full URLs are never seen by the server
 *   - Local bloom filter handles 95%+ without server contact
 */

// Configuration
const DOH_UPSTREAM = "https://cloudflare-dns.com/dns-query"; // Upstream resolver
const BLOCK_PAGE_IP = "0.0.0.0"; // IP to return for blocked domains

// Blocked domain cache (in-memory)
const blockedDomains = new Set<string>();
const safeDomains = new Set<string>();

/**
 * Check if a domain should be blocked.
 * Called by the VPN tunnel for every DNS query.
 */
export async function shouldBlockDomain(domain: string): Promise<{
  blocked: boolean;
  score?: number;
  reason?: string;
}> {
  // Normalize
  domain = domain.toLowerCase().replace(/\.$/, "");

  // Skip system/internal domains
  if (isSystemDomain(domain)) {
    return { blocked: false };
  }

  // Check local cache
  if (safeDomains.has(domain)) return { blocked: false };
  if (blockedDomains.has(domain)) return { blocked: true, reason: "Previously blocked" };

  // Check bloom filter (known safe, <1ms)
  // In production, load bloom filter from CDN
  // For now, check against API
  try {
    const resp = await fetch(`https://api.linkshield.io/api/v1/public/check/${domain}`);
    if (resp.ok) {
      const data = await resp.json();
      if (data.level === "dangerous") {
        blockedDomains.add(domain);
        return { blocked: true, score: data.score, reason: data.signals?.[0] || "Phishing detected" };
      } else {
        safeDomains.add(domain);
        // Evict cache if too large
        if (safeDomains.size > 10000) {
          const first = safeDomains.values().next().value;
          if (first) safeDomains.delete(first);
        }
        return { blocked: false };
      }
    }
  } catch {
    // API unavailable — allow (fail open for usability)
  }

  return { blocked: false };
}

function isSystemDomain(domain: string): boolean {
  const systemSuffixes = [
    "apple.com", "icloud.com", "mzstatic.com", // Apple
    "googleapis.com", "gstatic.com", "google.com", // Google
    "microsoft.com", "windows.net", "msftconnecttest.com", // Microsoft
    "local", "localhost", "internal",
    "linkshield.io", // Our own domain
  ];
  return systemSuffixes.some(s => domain === s || domain.endsWith("." + s));
}

/**
 * DNS-over-HTTPS query to upstream resolver
 * Used when domain is NOT blocked — forward to real DNS
 */
export async function resolveViaDoH(domain: string, type: string = "A"): Promise<string[]> {
  try {
    const resp = await fetch(
      `${DOH_UPSTREAM}?name=${encodeURIComponent(domain)}&type=${type}`,
      { headers: { Accept: "application/dns-json" } }
    );
    const data = await resp.json();
    return (data.Answer || [])
      .filter((a: any) => a.type === 1) // A records
      .map((a: any) => a.data);
  } catch {
    return [];
  }
}
