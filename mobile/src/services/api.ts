/**
 * LinkShield Mobile API Client
 * Privacy: only domain names sent. Full URLs stay on device.
 */

const API_BASE = "https://api.linkshield.io"; // Change for dev: http://localhost:8000

export interface DomainResult {
  domain: string;
  score: number;
  level: "safe" | "caution" | "dangerous";
  confidence: "high" | "medium" | "low";
  reasons: { signal: string; detail: string; weight: number }[];
  domain_age_days?: number;
  has_ssl?: boolean;
  ssl_issuer?: string;
  cached?: boolean;
}

export interface CheckResponse {
  results: DomainResult[];
  checked_at: string;
  api_calls_remaining?: number;
}

let _token: string | null = null;

export function setAuthToken(token: string | null) {
  _token = token;
}

export async function checkDomains(domains: string[]): Promise<CheckResponse> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (_token) headers["Authorization"] = `Bearer ${_token}`;

  const resp = await fetch(`${API_BASE}/api/v1/check`, {
    method: "POST",
    headers,
    body: JSON.stringify({ domains }),
  });

  if (resp.status === 429) {
    throw new Error("Rate limit exceeded. Upgrade for unlimited checks.");
  }
  if (!resp.ok) {
    throw new Error(`API error: ${resp.status}`);
  }

  return resp.json();
}

export async function checkSingleDomain(domain: string): Promise<DomainResult> {
  const resp = await checkDomains([domain]);
  if (resp.results.length === 0) throw new Error("No results");
  return resp.results[0];
}

export async function publicCheck(domain: string) {
  const resp = await fetch(`${API_BASE}/api/v1/public/check/${encodeURIComponent(domain)}`);
  if (!resp.ok) throw new Error(`API error: ${resp.status}`);
  return resp.json();
}

export async function submitAggregate(data: {
  total_checks: number;
  total_blocks: number;
  total_warnings: number;
  score?: number;
}) {
  if (!_token) return;
  await fetch(`${API_BASE}/api/v1/user/aggregates`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${_token}` },
    body: JSON.stringify(data),
  });
}

export async function getPercentile() {
  if (!_token) return null;
  const resp = await fetch(`${API_BASE}/api/v1/user/percentile`, {
    headers: { Authorization: `Bearer ${_token}` },
  });
  if (!resp.ok) return null;
  return resp.json();
}

export async function checkBreach(hashPrefix: string) {
  const resp = await fetch(`${API_BASE}/api/v1/breach/check/${hashPrefix}`);
  if (!resp.ok) throw new Error("Breach check failed");
  return resp.json();
}
