/**
 * Family Hub REST client (mobile).
 *
 * Mirror of packages/extension-core/src/utils/family-api.js but typed.
 * Talks to /api/v1/family/* on api.cleanway.ai. Handles everything
 * EXCEPT crypto — pair with mobile/src/lib/family-crypto.ts on the
 * client side and api/routers/family.py on the server.
 *
 * All functions accept an explicit `token` (Supabase access token);
 * they return null on any non-2xx so screens can show a polite
 * "couldn't load" state instead of crashing.
 */
import Constants from "expo-constants";

import type { Envelope } from "./family-crypto";

const API_BASE: string =
  process.env.EXPO_PUBLIC_API_URL ||
  (Constants.expoConfig?.extra?.apiUrl as string | undefined) ||
  "https://api.cleanway.ai";

interface FetchOpts {
  method?: "GET" | "POST" | "PATCH";
  token: string;
  body?: unknown;
}

async function _fetch<T>(path: string, opts: FetchOpts): Promise<T | null> {
  if (!opts.token) return null;
  const headers: Record<string, string> = {
    Authorization: `Bearer ${opts.token}`,
  };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";

  try {
    const resp = await fetch(`${API_BASE}${path}`, {
      method: opts.method ?? "GET",
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
    if (!resp.ok) return null;
    const text = await resp.text();
    return text ? (JSON.parse(text) as T) : ({} as T);
  } catch {
    return null;
  }
}

// ─── Response shapes (mirror api/routers/family.py Pydantic models) ──

export interface MyFamily {
  family_id: string;
  name: string;
  role: "owner" | "member";
  member_count: number;
}
export interface MyFamiliesResponse {
  families: MyFamily[];
}

export interface CreateFamilyResponse {
  family_id: string;
  name: string;
}

export interface RegisterKeyResponse {
  family_id: string;
  user_id: string;
  key_version: number;
}

export interface FamilyMemberRow {
  user_id: string;
  role: string;
  joined_at: string | null;
  public_key_b64: string | null;
  key_version: number | null;
}
export interface FamilyMembersResponse {
  family_id: string;
  members: FamilyMemberRow[];
}

export interface InviteCreateResponse {
  invite_id: string;
  code: string;
  pin: string;
  expires_at: string;
}

export interface AcceptInviteResponse {
  family_id: string;
  role: "member";
}

export interface SubmitAlertsResponse {
  accepted: number;
}

export interface StoredAlert {
  id: string;
  sender_user_id: string | null;
  sender_pubkey_b64: string | null;
  nonce_b64: string | null;
  ciphertext_b64: string | null;
  alert_type: string | null;
  created_at: string | null;
}
export interface ListAlertsResponse {
  family_id: string;
  alerts: StoredAlert[];
}

// ─── Public API ────────────────────────────────────────────────────

export function listMyFamilies(token: string): Promise<MyFamiliesResponse | null> {
  return _fetch<MyFamiliesResponse>("/api/v1/family/mine", { token });
}

export function createFamily(token: string, name = "My Family"): Promise<CreateFamilyResponse | null> {
  return _fetch<CreateFamilyResponse>("/api/v1/family", { method: "POST", token, body: { name } });
}

export function registerMyKey(
  token: string,
  familyId: string,
  publicKeyB64: string,
  keyVersion = 1,
): Promise<RegisterKeyResponse | null> {
  return _fetch<RegisterKeyResponse>(
    `/api/v1/family/${encodeURIComponent(familyId)}/keys`,
    { method: "POST", token, body: { public_key_b64: publicKeyB64, key_version: keyVersion } },
  );
}

export function listMembers(
  token: string,
  familyId: string,
): Promise<FamilyMembersResponse | null> {
  return _fetch<FamilyMembersResponse>(`/api/v1/family/${encodeURIComponent(familyId)}/members`, { token });
}

export function createInvite(
  token: string,
  familyId: string,
): Promise<InviteCreateResponse | null> {
  return _fetch<InviteCreateResponse>(`/api/v1/family/${encodeURIComponent(familyId)}/invite`, {
    method: "POST",
    token,
  });
}

export function acceptInvite(
  token: string,
  code: string,
  pin: string,
): Promise<AcceptInviteResponse | null> {
  return _fetch<AcceptInviteResponse>("/api/v1/family/accept", {
    method: "POST",
    token,
    body: { code, pin },
  });
}

export function submitAlerts(
  token: string,
  familyId: string,
  envelopes: Envelope[],
): Promise<SubmitAlertsResponse | null> {
  return _fetch<SubmitAlertsResponse>(
    `/api/v1/family/${encodeURIComponent(familyId)}/alerts`,
    { method: "POST", token, body: { envelopes } },
  );
}

export function listAlerts(
  token: string,
  familyId: string,
): Promise<ListAlertsResponse | null> {
  return _fetch<ListAlertsResponse>(`/api/v1/family/${encodeURIComponent(familyId)}/alerts`, { token });
}
