/**
 * The device pass (billing plan A.5), as the phone reads it.
 *
 * A compact JWS, `alg=EdDSA` (Ed25519), header `kid`, payload
 * `{v, dev, mode, src, plan, until, grace_until, lapse_policy, iat, exp}` —
 * no personal data. The billing role signs it; this file verifies it with the
 * public key(s) the build carries (several during a rotation) and applies the
 * one rule the phone follows when it cannot reach the server.
 *
 * `offlineMode` is a 1:1 port of `api/billing/entitlement.offline_mode`, and
 * scripts/test-entitlement.mjs pins it with the same cases as the server's
 * tests/billing/test_entitlement.py:
 *  - the device clock is clamped to `≥ iat` — a clock turned back extends nothing;
 *  - before `until` the issued mode; inside the grace window still the issued
 *    mode; after both, `lapse_policy`;
 *  - `until = null` means the mode holds until a newer pass (legacy free, lapsed);
 *  - `exp` is the signature's validity for the SERVER; the phone keeps using an
 *    expired pass offline because that is all it has (so `verifyPass` is what
 *    the app runs when a pass ARRIVES, and `offlineMode` what it runs after).
 */
import nacl from "tweetnacl";
import naclUtil from "tweetnacl-util";

export type ProtectionMode = "full" | "basic" | "off";
export type EntitlementSource = "subscription" | "trial" | "legacy" | "promo" | "none";
export type LapsePolicy = "basic" | "off";

export const PASS_VERSION = 1;
const ALG = "EdDSA";
const PUBLIC_KEY_BYTES = 32;

const MODES: readonly ProtectionMode[] = ["full", "basic", "off"];
const SOURCES: readonly EntitlementSource[] = ["subscription", "trial", "legacy", "promo", "none"];
const POLICIES: readonly LapsePolicy[] = ["basic", "off"];

export interface PassClaims {
  v: number;
  dev: string;
  mode: ProtectionMode;
  src: EntitlementSource;
  plan: string | null;
  /** Unix seconds; null = open-ended. */
  until: number | null;
  grace_until: number | null;
  lapse_policy: LapsePolicy;
  iat: number;
  exp: number;
}

export type PassInvalidReason =
  | "malformed"
  | "unsupported_alg"
  | "unknown_kid"
  | "bad_signature"
  | "unsupported_version"
  | "expired";

/** The token is not a pass we accept. `reason` is one short machine word, the same set the server uses. */
export class PassInvalid extends Error {
  readonly reason: PassInvalidReason;
  constructor(reason: PassInvalidReason) {
    super(reason);
    this.name = "PassInvalid";
    this.reason = reason;
  }
}

/** The protection mode a lapse policy stands for. */
export function lapseMode(policy: LapsePolicy): ProtectionMode {
  return policy === "basic" ? "basic" : "off";
}

// ── Base64url (RFC 7515: no padding) ──

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64_INDEX: Record<string, number> = Object.fromEntries(Array.from(B64, (c, i) => [c, i]));

/** Decodes base64url (and plain base64) without padding; throws PassInvalid("malformed") on anything else. */
export function base64UrlDecode(text: string): Uint8Array {
  const clean = text.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  if (clean.length % 4 === 1 || !/^[A-Za-z0-9_-]*$/.test(clean)) throw new PassInvalid("malformed");
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let n = 0;
  for (const ch of clean) {
    buffer = (buffer << 6) | B64_INDEX[ch];
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[n++] = (buffer >> bits) & 0xff;
    }
  }
  return out.subarray(0, n);
}

function jsonPart(part: string): Record<string, unknown> {
  let decoded: unknown;
  try {
    decoded = JSON.parse(naclUtil.encodeUTF8(base64UrlDecode(part)));
  } catch (e) {
    if (e instanceof PassInvalid) throw e;
    throw new PassInvalid("malformed");
  }
  if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) throw new PassInvalid("malformed");
  return decoded as Record<string, unknown>;
}

// ── Claims ──

function optInt(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n)) throw new PassInvalid("malformed");
  return Math.trunc(n);
}

function reqInt(value: unknown): number {
  const n = optInt(value);
  if (n === null) throw new PassInvalid("malformed");
  return n;
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[]): T {
  if (typeof value !== "string" || !(allowed as readonly string[]).includes(value)) throw new PassInvalid("malformed");
  return value as T;
}

/** The server's payload as typed claims; `PassInvalid("malformed")` for anything that is not one. */
export function claimsFromPayload(payload: unknown): PassClaims {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new PassInvalid("malformed");
  const p = payload as Record<string, unknown>;
  if (typeof p.dev !== "string" || p.dev.length === 0) throw new PassInvalid("malformed");
  const plan = p.plan === null || p.plan === undefined ? null : p.plan;
  if (plan !== null && typeof plan !== "string") throw new PassInvalid("malformed");
  return {
    v: reqInt(p.v),
    dev: p.dev,
    mode: oneOf(p.mode, MODES),
    src: oneOf(p.src, SOURCES),
    plan,
    until: optInt(p.until),
    grace_until: optInt(p.grace_until),
    lapse_policy: oneOf(p.lapse_policy, POLICIES),
    iat: reqInt(p.iat),
    exp: reqInt(p.exp),
  };
}

/** Header and claims of a token WITHOUT checking its signature — for reading a stored pass back. */
export function decodePass(token: string): { header: Record<string, unknown>; claims: PassClaims } {
  const parts = token.split(".");
  if (parts.length !== 3) throw new PassInvalid("malformed");
  return { header: jsonPart(parts[0]), claims: claimsFromPayload(jsonPart(parts[1])) };
}

/**
 * Signature, key id, version and `exp` — exactly the server's `Keyring.verify`.
 * `publicKeys` is `{kid: base64}`; every key still accepted during a rotation.
 */
export function verifyPass(token: string, publicKeys: Record<string, string>, nowSec: number): PassClaims {
  const parts = token.split(".");
  if (parts.length !== 3) throw new PassInvalid("malformed");
  const header = jsonPart(parts[0]);
  if (header.alg !== ALG) throw new PassInvalid("unsupported_alg");
  const kid = typeof header.kid === "string" ? header.kid : "";
  const keyB64 = Object.prototype.hasOwnProperty.call(publicKeys, kid) ? publicKeys[kid] : undefined;
  if (keyB64 === undefined) throw new PassInvalid("unknown_kid");
  const key = base64UrlDecode(keyB64);
  const signature = base64UrlDecode(parts[2]);
  const signingInput = naclUtil.decodeUTF8(`${parts[0]}.${parts[1]}`);
  let ok = false;
  try {
    ok = key.length === PUBLIC_KEY_BYTES && signature.length === nacl.sign.signatureLength
      && nacl.sign.detached.verify(signingInput, signature, key);
  } catch {
    ok = false;
  }
  if (!ok) throw new PassInvalid("bad_signature");
  const claims = claimsFromPayload(jsonPart(parts[1]));
  if (claims.v !== PASS_VERSION) throw new PassInvalid("unsupported_version");
  if (nowSec >= claims.exp) throw new PassInvalid("expired");
  return claims;
}

// ── The offline rule the phone follows ──

/** What the phone does with its last pass when the server is unreachable. */
export function offlineMode(claims: PassClaims, deviceNowSec: number): ProtectionMode {
  const now = Math.max(Math.trunc(deviceNowSec), claims.iat);
  if (claims.until === null || now < claims.until) return claims.mode;
  if (claims.grace_until !== null && now < claims.grace_until) return claims.mode;
  return lapseMode(claims.lapse_policy);
}

/**
 * When the offline rule's answer next changes (unix seconds), or null when
 * it never does. The native service re-reads the mode at this moment so the
 * notification and the list cadence follow without the app being opened.
 */
export function nextModeChange(claims: PassClaims, deviceNowSec: number): number | null {
  const now = Math.max(Math.trunc(deviceNowSec), claims.iat);
  if (claims.until === null) return null;
  if (now < claims.until) return claims.grace_until !== null && claims.grace_until > claims.until ? claims.grace_until : claims.until;
  if (claims.grace_until !== null && now < claims.grace_until) return claims.grace_until;
  return null;
}
