/**
 * Family Hub end-to-end crypto for mobile (RN).
 *
 * Same wire format as packages/extension-core/src/utils/family-crypto.js:
 *   curve25519 keypair · 24-byte nonce · base64url envelopes
 *
 * Differences from the extension:
 *   - Uses ESM imports (TypeScript) instead of globalThis.nacl
 *   - Secret key persisted in expo-secure-store (Keychain / Keystore)
 *     so a device wipe / app uninstall removes it; AsyncStorage isn't
 *     hardware-backed and we treat the secret as MUST-not-leak
 *   - Public key cached in expo-secure-store too for API parity, even
 *     though it's not secret — keeps the read path simple
 *   - Imports react-native-get-random-values polyfill so nacl.randomBytes
 *     works in Hermes / RN's JS engine (which lacks crypto.getRandomValues
 *     in older versions)
 */

// MUST be imported before tweetnacl so nacl.randomBytes uses real entropy
import "react-native-get-random-values";

import nacl from "tweetnacl";
import naclUtil from "tweetnacl-util";
import * as SecureStore from "expo-secure-store";

const SECRET_KEY = "family_secret_key_b64";
const PUBLIC_KEY = "family_public_key_b64";

// ─── base64url helpers ─────────────────────────────────────────────

function toB64Url(u8: Uint8Array): string {
  return naclUtil.encodeBase64(u8).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64Url(s: string): Uint8Array {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(s.length + ((4 - (s.length % 4)) % 4), "=");
  return naclUtil.decodeBase64(padded);
}

// ─── Keypair lifecycle ─────────────────────────────────────────────

export interface KeypairB64 {
  publicKeyB64: string;
  secretKeyB64: string;
}

/**
 * Get-or-create the family keypair on this device. Idempotent:
 * subsequent calls return the cached pair from SecureStore.
 *
 * Returns nulls when SecureStore is unavailable (very rare — should
 * only happen in unsigned dev builds without a passcode set).
 */
export async function getOrCreateKeypair(): Promise<KeypairB64 | null> {
  try {
    const existingPub = await SecureStore.getItemAsync(PUBLIC_KEY);
    const existingSec = await SecureStore.getItemAsync(SECRET_KEY);
    if (existingPub && existingSec) {
      return { publicKeyB64: existingPub, secretKeyB64: existingSec };
    }
  } catch {
    // Read failure → continue to fresh generation; write below will
    // also fail in this case, returning null.
  }

  const kp = nacl.box.keyPair();
  const pub = toB64Url(kp.publicKey);
  const sec = toB64Url(kp.secretKey);

  try {
    await SecureStore.setItemAsync(PUBLIC_KEY, pub);
    await SecureStore.setItemAsync(SECRET_KEY, sec);
  } catch {
    return null;
  }
  return { publicKeyB64: pub, secretKeyB64: sec };
}

export async function clearKeypair(): Promise<void> {
  try {
    await SecureStore.deleteItemAsync(PUBLIC_KEY);
    await SecureStore.deleteItemAsync(SECRET_KEY);
  } catch {
    // Silent — there's nothing to do if we can't clear
  }
}

// ─── Box encrypt / decrypt ─────────────────────────────────────────

export interface AlertPayload {
  domain: string;
  blocked_at?: string;
  level?: "safe" | "caution" | "dangerous";
  alert_type?: string;
  // Free-form additional fields the sender wants to share. Kept open
  // so the schema can evolve without breaking decryption.
  [extra: string]: unknown;
}

export interface Envelope {
  recipient_user_id?: string;
  ciphertext_b64: string;
  nonce_b64: string;
  sender_pubkey_b64: string;
  alert_type?: string;
}

/**
 * Encrypt an alert for one specific recipient.
 */
export function encryptForRecipient(
  alert: AlertPayload,
  recipientPubKeyB64: string,
  mySecretKeyB64: string,
): Omit<Envelope, "recipient_user_id"> {
  const payload = naclUtil.decodeUTF8(JSON.stringify(alert));
  const nonce = nacl.randomBytes(nacl.box.nonceLength); // 24 bytes
  const recipientKey = fromB64Url(recipientPubKeyB64);
  const myKey = fromB64Url(mySecretKeyB64);

  if (recipientKey.length !== nacl.box.publicKeyLength) {
    throw new Error(`Bad recipient pubkey length: ${recipientKey.length}`);
  }
  if (myKey.length !== nacl.box.secretKeyLength) {
    throw new Error(`Bad sender secret length: ${myKey.length}`);
  }

  const ct = nacl.box(payload, nonce, recipientKey, myKey);
  const senderPub = nacl.box.keyPair.fromSecretKey(myKey).publicKey;

  return {
    ciphertext_b64: toB64Url(ct),
    nonce_b64: toB64Url(nonce),
    sender_pubkey_b64: toB64Url(senderPub),
    alert_type: alert.alert_type ?? "block",
  };
}

/**
 * Decrypt a server-stored envelope. Returns null on any failure
 * (tampered ct, wrong key, JSON parse error) so callers don't have
 * to distinguish — the right behavior is always "skip this alert".
 */
export function decryptForMe(
  envelope: Pick<Envelope, "ciphertext_b64" | "nonce_b64" | "sender_pubkey_b64">,
  mySecretKeyB64: string,
): AlertPayload | null {
  let ct: Uint8Array, nonce: Uint8Array, senderPub: Uint8Array, mySec: Uint8Array;
  try {
    ct = fromB64Url(envelope.ciphertext_b64);
    nonce = fromB64Url(envelope.nonce_b64);
    senderPub = fromB64Url(envelope.sender_pubkey_b64);
    mySec = fromB64Url(mySecretKeyB64);
  } catch {
    return null;
  }

  const opened = nacl.box.open(ct, nonce, senderPub, mySec);
  if (!opened) return null;

  try {
    return JSON.parse(naclUtil.encodeUTF8(opened)) as AlertPayload;
  } catch {
    return null;
  }
}

/**
 * Fan-out helper: one alert → N envelopes addressed to N recipients.
 * Recipients without a published public key are silently dropped.
 */
export interface FamilyMember {
  user_id: string;
  public_key_b64?: string | null;
}

export function encryptForFamily(
  alert: AlertPayload,
  recipients: FamilyMember[],
  mySecretKeyB64: string,
): Envelope[] {
  return recipients
    .filter((r) => r && r.public_key_b64)
    .map((r) => ({
      recipient_user_id: r.user_id,
      ...encryptForRecipient(alert, r.public_key_b64 as string, mySecretKeyB64),
    }));
}
