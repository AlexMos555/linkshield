/**
 * Family Hub end-to-end crypto helpers.
 *
 * The server is BLIND to alert content. This file is the client side
 * of that contract: every alert is encrypted with curve25519 +
 * XSalsa20-Poly1305 (TweetNaCl's `nacl.box`) BEFORE it touches the
 * /family/{id}/alerts endpoint. Recipients decrypt locally.
 *
 * Wire-format compatibility:
 *   - 32-byte curve25519 public + secret keys
 *   - 24-byte nonce per envelope
 *   - matches what api/routers/family.py expects (see backend test
 *     test_submit_alerts_rejects_wrong_nonce_length).
 *
 * Storage:
 *   - The user's secret key NEVER leaves the device. Stored at
 *     chrome.storage.local["family_secret_key_b64"].
 *   - The matching public key is uploaded once via
 *     POST /api/v1/family/{id}/keys and shared with siblings.
 *
 * Loading: this module imports the vendored TweetNaCl itself (the file
 * sets self.nacl), so it works the same in the background service
 * worker and in extension pages, whatever else they load first. Base64
 * and UTF-8 use the platform's btoa/atob/TextEncoder/TextDecoder rather
 * than tweetnacl-util: that vendor file uses `this` as its global, which
 * is undefined inside an ES module, so the module service worker could
 * not load it at all.
 */

import "./vendor/tweetnacl.min.js";

const STORAGE_KEY_SECRET = "family_secret_key_b64";
const STORAGE_KEY_PUBLIC = "family_public_key_b64";

// ─── Vendor accessor ───────────────────────────────────────────────

function getNacl() {
  const n = typeof globalThis !== "undefined" ? globalThis.nacl : undefined;
  if (!n || !n.box) {
    throw new Error("tweetnacl not loaded — src/utils/vendor/tweetnacl.min.js did not evaluate");
  }
  return n;
}

// ─── Byte codecs ───────────────────────────────────────────────────

function utf8Encode(text) {
  return new TextEncoder().encode(text);
}

function utf8Decode(bytes) {
  // fatal: a box that opens to invalid UTF-8 is treated as unreadable.
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64ToBytes(b64) {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

// ─── base64url helpers (URL-safe, padding-free) ────────────────────
// The backend uses base64url for ciphertext / nonce / pubkey transport.

function toB64Url(uint8) {
  return bytesToBase64(uint8).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64Url(s) {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(s.length + ((4 - (s.length % 4)) % 4), "=");
  return base64ToBytes(padded);
}

// ─── Keypair lifecycle ─────────────────────────────────────────────

/**
 * Generate a fresh keypair if one doesn't already exist locally,
 * persist the secret in chrome.storage.local, and return both halves.
 *
 * Idempotent: subsequent calls return the same keypair.
 *
 * @returns {Promise<{ publicKeyB64: string, secretKeyB64: string }>}
 */
export async function getOrCreateKeypair() {
  const nacl = getNacl();
  const stored = await chrome.storage.local.get([STORAGE_KEY_SECRET, STORAGE_KEY_PUBLIC]);
  if (stored[STORAGE_KEY_SECRET] && stored[STORAGE_KEY_PUBLIC]) {
    return {
      publicKeyB64: stored[STORAGE_KEY_PUBLIC],
      secretKeyB64: stored[STORAGE_KEY_SECRET],
    };
  }

  const kp = nacl.box.keyPair();
  const pub = toB64Url(kp.publicKey);
  const sec = toB64Url(kp.secretKey);
  await chrome.storage.local.set({
    [STORAGE_KEY_PUBLIC]: pub,
    [STORAGE_KEY_SECRET]: sec,
  });
  return { publicKeyB64: pub, secretKeyB64: sec };
}

/**
 * Wipe the local keypair. Use this when the user signs out or
 * explicitly leaves a family. Their public key on the server stays
 * (other members may still want to read old ciphertexts addressed
 * to the dropped user; that's the family admin's call to clean up).
 */
export async function clearKeypair() {
  await chrome.storage.local.remove([STORAGE_KEY_SECRET, STORAGE_KEY_PUBLIC]);
}

// ─── Box encrypt / decrypt ─────────────────────────────────────────

/**
 * Encrypt a plaintext alert for a specific recipient.
 *
 * @param {object} alert      Arbitrary JSON-serialisable payload.
 *                            Conventionally { domain, blocked_at,
 *                            score, level, sender_label }.
 * @param {string} recipientPubKeyB64
 * @param {string} mySecretKeyB64
 * @returns {{ ciphertext_b64: string, nonce_b64: string,
 *            sender_pubkey_b64: string }} Wire envelope ready to POST.
 */
export function encryptForRecipient(alert, recipientPubKeyB64, mySecretKeyB64) {
  const nacl = getNacl();

  const payload = utf8Encode(JSON.stringify(alert));
  const nonce = nacl.randomBytes(nacl.box.nonceLength); // 24 bytes
  const recipientKey = fromB64Url(recipientPubKeyB64);
  const myKey = fromB64Url(mySecretKeyB64);

  if (recipientKey.length !== nacl.box.publicKeyLength) {
    throw new Error(`Bad recipient pubkey length: ${recipientKey.length}, expected ${nacl.box.publicKeyLength}`);
  }
  if (myKey.length !== nacl.box.secretKeyLength) {
    throw new Error(`Bad sender secret length: ${myKey.length}, expected ${nacl.box.secretKeyLength}`);
  }

  const ct = nacl.box(payload, nonce, recipientKey, myKey);
  // The server stores the sender's PUBLIC key alongside the ct so the
  // recipient can decrypt with their own secret. We derive it from the
  // sender's secret rather than trusting a separate input.
  const senderPub = nacl.box.keyPair.fromSecretKey(myKey).publicKey;

  return {
    ciphertext_b64: toB64Url(ct),
    nonce_b64: toB64Url(nonce),
    sender_pubkey_b64: toB64Url(senderPub),
  };
}

/**
 * Decrypt an envelope addressed to me.
 *
 * @param {{ ciphertext_b64: string, nonce_b64: string,
 *           sender_pubkey_b64: string }} envelope
 * @param {string} mySecretKeyB64
 * @returns {object|null} The decoded payload, or null if the box
 *                        couldn't be opened (tampered ciphertext,
 *                        wrong sender key, JSON parse error).
 */
export function decryptForMe(envelope, mySecretKeyB64) {
  const nacl = getNacl();

  let ct, nonce, senderPub, mySec;
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
    return JSON.parse(utf8Decode(opened));
  } catch {
    return null;
  }
}

// ─── Convenience: encrypt the same alert for a list of recipients ──
// One source alert → N envelopes (one per recipient with their pubkey).
// The server stores them as N rows; each recipient decrypts only their own.

/**
 * @param {object} alert
 * @param {Array<{ user_id: string, public_key_b64: string }>} recipients
 * @param {string} mySecretKeyB64
 * @returns {Array<object>} envelopes ready to POST as
 *          { envelopes: [...] } to /family/{id}/alerts.
 */
export function encryptForFamily(alert, recipients, mySecretKeyB64) {
  return recipients
    .filter((r) => r && r.public_key_b64)
    .map((r) => ({
      recipient_user_id: r.user_id,
      ...encryptForRecipient(alert, r.public_key_b64, mySecretKeyB64),
      alert_type: alert.alert_type || "block",
    }));
}
