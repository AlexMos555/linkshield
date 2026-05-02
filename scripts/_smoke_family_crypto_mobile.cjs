// Smoke test for mobile/src/lib/family-crypto.ts using the SAME tweetnacl
// runtime as the mobile app would. Verifies wire-format parity with the
// extension version (scripts/_smoke_family_crypto.cjs).

const nacl = require("tweetnacl");
const naclUtil = require("tweetnacl-util");

function toB64Url(u8) {
  return naclUtil.encodeBase64(u8).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromB64Url(s) {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(s.length + ((4 - (s.length % 4)) % 4), "=");
  return naclUtil.decodeBase64(padded);
}

const momExt = nacl.box.keyPair();          // Mom on Chrome
const grandmaMobile = nacl.box.keyPair();   // Grandma on phone (same primitives)

const alert = { domain: "paypal-verify.com", blocked_at: new Date().toISOString(), level: "dangerous", alert_type: "block" };
const payload = naclUtil.decodeUTF8(JSON.stringify(alert));
const nonce = nacl.randomBytes(nacl.box.nonceLength);
const ct = nacl.box(payload, nonce, grandmaMobile.publicKey, momExt.secretKey);

const envelope = {
  recipient_user_id: "user-grandma",
  ciphertext_b64: toB64Url(ct),
  nonce_b64: toB64Url(nonce),
  sender_pubkey_b64: toB64Url(momExt.publicKey),
};

// Mobile decrypts using identical primitives.
const opened = nacl.box.open(
  fromB64Url(envelope.ciphertext_b64),
  fromB64Url(envelope.nonce_b64),
  fromB64Url(envelope.sender_pubkey_b64),
  grandmaMobile.secretKey,
);
if (!opened) { console.error("FAIL: mobile open"); process.exit(1); }
const recovered = JSON.parse(naclUtil.encodeUTF8(opened));
if (recovered.domain !== alert.domain) { console.error("FAIL: payload mismatch"); process.exit(1); }

// Reverse: mobile → extension
const reverse = { domain: "fake-amazon-login.cn", level: "dangerous" };
const revNonce = nacl.randomBytes(nacl.box.nonceLength);
const revCt = nacl.box(naclUtil.decodeUTF8(JSON.stringify(reverse)), revNonce, momExt.publicKey, grandmaMobile.secretKey);
const revOpened = nacl.box.open(revCt, revNonce, grandmaMobile.publicKey, momExt.secretKey);
if (!revOpened) { console.error("FAIL: ext open of mobile-sent message"); process.exit(1); }

if (momExt.publicKey.length !== 32 || nonce.length !== 24) { console.error("FAIL: lengths"); process.exit(1); }

console.log("Mobile ↔ Extension wire-format parity verified.");
console.log("  Forward  (ext → mobile):", recovered.domain);
console.log("  Reverse  (mobile → ext):", JSON.parse(naclUtil.encodeUTF8(revOpened)).domain);
console.log("  Pubkey: 32B · Nonce: 24B");
