// Roundtrip smoke test for family-crypto.js logic.
// We test the box round-trip directly via tweetnacl since family-crypto.js
// uses globalThis.nacl + chrome.storage which aren't present in plain Node.

const nacl = require("tweetnacl");
const naclUtil = require("tweetnacl-util");

function toB64Url(u8) {
  return naclUtil.encodeBase64(u8).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromB64Url(s) {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(s.length + ((4 - (s.length % 4)) % 4), "=");
  return naclUtil.decodeBase64(padded);
}

// Mom and Grandma each generate a keypair on their own device.
const mom = nacl.box.keyPair();
const grandma = nacl.box.keyPair();

// Mom encrypts an alert FOR Grandma.
const alert = {
  domain: "paypal-verify.com",
  blocked_at: new Date().toISOString(),
  level: "dangerous",
  alert_type: "block",
};
const payload = naclUtil.decodeUTF8(JSON.stringify(alert));
const nonce = nacl.randomBytes(nacl.box.nonceLength);
const ct = nacl.box(payload, nonce, grandma.publicKey, mom.secretKey);

// Wire envelope (what we'd POST to /family/{id}/alerts):
const envelope = {
  recipient_user_id: "user-grandma",
  ciphertext_b64: toB64Url(ct),
  nonce_b64: toB64Url(nonce),
  sender_pubkey_b64: toB64Url(mom.publicKey),
};

// Server stores raw bytes; later Grandma's device pulls envelope back.
// Decode + nacl.box.open:
const ctBack = fromB64Url(envelope.ciphertext_b64);
const nonceBack = fromB64Url(envelope.nonce_b64);
const senderPubBack = fromB64Url(envelope.sender_pubkey_b64);

const opened = nacl.box.open(ctBack, nonceBack, senderPubBack, grandma.secretKey);
if (!opened) {
  console.error("FAIL: Grandma couldn't open the box");
  process.exit(1);
}
const recovered = JSON.parse(naclUtil.encodeUTF8(opened));

console.log("Mom pubkey:    ", toB64Url(mom.publicKey).slice(0, 16) + "…");
console.log("Grandma pubkey:", toB64Url(grandma.publicKey).slice(0, 16) + "…");
console.log("Nonce length:  ", nonce.length, "(expected 24)");
console.log("Ciphertext B64:", envelope.ciphertext_b64.slice(0, 32) + "…");
console.log("Recovered:     ", JSON.stringify(recovered));

// Tamper test: swap one byte of ct → open should return null.
const tamperedCt = new Uint8Array(ctBack);
tamperedCt[0] ^= 0xff;
const tamperedOpen = nacl.box.open(tamperedCt, nonceBack, senderPubBack, grandma.secretKey);
if (tamperedOpen) {
  console.error("FAIL: tampered ciphertext opened");
  process.exit(1);
}

// Wrong recipient test: Mom can't open her own message addressed to Grandma.
const wrongRecip = nacl.box.open(ctBack, nonceBack, senderPubBack, mom.secretKey);
if (wrongRecip) {
  console.error("FAIL: Mom decrypted message addressed to Grandma");
  process.exit(1);
}

// Length sanity (matches backend api/routers/family.py validation):
if (mom.publicKey.length !== 32) { console.error("FAIL: pubkey length"); process.exit(1); }
if (nonce.length !== 24)         { console.error("FAIL: nonce length"); process.exit(1); }

// Quick parity check — the JSON we recovered matches input.
if (recovered.domain !== alert.domain || recovered.level !== alert.level) {
  console.error("FAIL: payload mismatch");
  process.exit(1);
}

console.log("\nAll roundtrip + tamper + wrong-recipient + length checks passed.");
