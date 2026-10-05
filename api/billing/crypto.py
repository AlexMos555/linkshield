"""Phone numbers and secrets: normalisation, encryption at rest, keyed hashes.

The phone number is the most sensitive datum in the whole system (§4.7 of
the plan). It is stored only as AES-256-GCM ciphertext plus an HMAC for
lookups; it is never logged, never sent to the main API or to Sentry.

Only standard primitives from `cryptography` are used here — this module
frames them (versioned blobs, domain-separated HMACs), it does not invent.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets

# ── Phone numbers ──

# Russian numbers only, E.164: "+7" followed by 10 digits. Everything else is
# rejected at the boundary (plan A.6).
_RU_E164 = re.compile(r"^\+7\d{10}$")
_STRIP = re.compile(r"[\s\-().]")


class InvalidMsisdn(ValueError):
    """The value is not a Russian mobile number we can bill."""


def normalize_msisdn(raw: str) -> str:
    """'8 (916) 123-45-67', '79161234567', '+7 916 1234567' → '+79161234567'.

    Raises InvalidMsisdn for anything that is not a Russian number.
    """
    if not isinstance(raw, str):
        raise InvalidMsisdn("phone number must be a string")
    cleaned = _STRIP.sub("", raw.strip())
    if cleaned.startswith("+"):
        digits = cleaned[1:]
    else:
        digits = cleaned
    if not digits.isdigit():
        raise InvalidMsisdn("phone number may contain digits only")
    if len(digits) == 11 and digits[0] in ("7", "8"):
        candidate = "+7" + digits[1:]
    elif len(digits) == 10 and digits[0] == "9":
        candidate = "+7" + digits
    else:
        raise InvalidMsisdn("expected a Russian number: +7 and 10 digits")
    if not _RU_E164.fullmatch(candidate):
        raise InvalidMsisdn("expected a Russian number: +7 and 10 digits")
    return candidate


def msisdn_digits(msisdn: str) -> str:
    """'+79161234567' → '79161234567' (the form aggregators want)."""
    return msisdn.lstrip("+")


def mask_msisdn(msisdn: str) -> str:
    """'+79161234567' → '+7 9•• •••-45-67' — what a screen may show."""
    digits = msisdn_digits(msisdn)
    if len(digits) != 11:
        return "+7 ••• •••-••-••"
    return f"+7 {digits[1]}•• •••-{digits[7:9]}-{digits[9:11]}"


# ── Keyed hashes (lookups without plaintext) ──

# Domain separation: the same key never produces comparable digests for two
# kinds of input (a phone hash can never be confused with a code hash).
_DOMAIN_MSISDN = b"cleanway-billing/msisdn/v1:"
_DOMAIN_CODE = b"cleanway-billing/claim-code/v1:"
_DOMAIN_FINGERPRINT = b"cleanway-billing/fingerprint/v1:"
_DOMAIN_IP = b"cleanway-billing/ip/v1:"


class KeyedHasher:
    """HMAC-SHA-256 with one server-side key and per-purpose prefixes."""

    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("HMAC key must be at least 32 bytes")
        self._key = key

    def _digest(self, domain: bytes, value: str) -> str:
        return hmac.new(self._key, domain + value.encode("utf-8"), hashlib.sha256).hexdigest()

    def msisdn(self, msisdn: str) -> str:
        return self._digest(_DOMAIN_MSISDN, msisdn)

    def claim_code(self, code: str) -> str:
        return self._digest(_DOMAIN_CODE, code)

    def fingerprint(self, fingerprint_input: str) -> str:
        return self._digest(_DOMAIN_FINGERPRINT, fingerprint_input)

    def ip(self, ip: str) -> str:
        # 64 bits, like api/services/audit_log.py — correlation, not identity.
        return self._digest(_DOMAIN_IP, ip)[:16]


# ── Encryption at rest ──

_BLOB_VERSION = b"\x01"
_NONCE_BYTES = 12
_AAD = b"cleanway-billing/msisdn/v1"


class MsisdnCipher:
    """AES-256-GCM for phone numbers. Blob = version(1) | nonce(12) | ct+tag."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("AES-256-GCM key must be exactly 32 bytes")
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        self._aead = AESGCM(key)

    def encrypt_bytes(self, data: bytes) -> bytes:
        """Any sensitive blob (a webhook body may carry a phone number)."""
        nonce = os.urandom(_NONCE_BYTES)
        return _BLOB_VERSION + nonce + self._aead.encrypt(nonce, data, _AAD)

    def decrypt_bytes(self, blob: bytes) -> bytes:
        if not blob or blob[:1] != _BLOB_VERSION or len(blob) < 1 + _NONCE_BYTES + 16:
            raise ValueError("unknown msisdn blob format")
        nonce = blob[1:1 + _NONCE_BYTES]
        return self._aead.decrypt(nonce, blob[1 + _NONCE_BYTES:], _AAD)

    def encrypt(self, msisdn: str) -> bytes:
        return self.encrypt_bytes(msisdn.encode("utf-8"))

    def decrypt(self, blob: bytes) -> str:
        return self.decrypt_bytes(blob).decode("utf-8")


# ── Secrets and codes ──

_DEVICE_SECRET_BYTES = 32
_CLAIM_CODE_DIGITS = 6


def generate_device_secret() -> str:
    """The bearer secret a device keeps in its Keystore; we keep its SHA-256."""
    return secrets.token_urlsafe(_DEVICE_SECRET_BYTES)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def generate_claim_code() -> str:
    """Six digits, uniformly random, zero-padded ('048213')."""
    return f"{secrets.randbelow(10 ** _CLAIM_CODE_DIGITS):0{_CLAIM_CODE_DIGITS}d}"


def is_claim_code(value: str) -> bool:
    return isinstance(value, str) and len(value) == _CLAIM_CODE_DIGITS and value.isdigit()


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
