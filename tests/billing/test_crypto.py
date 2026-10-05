"""Phone-number normalisation, masking, keyed hashes and encryption at rest."""
from __future__ import annotations

import os

import pytest

from api.billing.crypto import (
    InvalidMsisdn,
    KeyedHasher,
    MsisdnCipher,
    constant_time_equal,
    generate_claim_code,
    generate_device_secret,
    is_claim_code,
    mask_msisdn,
    msisdn_digits,
    normalize_msisdn,
    sha256_hex,
)


@pytest.mark.parametrize("raw", [
    "+79161234567", "79161234567", "89161234567", "9161234567",
    "+7 916 123-45-67", "8 (916) 123 45 67", " +7-916-123-45-67 ", "+7.916.123.45.67",
])
def test_russian_numbers_normalise_to_e164(raw):
    assert normalize_msisdn(raw) == "+79161234567"


@pytest.mark.parametrize("raw", [
    "", "+1 415 555 0100", "+380501234567", "+7916123456", "+791612345678", "8916abc4567",
    "79161234567;DROP", "+7 (495) 123-45-67x", "0161234567", "+79161234567 +79161234567",
])
def test_everything_else_is_rejected(raw):
    with pytest.raises(InvalidMsisdn):
        normalize_msisdn(raw)


def test_non_string_is_rejected():
    with pytest.raises(InvalidMsisdn):
        normalize_msisdn(79161234567)  # type: ignore[arg-type]


def test_digits_and_mask():
    assert msisdn_digits("+79161234567") == "79161234567"
    assert mask_msisdn("+79161234567") == "+7 9•• •••-45-67"
    assert mask_msisdn("bad") == "+7 ••• •••-••-••"


def test_keyed_hasher_separates_domains_and_needs_a_real_key():
    with pytest.raises(ValueError):
        KeyedHasher(b"short")
    h = KeyedHasher(os.urandom(32))
    assert h.msisdn("+79161234567") != h.claim_code("+79161234567")
    assert h.msisdn("+79161234567") == h.msisdn("+79161234567")
    assert len(h.ip("10.0.0.1")) == 16
    other = KeyedHasher(os.urandom(32))
    assert other.msisdn("+79161234567") != h.msisdn("+79161234567")
    assert len(h.fingerprint("android-id")) == 64


def test_cipher_round_trip_and_tamper_detection():
    with pytest.raises(ValueError):
        MsisdnCipher(b"x" * 16)
    cipher = MsisdnCipher(os.urandom(32))
    blob = cipher.encrypt("+79161234567")
    assert blob[:1] == b"\x01" and b"9161234567" not in blob
    assert cipher.decrypt(blob) == "+79161234567"
    assert cipher.encrypt("+79161234567") != blob  # fresh nonce each time
    with pytest.raises(Exception):
        cipher.decrypt(blob[:-1] + bytes([blob[-1] ^ 1]))
    with pytest.raises(ValueError):
        cipher.decrypt(b"\x02" + blob[1:])
    with pytest.raises(ValueError):
        cipher.decrypt(b"")
    other = MsisdnCipher(os.urandom(32))
    with pytest.raises(Exception):
        other.decrypt(blob)


def test_secrets_and_codes():
    secret = generate_device_secret()
    assert len(secret) >= 40 and secret != generate_device_secret()
    assert len(sha256_hex(secret)) == 64
    code = generate_claim_code()
    assert is_claim_code(code)
    assert not is_claim_code("12345") and not is_claim_code("abcdef") and not is_claim_code(123456)  # type: ignore[arg-type]
    assert constant_time_equal("a", "a") and not constant_time_equal("a", "b")
