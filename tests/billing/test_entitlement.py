"""The device pass: signing, verification, rotation, and the app's offline rule."""
from __future__ import annotations

import base64
import json

import pytest

from api.billing.entitlement import (
    PASS_VERSION,
    Keyring,
    PassClaims,
    PassInvalid,
    Signer,
    generate_keypair,
    offline_mode,
)
from api.billing.models import EntitlementSource, LapsePolicy, ProtectionMode

NOW = 1_800_000_000
DAY = 86_400


def _claims(**overrides) -> PassClaims:
    base = dict(
        dev="dev-1", mode=ProtectionMode.FULL, src=EntitlementSource.SUBSCRIPTION,
        lapse_policy=LapsePolicy.BASIC, iat=NOW, exp=NOW + 7 * DAY, plan="family3",
        until=NOW + 20 * DAY, grace_until=NOW + 27 * DAY,
    )
    base.update(overrides)
    return PassClaims(**base)


@pytest.fixture
def signer() -> Signer:
    seed_b64, _ = generate_keypair()
    return Signer(base64.b64decode(seed_b64), kid="k1")


@pytest.fixture
def keyring(signer) -> Keyring:
    return Keyring({"k1": signer.public_key_b64})


def _parts(token: str):
    header, payload, sig = token.split(".")
    pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
    return json.loads(base64.urlsafe_b64decode(pad(header))), json.loads(base64.urlsafe_b64decode(pad(payload))), sig


def test_pass_is_a_compact_eddsa_jws_without_personal_data(signer, keyring):
    token = signer.sign(_claims())
    header, payload, _ = _parts(token)
    assert header == {"alg": "EdDSA", "typ": "JWT", "kid": "k1"}
    assert set(payload) == {"v", "dev", "mode", "src", "plan", "until", "grace_until", "lapse_policy", "iat", "exp"}
    assert payload["v"] == PASS_VERSION and payload["mode"] == "full" and payload["src"] == "subscription"
    assert keyring.verify(token, now=NOW + 1) == _claims()


def test_signer_refuses_bad_seed_and_empty_kid():
    with pytest.raises(ValueError):
        Signer(b"short", kid="k1")
    with pytest.raises(ValueError):
        Signer(b"\x00" * 32, kid="")


def test_tampered_payload_fails_verification(signer, keyring):
    token = signer.sign(_claims())
    header, payload, sig = token.split(".")
    forged = json.dumps({**json.loads(base64.urlsafe_b64decode(payload + "==")), "mode": "full", "until": None})
    forged_b64 = base64.urlsafe_b64encode(forged.encode()).rstrip(b"=").decode()
    with pytest.raises(PassInvalid) as e:
        keyring.verify(f"{header}.{forged_b64}.{sig}", now=NOW)
    assert e.value.reason == "bad_signature"


def test_foreign_key_is_rejected(signer):
    _, other_pub = generate_keypair()
    ring = Keyring({"k1": other_pub})
    with pytest.raises(PassInvalid) as e:
        ring.verify(signer.sign(_claims()), now=NOW)
    assert e.value.reason == "bad_signature"


def test_unknown_kid_is_rejected(signer):
    ring = Keyring({"k2": signer.public_key_b64})
    with pytest.raises(PassInvalid) as e:
        ring.verify(signer.sign(_claims()), now=NOW)
    assert e.value.reason == "unknown_kid"


def test_expired_pass_is_rejected_by_the_server(signer, keyring):
    token = signer.sign(_claims())
    assert keyring.verify(token, now=NOW + 7 * DAY - 1)
    with pytest.raises(PassInvalid) as e:
        keyring.verify(token, now=NOW + 7 * DAY)
    assert e.value.reason == "expired"


@pytest.mark.parametrize("token, reason", [
    ("not.a.jws.at.all", "malformed"),
    ("a.b", "malformed"),
    ("!!!.b.c", "malformed"),
])
def test_malformed_tokens(keyring, token, reason):
    with pytest.raises(PassInvalid) as e:
        keyring.verify(token, now=NOW)
    assert e.value.reason == reason


def test_alg_none_is_rejected(keyring):
    header = base64.urlsafe_b64encode(b'{"alg":"none","kid":"k1"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps(_claims().to_payload()).encode()).rstrip(b"=").decode()
    with pytest.raises(PassInvalid) as e:
        keyring.verify(f"{header}.{payload}.", now=NOW)
    assert e.value.reason == "unsupported_alg"


def test_rotation_old_kid_verifies_until_removed():
    old_seed, _ = generate_keypair()
    new_seed, _ = generate_keypair()
    old = Signer(base64.b64decode(old_seed), kid="2026-09")
    new = Signer(base64.b64decode(new_seed), kid="2026-12")
    token_old = old.sign(_claims())
    token_new = new.sign(_claims())
    both = Keyring({"2026-09": old.public_key_b64, "2026-12": new.public_key_b64})
    assert both.verify(token_old, NOW) and both.verify(token_new, NOW)
    only_new = Keyring({"2026-12": new.public_key_b64})
    assert only_new.verify(token_new, NOW)
    with pytest.raises(PassInvalid):
        only_new.verify(token_old, NOW)
    assert set(both.kids()) == {"2026-09", "2026-12"}


def test_keyring_from_json():
    _, pub = generate_keypair()
    assert Keyring.from_json(json.dumps({"k": pub})).kids() == ("k",)
    assert Keyring.from_json("").kids() == ()
    with pytest.raises(ValueError):
        Keyring.from_json("[1,2]")
    with pytest.raises(ValueError):
        Keyring.from_json("{not json")


def test_from_payload_rejects_garbage():
    with pytest.raises(PassInvalid):
        PassClaims.from_payload({"v": 1, "dev": "d", "mode": "turbo"})


# ── The offline rule (ported to the app as-is) ──


def test_offline_full_until_then_full_through_grace_then_lapse_policy():
    claims = _claims()
    assert offline_mode(claims, NOW + 19 * DAY) is ProtectionMode.FULL
    assert offline_mode(claims, NOW + 26 * DAY) is ProtectionMode.FULL       # grace window
    assert offline_mode(claims, NOW + 27 * DAY) is ProtectionMode.BASIC      # lapse_policy=basic
    assert offline_mode(_claims(lapse_policy=LapsePolicy.OFF), NOW + 27 * DAY) is ProtectionMode.OFF


def test_offline_clock_turned_back_cannot_extend_the_pass():
    claims = _claims(until=NOW + 1 * DAY, grace_until=None)
    # The phone claims it is a year before the pass was issued: treated as `iat`.
    assert offline_mode(claims, NOW - 365 * DAY) is ProtectionMode.FULL
    assert offline_mode(claims, NOW + 1 * DAY) is ProtectionMode.BASIC


def test_offline_trial_has_no_grace():
    claims = _claims(src=EntitlementSource.TRIAL, plan=None, until=NOW + 14 * DAY, grace_until=None)
    assert offline_mode(claims, NOW + 13 * DAY) is ProtectionMode.FULL
    assert offline_mode(claims, NOW + 14 * DAY) is ProtectionMode.BASIC


def test_offline_open_ended_pass_keeps_its_mode():
    legacy = _claims(src=EntitlementSource.LEGACY, plan=None, until=None, grace_until=None)
    assert offline_mode(legacy, NOW + 10 * 365 * DAY) is ProtectionMode.FULL
    lapsed = _claims(mode=ProtectionMode.BASIC, src=EntitlementSource.NONE, until=None, grace_until=None)
    assert offline_mode(lapsed, NOW + 30 * DAY) is ProtectionMode.BASIC
