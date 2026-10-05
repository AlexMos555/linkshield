"""The device pass (plan A.5): a compact JWS, EdDSA (Ed25519), no personal data.

    header  {"alg": "EdDSA", "typ": "JWT", "kid": "<key id>"}
    payload {"v": 1, "dev": "<device uuid>", "mode": "full|basic|off",
             "src": "subscription|trial|legacy|promo|none", "plan": "family3"|null,
             "until": <unix>|null, "grace_until": <unix>|null,
             "lapse_policy": "basic|off", "iat": <unix>, "exp": <unix>}

The billing service signs (private seed in its env / Lockbox); the app and
the main API verify with the public key(s) — `Keyring` holds every key id
still accepted, which is how rotation works: sign with the new kid, keep
the old public key until every pass issued with it has expired.

`offline_mode` is THE rule the app follows when it cannot reach the server;
it is implemented here so the JS port (`mobile/src/lib/entitlement.ts`) is
pinned by the same tests:
  * the device clock can never be earlier than the pass's `iat` (a clock
    turned back does not extend anything);
  * before `until` — the issued mode; during the grace window — still the
    issued mode; after both — `lapse_policy`; `until = null` — the mode holds
    until a newer pass says otherwise (legacy free, lapsed);
  * `exp` is the signature's validity for the SERVER; the app keeps using an
    expired pass offline because that is all it has.
"""
from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Optional

from api.billing.models import EntitlementSource, LapsePolicy, ProtectionMode

PASS_VERSION = 1
_ALG = "EdDSA"
_SEED_BYTES = 32


class PassInvalid(Exception):
    """The token is not a pass we accept. `reason` is one short machine word."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class PassClaims:
    dev: str
    mode: ProtectionMode
    src: EntitlementSource
    lapse_policy: LapsePolicy
    iat: int
    exp: int
    plan: Optional[str] = None
    until: Optional[int] = None
    grace_until: Optional[int] = None
    v: int = PASS_VERSION

    def to_payload(self) -> dict:
        payload = asdict(self)
        payload["mode"] = self.mode.value
        payload["src"] = self.src.value
        payload["lapse_policy"] = self.lapse_policy.value
        return payload

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "PassClaims":
        try:
            return cls(
                v=int(payload["v"]),
                dev=str(payload["dev"]),
                mode=ProtectionMode(payload["mode"]),
                src=EntitlementSource(payload["src"]),
                lapse_policy=LapsePolicy(payload["lapse_policy"]),
                iat=int(payload["iat"]),
                exp=int(payload["exp"]),
                plan=payload.get("plan"),
                until=_opt_int(payload.get("until")),
                grace_until=_opt_int(payload.get("grace_until")),
            )
        except (KeyError, ValueError, TypeError) as e:
            raise PassInvalid("malformed") from e


def _opt_int(value: Any) -> Optional[int]:
    return None if value is None else int(value)


# ── Base64url (RFC 7515: no padding) ──


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as e:
        raise PassInvalid("malformed") from e


# ── Keys ──


def generate_keypair() -> tuple:
    """(private seed base64, public key base64) — for the ops runbook and tests."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    seed = private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption(),
    )
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(seed).decode("ascii"), base64.b64encode(public).decode("ascii")


class Signer:
    """Signs passes with one Ed25519 seed under one key id."""

    def __init__(self, seed: bytes, kid: str) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        if len(seed) != _SEED_BYTES:
            raise ValueError("Ed25519 seed must be 32 bytes")
        if not kid:
            raise ValueError("key id must not be empty")
        self._key = Ed25519PrivateKey.from_private_bytes(seed)
        self.kid = kid
        self.public_key_b64 = base64.b64encode(
            self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
        ).decode("ascii")

    def sign(self, claims: PassClaims) -> str:
        header = {"alg": _ALG, "typ": "JWT", "kid": self.kid}
        signing_input = _b64url(_canonical(header)) + "." + _b64url(_canonical(claims.to_payload()))
        signature = self._key.sign(signing_input.encode("ascii"))
        return signing_input + "." + _b64url(signature)


def _canonical(obj: Mapping[str, Any]) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


class Keyring:
    """Public keys by key id — every key a verifier still accepts."""

    def __init__(self, public_keys_b64: Mapping[str, str]) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        self._keys = {
            kid: Ed25519PublicKey.from_public_bytes(base64.b64decode(pub))
            for kid, pub in public_keys_b64.items()
        }

    @classmethod
    def from_json(cls, text: str) -> "Keyring":
        try:
            mapping = json.loads(text) if text.strip() else {}
        except json.JSONDecodeError as e:
            raise ValueError(f"BILLING_ENTITLEMENT_PUBLIC_KEYS is not JSON: {e}") from e
        if not isinstance(mapping, dict):
            raise ValueError("BILLING_ENTITLEMENT_PUBLIC_KEYS must be a JSON object {kid: base64}")
        return cls(mapping)

    def kids(self) -> tuple:
        return tuple(self._keys)

    def verify(self, token: str, now: int) -> PassClaims:
        """Signature, key id, version and `exp` — raises PassInvalid otherwise."""
        from cryptography.exceptions import InvalidSignature

        parts = token.split(".")
        if len(parts) != 3:
            raise PassInvalid("malformed")
        header = _json_part(parts[0])
        if header.get("alg") != _ALG:
            raise PassInvalid("unsupported_alg")
        key = self._keys.get(str(header.get("kid", "")))
        if key is None:
            raise PassInvalid("unknown_kid")
        try:
            key.verify(_b64url_decode(parts[2]), f"{parts[0]}.{parts[1]}".encode("ascii"))
        except InvalidSignature as e:
            raise PassInvalid("bad_signature") from e
        claims = PassClaims.from_payload(_json_part(parts[1]))
        if claims.v != PASS_VERSION:
            raise PassInvalid("unsupported_version")
        if now >= claims.exp:
            raise PassInvalid("expired")
        return claims


def _json_part(part: str) -> dict:
    try:
        decoded = json.loads(_b64url_decode(part))
    except (ValueError, UnicodeDecodeError) as e:
        raise PassInvalid("malformed") from e
    if not isinstance(decoded, dict):
        raise PassInvalid("malformed")
    return decoded


# ── The offline rule the app follows ──


def offline_mode(claims: PassClaims, device_now: int) -> ProtectionMode:
    """What the phone does with its last pass when the server is unreachable."""
    now = max(int(device_now), claims.iat)
    if claims.until is None or now < claims.until:
        return claims.mode
    if claims.grace_until is not None and now < claims.grace_until:
        return claims.mode
    return claims.lapse_policy.mode
