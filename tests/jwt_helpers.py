"""Supabase-style access tokens for tests, verified against a fake JWKS.

Supabase signs user access tokens with an asymmetric key (ES256 for this
project) and publishes the public half at
``<SUPABASE_URL>/auth/v1/.well-known/jwks.json``. The API verifies tokens
against that document (api/services/auth.py), so tests mint tokens with a
locally generated P-256 key and serve its public JWK from a fake JWKS —
nothing leaves the test process.

    key = SigningKey()
    jwks = install_fake_jwks(monkeypatch, key)
    headers = {"Authorization": f"Bearer {key.token('user-1')}"}
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Iterable, Optional

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

TEST_SUPABASE_URL = "https://test-project.supabase.co"
TEST_ISSUER = f"{TEST_SUPABASE_URL}/auth/v1"


class SigningKey:
    """One ES256 key pair, as a Supabase project's signing key."""

    def __init__(self, kid: Optional[str] = None) -> None:
        self.kid = kid or f"test-kid-{uuid.uuid4().hex[:8]}"
        self.private_key = ec.generate_private_key(ec.SECP256R1())

    def public_jwk(self) -> dict[str, Any]:
        jwk = ECAlgorithm.to_jwk(self.private_key.public_key(), as_dict=True)
        jwk.update({"kid": self.kid, "alg": "ES256", "use": "sig", "key_ops": ["verify"]})
        return jwk

    def token(
        self,
        sub: str = "user-test",
        *,
        email: Optional[str] = "person@example.com",
        iat_ago: int = 0,
        ttl: int = 3600,
        drop: Iterable[str] = (),
        **claims: Any,
    ) -> str:
        """A token shaped like a Supabase access token. ``iat_ago`` backdates
        the issue time (exp follows it); ``drop`` removes claims; keyword
        claims override the defaults."""
        iat = int(time.time()) - iat_ago
        payload: dict[str, Any] = {
            "sub": sub,
            "email": email,
            "aud": "authenticated",
            "role": "authenticated",
            "iss": TEST_ISSUER,
            "iat": iat,
            "exp": iat + ttl,
            "session_id": str(uuid.uuid4()),
        }
        payload.update(claims)
        for name in drop:
            payload.pop(name, None)
        return jwt.encode(payload, self.private_key, algorithm="ES256", headers={"kid": self.kid})

    def headers(self, sub: str = "user-test", **kw: Any) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token(sub, **kw)}"}


class FakeJwks:
    """What the fake JWKS endpoint serves; counts fetches; can go down."""

    def __init__(self, keys: Iterable[SigningKey]) -> None:
        self.keys = list(keys)
        self.fetches = 0
        self.down = False

    def document(self) -> dict[str, Any]:
        self.fetches += 1
        if self.down:
            raise jwt.PyJWKClientConnectionError("fake JWKS endpoint is down")
        return {"keys": [k.public_jwk() for k in self.keys]}


def install_fake_jwks(monkeypatch, *keys: SigningKey) -> FakeJwks:
    """Point the API at TEST_SUPABASE_URL and answer its JWKS fetches locally."""
    from api.config import get_settings
    from api.services import auth

    monkeypatch.setattr(get_settings(), "supabase_url", TEST_SUPABASE_URL)
    fake = FakeJwks(keys)
    monkeypatch.setattr(auth._SupabaseJWKClient, "_download", lambda self: fake.document())
    # A fresh client per test: no keys cached from another test's fake.
    monkeypatch.setattr(auth, "_jwks_clients", {})
    return fake
