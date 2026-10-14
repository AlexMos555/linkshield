"""
Supabase access tokens are verified against the project's JWKS.

The project signs user tokens with an asymmetric ES256 key (published at
<SUPABASE_URL>/auth/v1/.well-known/jwks.json); the legacy HS256 shared secret
is only "previously used". Pinned here:

- an ES256 token from the published key is accepted (sub/email/session/iat);
- issuer, audience, expiry, and the presence of sub/exp/iat are enforced;
- an HS256 token signed with the legacy secret is refused unless the explicit
  SUPABASE_ALLOW_LEGACY_HS256 opt-in is on (and even then iss/aud apply);
- `alg: none` and a token signed by another key under a known kid fail;
- keys are cached (10 min), an unknown kid refetches the JWKS (with a cooldown
  so random kids can't hammer Supabase), and a JWKS outage serves the last good
  keys — with nothing cached the API answers 503 `auth_unavailable`, never a
  500 with details.
"""
from __future__ import annotations

import time

import jwt
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from api.models.schemas import UserTier
from tests.jwt_helpers import TEST_ISSUER, SigningKey, install_fake_jwks

LEGACY_SECRET = "test-secret-for-development-only-not-for-production-use"


@pytest.fixture
def key():
    return SigningKey()


@pytest.fixture
def jwks(monkeypatch, key):
    from api.services import auth

    async def _free(_user_id):
        return UserTier.free

    monkeypatch.setattr(auth, "_resolve_user_tier", _free)
    return install_fake_jwks(monkeypatch, key)


async def _decode(token: str):
    from api.services.auth import _decode_jwt_and_resolve

    return await _decode_jwt_and_resolve(f"Bearer {token}")


async def _refused(token: str, status: int = 401) -> HTTPException:
    with pytest.raises(HTTPException) as exc:
        await _decode(token)
    assert exc.value.status_code == status
    return exc.value


def _legacy_token(**claims) -> str:
    now = int(time.time())
    payload = {"sub": "user-1", "aud": "authenticated", "iss": TEST_ISSUER, "iat": now, "exp": now + 3600}
    payload.update(claims)
    return jwt.encode(payload, LEGACY_SECRET, algorithm="HS256")


# ─── accepted ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_es256_token_from_the_published_key_is_accepted(jwks, key):
    token = key.token("user-1", email="ann@example.com", session_id="sess-1")
    user = await _decode(token)
    assert user.id == "user-1"
    assert user.email == "ann@example.com"
    assert user.session_id == "sess-1"
    assert user.issued_at is not None and abs(user.issued_at - time.time()) < 5


# ─── claims ─────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "https://evil.supabase.co/auth/v1"},
        {"iss": "https://test-project.supabase.co"},
        {"aud": "anon"},
        {"aud": "service_role"},
    ],
)
async def test_wrong_issuer_or_audience_is_refused(jwks, key, claims):
    await _refused(key.token(**claims))


@pytest.mark.asyncio
async def test_expired_token_is_refused(jwks, key):
    await _refused(key.token(iat_ago=7200, ttl=3600))


@pytest.mark.asyncio
@pytest.mark.parametrize("claim", ["sub", "exp", "iat", "iss", "aud"])
async def test_token_without_a_required_claim_is_refused(jwks, key, claim):
    await _refused(key.token(drop=[claim]))


@pytest.mark.asyncio
async def test_token_issued_in_the_future_is_refused(jwks, key):
    await _refused(key.token(iat_ago=-3600))


# ─── algorithms and keys ────────────────────────────────────────


@pytest.mark.asyncio
async def test_hs256_signed_with_the_legacy_secret_is_refused_by_default(jwks):
    await _refused(_legacy_token())


@pytest.mark.asyncio
async def test_hs256_opt_in_accepts_legacy_tokens_but_still_checks_issuer(jwks, monkeypatch):
    from api.config import get_settings

    monkeypatch.setattr(get_settings(), "supabase_allow_legacy_hs256", True)
    user = await _decode(_legacy_token(sub="legacy-user"))
    assert user.id == "legacy-user"
    await _refused(_legacy_token(iss="https://evil.supabase.co/auth/v1"))


@pytest.mark.asyncio
async def test_unsigned_token_is_refused(jwks, key):
    now = int(time.time())
    token = jwt.encode(
        {"sub": "user-1", "aud": "authenticated", "iss": TEST_ISSUER, "iat": now, "exp": now + 60},
        None,
        algorithm="none",
        headers={"kid": key.kid},
    )
    await _refused(token)


@pytest.mark.asyncio
async def test_token_signed_by_another_key_under_a_known_kid_is_refused(jwks, key):
    impostor = SigningKey(kid=key.kid)
    await _refused(impostor.token())


@pytest.mark.asyncio
async def test_garbage_is_refused(jwks):
    await _refused("not-a-jwt")


# ─── JWKS caching, rotation, outage ─────────────────────────────


@pytest.mark.asyncio
async def test_keys_are_cached_for_ten_minutes(jwks, key):
    from api.services import auth

    await _decode(key.token())
    await _decode(key.token())
    assert jwks.fetches == 1
    assert auth._jwks_client().jwk_set_cache.lifespan == 600


@pytest.mark.asyncio
async def test_unknown_kid_refetches_the_jwks(jwks, key):
    from api.services import auth

    await _decode(key.token())
    assert jwks.fetches == 1
    rotated = SigningKey()
    jwks.keys.append(rotated)
    # Past the anti-hammering cooldown, an unknown kid refetches the set.
    auth._jwks_client()._last_successful_fetch -= 60
    user = await _decode(rotated.token("rotated-user"))
    assert user.id == "rotated-user"
    assert jwks.fetches == 2


@pytest.mark.asyncio
async def test_unknown_kid_within_the_cooldown_does_not_hammer_supabase(jwks, key):
    await _decode(key.token())
    for _ in range(5):
        await _refused(SigningKey().token())
    assert jwks.fetches == 1


@pytest.mark.asyncio
async def test_jwks_outage_with_no_cached_key_is_503_without_details(jwks, key):
    jwks.down = True
    exc = await _refused(key.token(), status=503)
    assert exc.detail["code"] == "auth_unavailable"
    assert "fake JWKS" not in str(exc.detail)


@pytest.mark.asyncio
async def test_jwks_outage_serves_the_last_good_keys(jwks, key):
    from api.services import auth

    await _decode(key.token())
    jwks.down = True
    auth._jwks_client().jwk_set_cache.put(None)  # the 10-minute cache ran out
    user = await _decode(key.token("still-in"))
    assert user.id == "still-in"


@pytest.mark.asyncio
async def test_unconfigured_supabase_url_is_503(jwks, key, monkeypatch):
    from api.config import get_settings

    monkeypatch.setattr(get_settings(), "supabase_url", "")
    exc = await _refused(key.token(), status=503)
    assert exc.detail["code"] == "auth_unavailable"


# ─── over HTTP ──────────────────────────────────────────────────


def test_http_answers_401_and_503_never_500(jwks, key):
    from api.main import app

    c = TestClient(app, raise_server_exceptions=False)
    path = "/api/v1/user/account/restore"
    assert c.post(path).status_code == 401
    assert c.post(path, headers={"Authorization": "Bearer junk"}).status_code == 401
    assert c.post(path, headers={"Authorization": f"Bearer {_legacy_token()}"}).status_code == 401

    jwks.down = True
    resp = c.post(path, headers=key.headers())
    assert resp.status_code == 503
    assert resp.json()["detail"]["code"] == "auth_unavailable"
