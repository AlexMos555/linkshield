"""Supabase token verification under hostile input and a misbehaving JWKS.

Complements tests/test_jwt_verification.py:

- malformed tokens (segment count, base64, non-object header, kid type) and
  algorithm tricks (HS256 keyed with the published public key, RS256 under an
  EC kid, HS512, no alg) are 401s, never 500s;
- `nbf` in the future, a non-string / empty `sub`, and the 30 s clock-skew
  leeway on `exp`;
- the REAL JWKS download (urllib, no fake `_download`): the URL and timeout we
  use, a timeout or connection failure, and an endpoint that answers 200 with
  something that is not a usable key set (an HTML error page, an empty set, a
  JSON array). With good keys cached those must keep working (stale-if-error);
  with nothing cached they are 503 `auth_unavailable`, and a garbled answer
  must not poison the cache once Supabase recovers;
- get_optional_user / get_current_user_no_disposable entry points;
- the subscriptions tier lookup falls back to free on errors / unknown tiers.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import time
import urllib.error

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from api.models.schemas import UserTier
from tests.jwt_helpers import TEST_ISSUER, TEST_SUPABASE_URL, SigningKey, install_fake_jwks


@pytest.fixture
def key():
    return SigningKey()


@pytest.fixture
def free_tier(monkeypatch):
    from api.services import auth

    async def _free(_user_id):
        return UserTier.free

    monkeypatch.setattr(auth, "_resolve_user_tier", _free)


@pytest.fixture
def jwks(monkeypatch, key, free_tier):
    return install_fake_jwks(monkeypatch, key)


async def _decode(token: str):
    from api.services.auth import _decode_jwt_and_resolve

    return await _decode_jwt_and_resolve(f"Bearer {token}")


async def _refused(token: str, status: int = 401) -> HTTPException:
    with pytest.raises(HTTPException) as exc:
        await _decode(token)
    assert exc.value.status_code == status
    return exc.value


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _claims(**over) -> dict:
    now = int(time.time())
    payload = {"sub": "user-1", "aud": "authenticated", "iss": TEST_ISSUER, "iat": now, "exp": now + 3600}
    payload.update(over)
    return payload


# ─── malformed tokens ───────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "token",
    [
        "a.b",                                          # two segments
        "a.b.c.d",                                      # four segments
        "!!!.e30.sig",                                  # header is not base64url
        f"{_b64(b'not json')}.e30.sig",                 # header is not JSON
        f"{_b64(b'[1, 2]')}.e30.sig",                   # header is not an object
        f"{_b64(json.dumps({'alg': 'ES256', 'kid': 123}).encode())}.e30.sig",  # kid not a string
        f"{_b64(json.dumps({'alg': 'ES256'}).encode())}.%%%.sig",              # payload not base64
        "Bearer",                                       # the scheme word alone
    ],
)
async def test_malformed_tokens_are_401_not_500(jwks, security_events, token):
    exc = await _refused(token)
    assert exc.detail == "Invalid or expired token"
    assert security_events == [("auth_invalid_token", None)]


@pytest.mark.asyncio
@pytest.mark.parametrize("header", ["", "Bearer ", "Bearer    "])
async def test_missing_or_empty_bearer_is_401(jwks, header):
    from api.services.auth import _decode_jwt_and_resolve

    with pytest.raises(HTTPException) as exc:
        await _decode_jwt_and_resolve(header)
    assert exc.value.status_code == 401


# ─── algorithm tricks ───────────────────────────────────────────


def _hs256_with(secret: bytes, kid: str) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": kid}).encode())
    body = _b64(json.dumps(_claims(sub="attacker")).encode())
    sig = hmac.new(secret, f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{_b64(sig)}"


def _public_key_forms(key: SigningKey) -> list[bytes]:
    pem = key.private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return [pem, json.dumps(key.public_jwk()).encode()]


@pytest.mark.asyncio
@pytest.mark.parametrize("legacy_opt_in", [False, True])
async def test_hs256_keyed_with_the_published_public_key_is_refused(jwks, key, monkeypatch, legacy_opt_in):
    """Classic key confusion: the public key (which anyone can download) used
    as an HMAC secret. Refused by default, and the legacy HS256 opt-in only
    ever verifies against the shared secret."""
    from api.config import get_settings

    monkeypatch.setattr(get_settings(), "supabase_allow_legacy_hs256", legacy_opt_in)
    for secret in _public_key_forms(key):
        await _refused(_hs256_with(secret, key.kid))


@pytest.mark.asyncio
async def test_rs256_token_under_an_ec_kid_is_refused(jwks, key):
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(_claims(), rsa_key, algorithm="RS256", headers={"kid": key.kid})
    await _refused(token)


@pytest.mark.asyncio
@pytest.mark.parametrize("alg", ["HS512", "PS256", "EdDSA", None])
async def test_algorithms_outside_the_allowlist_are_refused(jwks, key, alg):
    header = {"kid": key.kid, "typ": "JWT"}
    if alg is not None:
        header["alg"] = alg
    token = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(_claims()).encode())}.{_b64(b'sig')}"
    await _refused(token)


@pytest.mark.asyncio
async def test_es256_header_without_a_kid_is_refused(jwks, key):
    token = jwt.encode(_claims(), key.private_key, algorithm="ES256")
    await _refused(token)


# ─── claims ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_not_before_in_the_future_is_refused(jwks, key):
    await _refused(key.token(nbf=int(time.time()) + 3600))


@pytest.mark.asyncio
async def test_not_before_within_the_leeway_is_accepted(jwks, key):
    user = await _decode(key.token("skewed", nbf=int(time.time()) + 10))
    assert user.id == "skewed"


@pytest.mark.asyncio
async def test_expiry_honours_the_30s_clock_skew_leeway(jwks, key):
    # Expired 10 s ago: within the leeway.
    assert (await _decode(key.token("late", iat_ago=3610, ttl=3600))).id == "late"
    # Expired 60 s ago: the everyday "refresh your session" answer.
    exc = await _refused(key.token(iat_ago=3660, ttl=3600))
    assert exc.detail == "Token expired"


@pytest.mark.asyncio
@pytest.mark.parametrize("sub", ["", 123, None, ["user-1"]])
async def test_subject_must_be_a_non_empty_string(jwks, key, sub):
    await _refused(key.token(sub=sub))


@pytest.mark.asyncio
async def test_non_numeric_iat_is_refused(jwks, key):
    await _refused(key.token(iat="yesterday"))


@pytest.mark.asyncio
async def test_odd_optional_claims_are_dropped_not_trusted(jwks, key):
    user = await _decode(key.token("u1", email="", session_id=42))
    assert user.email is None
    assert user.session_id is None


# ─── the real JWKS download (urllib, offline) ───────────────────


class _Opener:
    """What urllib.request.build_opener returns: serves `responses` in order
    (bytes = a 200 body, an exception = raised), the last one repeatedly."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls: list[tuple[str, float]] = []

    def serve(self, *responses):
        self.responses = list(responses)

    def open(self, request, timeout=None):
        self.calls.append((request.full_url, timeout))
        item = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(item, BaseException):
            raise item
        return io.BytesIO(item)


@pytest.fixture
def jwks_http(monkeypatch, free_tier):
    """The API pointed at TEST_SUPABASE_URL with PyJWT's own fetch code
    running against an in-process opener: nothing leaves the test."""
    import urllib.request

    from api.config import get_settings
    from api.services import auth

    monkeypatch.setattr(get_settings(), "supabase_url", TEST_SUPABASE_URL)
    monkeypatch.setattr(auth, "_jwks_clients", {})
    opener = _Opener(b"{}")
    monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: opener)
    return opener


def _jwks_body(*keys: SigningKey) -> bytes:
    return json.dumps({"keys": [k.public_jwk() for k in keys]}).encode()


def _expire_key_cache():
    from api.services import auth

    auth._jwks_client().jwk_set_cache.put(None)


@pytest.mark.asyncio
async def test_real_download_fetches_the_project_jwks_with_a_short_timeout(jwks_http, key):
    jwks_http.serve(_jwks_body(key))
    assert (await _decode(key.token("u1"))).id == "u1"
    assert jwks_http.calls == [(f"{TEST_SUPABASE_URL}/auth/v1/.well-known/jwks.json", 5)]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [
    TimeoutError("timed out"),
    urllib.error.URLError("connection refused"),
    urllib.error.HTTPError(f"{TEST_SUPABASE_URL}/auth/v1/.well-known/jwks.json", 502, "Bad Gateway", {}, None),
])
async def test_real_download_failure_with_nothing_cached_is_503(jwks_http, key, failure):
    jwks_http.serve(failure)
    exc = await _refused(key.token(), status=503)
    assert exc.detail["code"] == "auth_unavailable"


# What a JWKS endpoint has been seen to answer with a 200 during an incident:
# a proxy's HTML page, a truncated document, an empty key set, a bare array,
# a key set whose only key is unusable.
_GARBLED = [
    b"<html><body>502 Bad Gateway</body></html>",
    b'{"keys": [',
    b'{"keys": []}',
    b"[]",
    b'{"keys": [{"kty": "EC", "crv": "P-256", "kid": "x"}]}',
]


@pytest.mark.asyncio
@pytest.mark.parametrize("body", _GARBLED)
async def test_garbled_jwks_with_nothing_cached_is_503_not_500_or_401(jwks_http, key, body, security_events):
    jwks_http.serve(body)
    exc = await _refused(key.token(), status=503)
    assert exc.detail["code"] == "auth_unavailable"
    # Not an attack on our side: the token itself was never judged.
    assert security_events == []


@pytest.mark.asyncio
@pytest.mark.parametrize("body", _GARBLED)
async def test_garbled_jwks_does_not_lock_users_out_after_supabase_recovers(jwks_http, key, body):
    jwks_http.serve(body)
    await _refused(key.token(), status=503)
    jwks_http.serve(_jwks_body(key))
    assert (await _decode(key.token("back"))).id == "back"


@pytest.mark.asyncio
@pytest.mark.parametrize("body", _GARBLED)
async def test_garbled_jwks_serves_the_last_good_keys(jwks_http, key, body):
    jwks_http.serve(_jwks_body(key))
    await _decode(key.token())
    _expire_key_cache()
    jwks_http.serve(body)
    assert (await _decode(key.token("still-in"))).id == "still-in"
    # And the good set stays the one served on the next request too.
    assert (await _decode(key.token("again"))).id == "again"


@pytest.mark.asyncio
async def test_unknown_kid_refetch_that_comes_back_garbled_keeps_the_old_keys(jwks_http, key):
    from api.services import auth

    jwks_http.serve(_jwks_body(key))
    await _decode(key.token())
    auth._jwks_client()._last_successful_fetch -= 60   # past the cooldown
    jwks_http.serve(b"<html>maintenance</html>")
    await _refused(SigningKey().token())               # unknown kid: 401, not 500
    assert (await _decode(key.token("known"))).id == "known"


# ─── other entry points ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_optional_user_is_none_for_missing_or_bad_tokens(jwks, key, fake_redis, security_events):
    from api.services.auth import get_optional_user

    assert await get_optional_user(None, None) is None
    assert await get_optional_user("Bearer junk", None) is None
    assert await get_optional_user(f"Bearer {key.token(iat_ago=7200)}", None) is None
    user = await get_optional_user(f"Bearer {key.token('opt-user')}", None)
    assert user is not None and user.id == "opt-user"


@pytest.mark.asyncio
async def test_optional_user_is_none_for_a_soft_deleted_account(jwks, key, fake_redis):
    from api.services.auth import get_optional_user

    await fake_redis.setex("deleted:gone-user", 3600, "1")
    assert await get_optional_user(f"Bearer {key.token('gone-user')}", None) is None


@pytest.mark.asyncio
async def test_disposable_email_is_refused_at_the_endpoint_gate(jwks, key, fake_redis):
    from api.services.auth import get_current_user_no_disposable

    with pytest.raises(HTTPException) as exc:
        await get_current_user_no_disposable(f"Bearer {key.token('d1', email='x@mailinator.com')}", None)
    assert exc.value.status_code == 403
    assert "support_url" in exc.value.detail


@pytest.mark.asyncio
@pytest.mark.parametrize("email", ["ann@gmail.com", None])
async def test_real_or_absent_email_passes_the_disposable_gate(jwks, key, fake_redis, email):
    from api.services.auth import get_current_user_no_disposable

    user = await get_current_user_no_disposable(f"Bearer {key.token('r1', email=email)}", None)
    assert user.id == "r1"


@pytest.mark.asyncio
async def test_a_failing_sentry_never_breaks_sign_in(jwks, key, fake_redis, monkeypatch):
    import sentry_sdk

    from api.services.auth import get_current_user

    def _boom(*a, **k):
        raise RuntimeError("sentry hub unavailable")

    monkeypatch.setattr(sentry_sdk, "set_user", _boom)
    user = await get_current_user(f"Bearer {key.token('s1')}", None)
    assert user.id == "s1"


# ─── subscriptions tier lookup ──────────────────────────────────


@pytest.fixture
def supabase(monkeypatch):
    from api.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(s, "supabase_service_key", "fake-key", raising=False)
    monkeypatch.setattr(s, "supabase_secret_key", "", raising=False)


def _httpx_answering(monkeypatch, *, status=200, body=None, exc=None):
    import httpx

    class _Resp:
        status_code = status

        def json(self):
            return body

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def get(self, url, headers=None, **kw):
            if exc is not None:
                raise exc
            return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", _Client)


def _entitlements(monkeypatch, plan=None):
    from api.services import entitlements

    calls = []

    async def _ent(user_id, legacy_row=None):
        calls.append(user_id)
        return entitlements.Entitlement(
            plan=plan or "free", status="active" if plan else "free",
            source="google_play" if plan else None, external_id=None, period_end=None, device_limit=1,
        )

    monkeypatch.setattr(entitlements, "get_effective_entitlement", _ent)
    return calls


@pytest.mark.asyncio
async def test_unknown_tier_in_the_subscriptions_row_is_free(supabase, monkeypatch):
    from api.services import auth

    _httpx_answering(monkeypatch, body=[{"tier": "platinum"}])
    assert await auth._fetch_tier_from_supabase("u1") is UserTier.free


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 500, 503])
async def test_subscriptions_error_status_falls_through_to_entitlements(supabase, monkeypatch, status):
    from api.services import auth

    _httpx_answering(monkeypatch, status=status, body={"message": "boom"})
    calls = _entitlements(monkeypatch, plan="personal")
    assert await auth._fetch_tier_from_supabase("u1") is UserTier.personal
    assert calls == ["u1"]


@pytest.mark.asyncio
async def test_subscriptions_timeout_is_free_not_an_error(supabase, monkeypatch):
    import httpx

    from api.services import auth

    _httpx_answering(monkeypatch, exc=httpx.ReadTimeout("slow"))
    assert await auth._fetch_tier_from_supabase("u1") is UserTier.free
