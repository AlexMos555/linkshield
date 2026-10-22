"""
Authentication service.

Validates Supabase access tokens and resolves user tier from database.
Tier is cached in Redis for 5 minutes to avoid per-request DB calls.

Supabase signs user access tokens with the project's ASYMMETRIC signing key
(ES256 today; RS256 also accepted) and publishes the public half at
``<SUPABASE_URL>/auth/v1/.well-known/jwks.json``. Tokens are verified against
that JWKS only: signature, ``exp``, ``iat``, ``aud == "authenticated"`` and
``iss == <SUPABASE_URL>/auth/v1``. HS256 tokens signed with the legacy shared
secret are refused unless SUPABASE_ALLOW_LEGACY_HS256 is explicitly on —
docs/runbooks/supabase-jwt-signing-keys.md.
"""

import asyncio
import logging
import threading
import time
from typing import Any, Optional

import jwt
from fastapi import Depends, HTTPException, Header

from api.config import get_settings
from api.models.schemas import AuthUser, UserTier
from api.services import security_alerts
from api.services import supabase_keys

logger = logging.getLogger("cleanway.auth")

# Cache tier in Redis for 5 minutes
_TIER_CACHE_TTL = 300

_AUDIENCE = "authenticated"
_ASYMMETRIC_ALGORITHMS = ("ES256", "RS256")
# Clock skew tolerated on exp / iat / nbf.
_LEEWAY_S = 30
# JWKS cache: keys are reused for 10 minutes; an unknown kid refetches the
# set, at most once per cooldown so random kids can't hammer Supabase.
_JWKS_LIFESPAN_S = 600
_JWKS_UNKNOWN_KID_COOLDOWN_S = 30
_JWKS_TIMEOUT_S = 5

# Sensitive actions need a token issued at most this long ago.
RECENT_AUTH_MAX_AGE_S = 600

_INVALID = "Invalid or expired token"
_EXPIRED = "Token expired"


def _auth_unavailable() -> HTTPException:
    # Deliberately no upstream detail: the reason is in the server log.
    return HTTPException(
        status_code=503,
        detail={
            "code": "auth_unavailable",
            "error": "Sign-in can't be checked right now. Please try again in a moment.",
        },
    )


class _SupabaseJWKClient(jwt.PyJWKClient):
    """PyJWKClient that keeps serving the last good key set when a refetch
    fails (stale-if-error): a short Supabase blip must not sign everyone out.
    With nothing fetched yet, the error propagates and the API fails closed."""

    def __init__(self, uri: str) -> None:
        super().__init__(
            uri,
            cache_jwk_set=True,
            lifespan=_JWKS_LIFESPAN_S,
            timeout=_JWKS_TIMEOUT_S,
            cooldown_duration=_JWKS_UNKNOWN_KID_COOLDOWN_S,
        )
        self._last_good: Optional[dict[str, Any]] = None

    def _download(self) -> Any:
        return jwt.PyJWKClient.fetch_data(self)

    def fetch_data(self) -> Any:
        try:
            data = self._as_jwk_set_payload(self._download())
            if self.jwk_set_cache is not None:
                # Parses the set: raises PyJWKSetError when no key is usable.
                self.jwk_set_cache.put(data)
        except jwt.PyJWKClientConnectionError:
            if self._last_good is None:
                raise
            logger.warning("jwks_fetch_failed_serving_cached_keys")
            return self._last_good
        except (ValueError, jwt.PyJWKClientError, jwt.PyJWKSetError) as e:
            # A 200 that is not a usable key set (a proxy's HTML error page,
            # a truncated or empty document, a bare JSON array) is an outage
            # too: keep the last good keys, else 503 — never a 500 (invalid
            # JSON) or a 401 that would sign every user out.
            if self._last_good is None:
                raise jwt.PyJWKSetError(f"unusable JWKS response: {type(e).__name__}") from e
            logger.warning("jwks_malformed_serving_cached_keys", extra={"error": type(e).__name__})
            return self._last_good
        self._last_successful_fetch = time.monotonic()
        self._last_good = data
        return data


_jwks_clients: dict[str, _SupabaseJWKClient] = {}
_jwks_lock = threading.Lock()


def _supabase_base() -> str:
    return (get_settings().supabase_url or "").strip().rstrip("/")


def _jwks_client() -> _SupabaseJWKClient:
    """One client (and key cache) per process for the configured project."""
    uri = f"{_supabase_base()}/auth/v1/.well-known/jwks.json"
    with _jwks_lock:
        client = _jwks_clients.get(uri)
        if client is None:
            client = _jwks_clients[uri] = _SupabaseJWKClient(uri)
        return client


def _verify_supabase_token(token: str) -> dict[str, Any]:
    """Verify signature + claims; return the payload. Blocking (a JWKS fetch
    may hit the network) — call it off the event loop."""
    settings = get_settings()
    base = _supabase_base()
    if not base:
        logger.error("jwt_verify_unconfigured_supabase_url")
        raise _auth_unavailable()

    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail=_INVALID)
    alg = header.get("alg")

    key: Any
    if alg in _ASYMMETRIC_ALGORITHMS:
        try:
            key = _jwks_client().get_signing_key_from_jwt(token)
        except jwt.PyJWKClientConnectionError as e:
            logger.error("jwks_unavailable", extra={"error": type(e).__name__})
            raise _auth_unavailable()
        except jwt.PyJWKSetError as e:
            logger.error("jwks_malformed", extra={"error": str(e)})
            raise _auth_unavailable()
        except (jwt.PyJWKClientError, jwt.InvalidTokenError) as e:
            # Unknown kid (after the allowed refetch) or a malformed header.
            logger.warning("jwt_unknown_signing_key", extra={"error": str(e)})
            raise HTTPException(status_code=401, detail=_INVALID)
        algorithms = [alg]
    elif alg == "HS256" and settings.supabase_allow_legacy_hs256 and settings.supabase_jwt_secret:
        key = settings.supabase_jwt_secret
        algorithms = ["HS256"]
    else:
        logger.warning("jwt_algorithm_refused", extra={"alg": str(alg)[:16]})
        raise HTTPException(status_code=401, detail=_INVALID)

    try:
        return jwt.decode(
            token,
            key,
            algorithms=algorithms,
            audience=_AUDIENCE,
            issuer=f"{base}/auth/v1",
            leeway=_LEEWAY_S,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail=_EXPIRED)
    except jwt.InvalidTokenError as e:
        # Log the real error server-side, return generic message to client.
        logger.warning("jwt_invalid", extra={"error": str(e)})
        raise HTTPException(status_code=401, detail=_INVALID)


async def _decode_jwt_and_resolve(authorization: Optional[str]) -> AuthUser:
    """
    Shared JWT validate + tier resolve path used by every entry-point
    dependency (get_current_user, get_current_user_including_deleted,
    get_optional_user). Centralising it means the JWT options + the
    error-mapping policy live in ONE place — previous duplication
    (audit backend MEDIUM "JWT decode logic is fully duplicated
    between get_current_user and get_current_user_including_deleted")
    let the two paths drift on subtle behaviour (audience claim,
    algorithm allowlist, error wording).

    Throws HTTPException(401) on any auth failure, 503 when the signing keys
    can't be fetched and none are cached. Callers layer on additional gates
    (soft-delete check, disposable-email check) AFTER this returns.
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")

    token = authorization.replace("Bearer ", "").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Token required")

    # Off the event loop: a cache miss fetches the JWKS over the network.
    try:
        payload = await asyncio.to_thread(_verify_supabase_token, token)
    except HTTPException as e:
        # Forged, foreign-key or malformed tokens. An expired token is the
        # everyday case (clients refresh), so it is not counted.
        if e.status_code == 401 and e.detail != _EXPIRED:
            await security_alerts.record("auth_invalid_token")
        raise

    user_id = payload.get("sub")
    email = payload.get("email")
    if not isinstance(user_id, str) or not user_id:
        raise HTTPException(status_code=401, detail=_INVALID)

    tier = await _resolve_user_tier(user_id)
    session_id = payload.get("session_id")
    iat = payload.get("iat")
    return AuthUser(
        id=user_id,
        email=email if isinstance(email, str) and email else None,
        tier=tier,
        session_id=session_id if isinstance(session_id, str) else None,
        issued_at=int(iat) if isinstance(iat, (int, float)) else None,
    )


def require_recent_auth(user: AuthUser, max_age_s: int = RECENT_AUTH_MAX_AGE_S) -> None:
    """401 `reauth_required` unless the caller's token was issued within
    `max_age_s`. Clients answer it by refreshing the session (a refresh
    issues a new access token) and retrying, or by asking for a sign-in."""
    if user.issued_at is None or time.time() - user.issued_at > max_age_s:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "reauth_required",
                "error": "Please sign in again to continue.",
            },
        )


# The users row (deletion_requested_at) is the truth about a deletion; Redis
# only caches its answer. "Not deleted" is stored as the time the row said
# so: trusted for 5 minutes, and kept a day only to ride out a database
# outage (stale-if-error). DELETE /user/account drops it at once. "Deleted",
# read back from the row after the 30-day flag expired, is cached for an
# hour (restore and the purge drop it).
_NOT_DELETED_FRESH_S = 300
_NOT_DELETED_KEEP_S = 24 * 3600
_DELETED_RECACHE_TTL_S = 3600


def _checked_at(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


async def _deletion_requested(user_id: str) -> bool:
    """Is this account in its deletion grace window?

    Fast path: the `deleted:{id}` Redis flag written by DELETE /user/account,
    then a fresh `notdeleted:{id}` answer cached below. A missing flag is
    NOT "not deleted": the flag expires after 30 days while the account
    waits for the purge, and it can be lost (eviction, a Redis blip at
    deletion time) — reading that as "allowed" gave a deleted account its
    API access back. Otherwise the users row (deletion_requested_at)
    decides, and its answer is cached. When the row can't be read, a "not
    deleted" the row gave in the last day still answers (it is dropped the
    moment the account is deleted); with none, 503 — never "allowed", and
    never a 410 that would tell every live user their account is going away.
    No database configured (local dev) → there is no row: not deleted."""
    r = None
    checked_at: Optional[float] = None
    try:
        from api.services.cache import get_redis

        r = await get_redis()
        if await r.get(f"deleted:{user_id}"):
            return True
        checked_at = _checked_at(await r.get(f"notdeleted:{user_id}"))
    except Exception as e:
        r = None
        logger.warning(
            "deleted_flag_unreadable",
            extra={"user_id": user_id, "error": type(e).__name__},
        )
    now = time.time()
    if checked_at is not None and now - checked_at < _NOT_DELETED_FRESH_S:
        return False

    from api.services import account_store

    store = account_store.get_account_store()
    if store is None:
        return False
    try:
        deleted = await store.is_deletion_requested(user_id)
    except account_store.AccountStoreError as e:
        if checked_at is not None:
            logger.warning(
                "deleted_check_served_stale",
                extra={"user_id": user_id, "age_s": int(now - checked_at), "error": str(e)},
            )
            return False
        logger.error(
            "deleted_check_unavailable",
            extra={"user_id": user_id, "error": str(e)},
        )
        raise _auth_unavailable() from e

    if r is not None:
        try:
            if deleted:
                await r.setex(f"deleted:{user_id}", _DELETED_RECACHE_TTL_S, "1")
            else:
                await r.setex(f"notdeleted:{user_id}", _NOT_DELETED_KEEP_S, str(int(now)))
        except Exception as e:
            # The answer stands; the next request reads the row again.
            logger.warning(
                "deleted_flag_cache_failed",
                extra={"user_id": user_id, "error": type(e).__name__},
            )
    return deleted


async def _refuse_revoked_device(user_id: str, device_id: Optional[str]) -> None:
    """403 `device_revoked` when this install was unlinked from the account.

    The app sends its per-install id as X-Device-Id (see
    api/services/account_devices.py). An unlinked install keeps a valid JWT
    for up to an hour, so the token alone can't tell — the marker written at
    unlink time can. The app answers this code by signing out locally."""
    if not isinstance(device_id, str) or not device_id:
        return
    from api.services.account_devices import is_revoked

    if await is_revoked(user_id, device_id):
        raise HTTPException(
            status_code=403,
            detail={
                "code": "device_revoked",
                "error": "This device was removed from your account. Sign in again to use it.",
            },
        )


async def get_current_user(
    authorization: Optional[str] = Header(None),
    # Hidden from the OpenAPI document: it is a transport detail of our own
    # clients, not a parameter of every authenticated endpoint.
    x_device_id: Optional[str] = Header(None, alias="X-Device-Id", include_in_schema=False),
) -> AuthUser:
    """
    Validate Supabase JWT and return authenticated user.
    Tier is resolved from Supabase DB (cached in Redis).
    """
    user = await _decode_jwt_and_resolve(authorization)

    # ── Soft-delete gate ──
    # Privacy Policy §9: account-deleted users must lose access during
    # the 30-day grace window. Without this check, a user who clicked
    # "Delete account" would still be charged + still use the API
    # throughout grace. The users row (deletion_requested_at) is the
    # truth; the Redis flag set in api/routers/user.py::delete_account
    # (and cleared by /user/account/restore) only caches it — a missing
    # flag sends the gate to the row (see _deletion_requested). Two
    # endpoints opt out via `get_current_user_including_deleted` so the
    # user can still restore + export their data while locked out of
    # everything else.
    if await _deletion_requested(user.id):
        raise HTTPException(
            status_code=410,
            detail={
                "error": "Account is scheduled for deletion.",
                "restore_url": "/api/v1/user/account/restore",
            },
        )

    # Unlinked device gate (Redis marker, the devices row when Redis is down).
    # Called directly from Python (get_optional_user, tests) the parameter
    # holds FastAPI's Header() default instead of a string — ignored then.
    await _refuse_revoked_device(user.id, x_device_id if isinstance(x_device_id, str) else None)

    # Attach context to Sentry's request-scoped scope so any subsequent
    # error within this request is pre-tagged with the authenticated
    # user_id + tier. Triage in Sentry without this would require
    # correlating by request_id manually. We deliberately DO NOT pass
    # `email` — privacy invariant + our own data-scrubbing config
    # already strips it.
    try:
        import sentry_sdk

        sentry_sdk.set_user(
            {"id": user.id, "tier": user.tier.value if hasattr(user.tier, "value") else str(user.tier)}
        )
    except Exception:
        # Sentry isn't configured in dev / tests — silent.
        pass

    return user


async def get_recently_authenticated_user(
    user: AuthUser = Depends(get_current_user),
) -> AuthUser:
    """get_current_user + a token issued at most RECENT_AUTH_MAX_AGE_S ago.

    For actions a stolen, older token must not be able to take: deleting the
    account, minting the browser extension a long-lived session of its own."""
    try:
        require_recent_auth(user)
    except HTTPException:
        await security_alerts.record("reauth_required", key=user.id)
        raise
    return user


async def get_current_user_including_deleted(
    authorization: Optional[str] = Header(None),
) -> AuthUser:
    """Like get_current_user but does NOT enforce the soft-delete lock.

    Intended for the narrow set of endpoints that a soft-deleted user
    must still reach:
      - POST /api/v1/user/account/restore  (the way out of the lock)
      - GET  /api/v1/user/export           (GDPR Art. 15 — they still
                                            have the right to access)

    Identical JWT path to get_current_user (shared via
    _decode_jwt_and_resolve) — only the soft-delete + Sentry-context
    layering is skipped. (Audit backend MEDIUM "JWT decode logic is
    fully duplicated between get_current_user and
    get_current_user_including_deleted".)
    """
    return await _decode_jwt_and_resolve(authorization)


async def get_optional_user(
    authorization: Optional[str] = Header(None),
    x_device_id: Optional[str] = Header(None, alias="X-Device-Id", include_in_schema=False),
) -> Optional[AuthUser]:
    """Same as get_current_user but returns None for unauthenticated requests
    (an unlinked device counts as unauthenticated here)."""
    if not authorization:
        return None
    try:
        return await get_current_user(
            authorization, x_device_id if isinstance(x_device_id, str) else None
        )
    except HTTPException:
        return None


async def get_current_user_no_disposable(
    authorization: Optional[str] = Header(None),
    x_device_id: Optional[str] = Header(None, alias="X-Device-Id", include_in_schema=False),
) -> AuthUser:
    """`get_current_user` plus a domain check against the disposable
    blocklist (mailinator, 10minutemail, …).

    The /signup landing form already pre-flights via /auth/check-email,
    but anyone with our public Supabase anon key can call signInWithOtp
    directly and bypass that. This dependency is the second layer:
    even with a forged session, calls to expensive endpoints (think
    /check, which fans out to Google Safe Browsing + IPQS + half a
    dozen other paid providers) get refused before they burn quota.

    Paid users with disposable addresses are vanishingly rare (you don't
    pay $9/mo from a mailinator inbox), so we don't bother carving an
    exception for tier > free. If a real customer ever hits this,
    support email path stays open via /unsubscribe / /settings which
    use plain `get_current_user` so they can still update their address.
    """
    user = await get_current_user(
        authorization, x_device_id if isinstance(x_device_id, str) else None
    )
    # Lazy import — keeps the module-level import graph small for
    # tests that stub auth without loading the 5400-domain blocklist.
    from api.services.email_validator import is_disposable_email

    if user.email and is_disposable_email(user.email):
        logger.warning(
            "disposable_email_blocked_at_endpoint",
            extra={"user_id": user.id, "domain": user.email.rsplit("@", 1)[-1]},
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error": (
                    "Free-tier checks aren't available for disposable / "
                    "throwaway email addresses. Update your account to a "
                    "real email or contact support."
                ),
                "support_url": "https://cleanway.ai/support",
            },
        )
    return user


async def _resolve_user_tier(user_id: str) -> UserTier:
    """
    Look up user's subscription tier.
    1. Check Redis cache (tier:{user_id})
    2. If miss, query Supabase subscriptions table
    3. Cache result for 5 minutes
    4. Fallback to free tier if DB unavailable
    """
    from api.services.cache import get_redis

    # 1. Check Redis cache
    try:
        r = await get_redis()
        cached_tier = await r.get(f"tier:{user_id}")
        if cached_tier:
            return UserTier(cached_tier)
    except Exception:
        pass

    # 2. Query Supabase
    tier = await _fetch_tier_from_supabase(user_id)

    # 3. Cache the result
    try:
        r = await get_redis()
        await r.setex(f"tier:{user_id}", _TIER_CACHE_TTL, tier.value)
    except Exception:
        pass

    return tier


async def _fetch_tier_from_supabase(user_id: str) -> UserTier:
    """
    Query Supabase for user's active subscription tier.
    Returns free tier if no active subscription or on error.
    """
    import httpx

    settings = get_settings()

    if not settings.supabase_url or not supabase_keys.server_key(settings):
        logger.debug("Supabase not configured — defaulting to free tier")
        return UserTier.free

    try:
        # We grant paid tier on BOTH `active` AND `past_due`. Stripe sends
        # `past_due` while it's retrying a failed payment (typical dunning
        # window is 1-2 weeks); revoking the user's tier instantly on the
        # first declined card is hostile UX. If the retry cycle fails,
        # Stripe eventually sends `customer.subscription.deleted` which our
        # webhook maps to status='cancelled' — the user falls to free
        # naturally at that point.
        #
        # order=created_at.desc + limit=1: when a user has historical
        # cancelled rows alongside a current row, pick the most recent.
        # Otherwise the unordered query could return any row and a stale
        # cancelled row would override a fresh active subscription.
        url = (
            f"{settings.supabase_url}/rest/v1/subscriptions"
            f"?user_id=eq.{user_id}"
            f"&status=in.(active,past_due)"
            f"&select=tier"
            f"&order=created_at.desc"
            f"&limit=1"
        )
        headers = {
            **supabase_keys.server_headers(settings),
        }

        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                if data and len(data) > 0:
                    tier_str = data[0].get("tier", "free")
                    try:
                        return UserTier(tier_str)
                    except ValueError:
                        logger.warning("Unknown tier value: %s", tier_str)
                        return UserTier.free

        return await _tier_from_entitlements(user_id)

    except Exception as e:
        logger.warning("supabase_tier_lookup_failed", extra={"error": str(e)})
        return UserTier.free  # Safe fallback


async def _tier_from_entitlements(user_id: str) -> UserTier:
    """Plans paid outside Stripe (Google Play / App Store via RevenueCat,
    later RuStore, the operator, promo) exist only in `entitlements`
    (migration 023 step 2): without this a store purchase would show as
    paid on the account screen yet keep free limits everywhere else."""
    from api.services.entitlements import get_effective_entitlement

    try:
        ent = await get_effective_entitlement(user_id, legacy_row=None)
        if ent.is_paid:
            return UserTier(ent.plan)
        return UserTier.free
    except Exception as e:  # EntitlementError, or a plan name UserTier doesn't know
        logger.warning("entitlement_tier_lookup_failed", extra={"error": str(e)})
        return UserTier.free  # same safe fallback as the subscriptions lookup
