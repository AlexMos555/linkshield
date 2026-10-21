"""Which Supabase API key the backend uses, and how it is sent.

Supabase has two generations of API keys:

* legacy JWT keys — ``anon`` and ``service_role`` (``eyJ…``), signed with the
  project's legacy HS256 secret. Sent as ``apikey`` and also as
  ``Authorization: Bearer``;
* new keys — ``sb_publishable_…`` (replaces anon) and ``sb_secret_…``
  (replaces service_role). They are NOT JWTs: they go in the ``apikey``
  header only. Supabase tolerates one in ``Authorization`` only when it is
  byte-identical to ``apikey`` and recommends leaving that header out (or
  putting a user's JWT there). A secret key acts as ``service_role``.

The legacy HS256 secret can be revoked only once nothing uses the legacy
keys, so every server-side call goes through this module: it prefers
``SUPABASE_SECRET_KEY`` over ``SUPABASE_SERVICE_KEY`` and builds headers from
the key's shape (not from the variable name — an ``sb_secret_`` value pasted
into the old variable works too). Runbook:
docs/runbooks/supabase-jwt-signing-keys.md.
"""
from __future__ import annotations

import base64
import json
import os
from typing import Any, Literal, Optional

SECRET_PREFIX = "sb_secret_"
PUBLISHABLE_PREFIX = "sb_publishable_"
_NEW_KEY_PREFIX = "sb_"

KeyKind = Literal[
    "secret",
    "publishable",
    "legacy_service_role",
    "legacy_anon",
    "legacy_jwt",
    "unknown",
    "missing",
]


def _clean(value: Any) -> str:
    # Non-strings (a MagicMock settings attribute in tests) are "not set".
    return value.strip() if isinstance(value, str) else ""


def _jwt_role(key: str) -> Optional[str]:
    """The ``role`` claim of an unverified JWT, or None if unreadable.

    Only used to tell an anon key from a service_role one — never to trust
    anything.
    """
    parts = key.split(".")
    if len(parts) != 3:
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, TypeError):
        return None
    role = claims.get("role") if isinstance(claims, dict) else None
    return role if isinstance(role, str) else None


def is_jwt(key: str) -> bool:
    return _clean(key).startswith("eyJ")


def key_kind(key: Any) -> KeyKind:
    k = _clean(key)
    if not k:
        return "missing"
    if k.startswith(SECRET_PREFIX):
        return "secret"
    if k.startswith(PUBLISHABLE_PREFIX):
        return "publishable"
    if is_jwt(k):
        role = _jwt_role(k)
        if role == "service_role":
            return "legacy_service_role"
        if role == "anon":
            return "legacy_anon"
        return "legacy_jwt"
    return "unknown"


def _settings(settings: Any) -> Any:
    if settings is not None:
        return settings
    from api.config import get_settings

    return get_settings()


def server_key(settings: Any = None) -> str:
    """The server (service-role) key: SUPABASE_SECRET_KEY, else the legacy one."""
    s = _settings(settings)
    return _clean(getattr(s, "supabase_secret_key", "")) or _clean(
        getattr(s, "supabase_service_key", "")
    )


def server_key_from_env() -> str:
    """Same preference, read straight from the environment (for modules
    that do not go through Settings)."""
    return _clean(os.environ.get("SUPABASE_SECRET_KEY", "")) or _clean(
        os.environ.get("SUPABASE_SERVICE_KEY", "")
    )


def public_key(settings: Any = None) -> str:
    """The public key: SUPABASE_PUBLISHABLE_KEY, else the legacy anon key."""
    s = _settings(settings)
    return _clean(getattr(s, "supabase_publishable_key", "")) or _clean(
        getattr(s, "supabase_anon_key", "")
    )


def api_key_headers(key: str, **extra: str) -> dict[str, str]:
    """Headers that authenticate with ``key``.

    A legacy key is also sent as ``Authorization: Bearer`` (what the legacy
    gateway expects — kept for anything that is not an ``sb_`` key); an
    ``sb_`` key never is. ``extra`` may carry a user's own
    ``Authorization: Bearer <user JWT>``, which is kept.
    """
    k = _clean(key)
    headers: dict[str, str] = {"apikey": k}
    if k and not k.startswith(_NEW_KEY_PREFIX):
        headers["Authorization"] = f"Bearer {k}"
    headers.update(extra)
    return headers


def server_headers(settings: Any = None, **extra: str) -> dict[str, str]:
    """Service-role headers for PostgREST / GoTrue admin / Storage calls."""
    return api_key_headers(server_key(settings), **extra)


async def probe_server_key(settings: Any = None, timeout: float = 2.0) -> dict[str, Any]:
    """Does the server key act as service_role? (for /health/deep)

    The Auth admin API answers 200 only to a service-role caller, so one
    ``GET /auth/v1/admin/users?per_page=1`` proves the key works where the
    backend needs it most (account deletion, extension sessions). The
    response body is discarded; the result names the key's kind, never the
    key.
    """
    s = _settings(settings)
    key = server_key(s)
    kind = key_kind(key)
    base = _clean(getattr(s, "supabase_url", "")).rstrip("/")
    if not key or not base:
        return {"ok": False, "kind": kind, "error": "not_configured"}
    import httpx

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(
                f"{base}/auth/v1/admin/users",
                params={"page": 1, "per_page": 1},
                headers=api_key_headers(key),
            )
    except Exception as e:  # noqa: BLE001 — reported, never raised
        return {"ok": False, "kind": kind, "error": type(e).__name__}
    return {"ok": resp.status_code == 200, "kind": kind, "status": resp.status_code}


def validate(settings: Any) -> list[str]:
    """Problems with the configured keys (empty list = fine).

    Only clearly wrong combinations: a public key where a server key belongs
    (every server write would fail RLS), a server key where a public one
    belongs, or a value in SUPABASE_SECRET_KEY / SUPABASE_PUBLISHABLE_KEY
    that does not have that variable's prefix. Messages name variables and
    kinds, never values.
    """
    problems: list[str] = []
    secret = _clean(getattr(settings, "supabase_secret_key", ""))
    service = _clean(getattr(settings, "supabase_service_key", ""))
    publishable = _clean(getattr(settings, "supabase_publishable_key", ""))
    anon = _clean(getattr(settings, "supabase_anon_key", ""))

    if secret and key_kind(secret) != "secret":
        problems.append(
            f"SUPABASE_SECRET_KEY must be a secret key (starts with {SECRET_PREFIX}); "
            f"got a {key_kind(secret)} key."
        )
    if service and key_kind(service) in ("publishable", "legacy_anon"):
        problems.append(
            f"SUPABASE_SERVICE_KEY holds a public ({key_kind(service)}) key, not a "
            "server key — use the sb_secret_ key (SUPABASE_SECRET_KEY) or the "
            "legacy service_role key."
        )
    if publishable and key_kind(publishable) != "publishable":
        problems.append(
            f"SUPABASE_PUBLISHABLE_KEY must start with {PUBLISHABLE_PREFIX}; "
            f"got a {key_kind(publishable)} key."
        )
    if anon and key_kind(anon) in ("secret", "legacy_service_role"):
        problems.append(
            f"SUPABASE_ANON_KEY holds a server ({key_kind(anon)}) key — it must be "
            "the public anon / sb_publishable_ key."
        )
    return problems
