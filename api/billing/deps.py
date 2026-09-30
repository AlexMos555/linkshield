"""FastAPI plumbing for /billing/v1: context, device auth, limits, idempotency, envelope."""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

from api.billing.context import BillingContext
from api.billing.models import Device, IdempotentResponse
from api.billing.service.devices import authenticate
from api.billing.service.errors import BillingError, Invalid
from api.services.rate_limiter import _extract_client_ip, check_install_rate_limit, check_ip_rate_limit

logger = logging.getLogger("cleanway.billing.api")

APP_VERSION_HEADER = "X-Cleanway-App-Version"
IDEMPOTENCY_HEADER = "Idempotency-Key"
_MAX_IDEMPOTENCY_KEY = 128
_HOUR = 3600

_context: Optional[BillingContext] = None
_context_lock = asyncio.Lock()


# ── Context ──


def install_context(ctx: Optional[BillingContext]) -> None:
    """Tests (and the mount) put the context here; None clears it."""
    global _context
    _context = ctx


async def get_context() -> BillingContext:
    """The runtime context, built on first use from settings when nothing was installed."""
    global _context
    if _context is not None:
        return _context
    async with _context_lock:
        if _context is None:
            from api.billing.bootstrap import build_runtime_context

            _context = await build_runtime_context()
    return _context


async def close_context() -> None:
    global _context
    if _context is not None:
        await _context.store.close()
        _context = None


# ── Envelope ──


def ok(data: Any) -> Dict[str, Any]:
    return {"success": True, "data": data, "error": None}


def fail(code: str, message: str) -> Dict[str, Any]:
    return {"success": False, "data": None, "error": {"code": code, "message": message}}


def register_error_handlers(app: FastAPI) -> None:
    async def _billing_error(_: Request, exc: BillingError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=fail(exc.code, exc.message))

    app.add_exception_handler(BillingError, _billing_error)


# ── Device auth ──


def _bearer(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    return token.strip() if scheme.lower() == "bearer" and token.strip() else None


async def current_device(
    authorization: Optional[str] = Header(default=None),
    x_cleanway_app_version: Optional[str] = Header(default=None),
) -> Device:
    ctx = await get_context()
    version = (x_cleanway_app_version or "")[:32] or None
    return await authenticate(ctx, _bearer(authorization), app_version=version)


# ── Rate limits (Redis-backed, shared limiter; fail-open in dev, fail-closed in prod) ──


def client_ip(request: Request) -> str:
    return _extract_client_ip(request)


async def limit_ip(request: Request, category: str, per_hour: int, window: int = _HOUR) -> None:
    await check_ip_rate_limit(client_ip(request), f"billing:{category}", per_hour, window)


async def limit_key(key: str, category: str, per_hour: int, window: int = _HOUR) -> None:
    await check_install_rate_limit(key, f"billing:{category}", per_hour, window)


def ip_limit(category: str, setting: str) -> Callable:
    """A per-IP dependency whose limit is the named field of the context's settings."""
    async def dep(request: Request) -> None:
        ctx = await get_context()
        await limit_ip(request, category, getattr(ctx.settings, setting))

    return dep


# ── Idempotency (plan A.6) ──


def idempotency_key(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    key = value.strip()
    if not key or len(key) > _MAX_IDEMPOTENCY_KEY:
        raise Invalid("Idempotency-Key must be 1..128 characters", code="idempotency_key_invalid")
    return key


async def idempotent(ctx: BillingContext, *, scope: str, key: Optional[str], status_code: int,
                     compute: Callable[[], Awaitable[Dict[str, Any]]]) -> Tuple[int, Dict[str, Any]]:
    """Replay the stored answer for a repeated key; otherwise compute and store it."""
    if key is None:
        return status_code, ok(await compute())
    async with ctx.store.transaction() as tx:
        stored = await tx.get_idempotent_response(scope, key)
    if stored is not None:
        return stored.status_code, dict(stored.body)
    body = ok(await compute())
    async with ctx.store.transaction() as tx:
        await tx.put_idempotent_response(IdempotentResponse(scope=scope, key=key, status_code=status_code, body=body,
                                                            created_at=ctx.now()))
    return status_code, body
