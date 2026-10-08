"""The signed-in account: plan and linked devices.

  GET    /api/v1/me/entitlement      plan, status, source, period_end,
                                     device_limit, devices_used, devices
  GET    /api/v1/me/devices          linked devices
  POST   /api/v1/me/devices          register this install / heartbeat (idempotent)
  PATCH  /api/v1/me/devices/{id}     rename a device
  DELETE /api/v1/me/devices/{id}     unlink a device

docs/ACCOUNTS_BILLING_PLAN.md §1, §5. The app registers itself right after
sign-in and heartbeats on start; the account screens (app + /account on the
website) read the entitlement. Error answers carry a stable `code`:

  409 device_limit_reached  — no free seat; `devices` lists the linked ones
                              so the client can offer "unlink one" or "add a
                              device" right there
  403 device_revoked        — this install was unlinked; sign out locally
  404 device_not_found
  503 account_unavailable   — the database couldn't answer; retry later
"""
from __future__ import annotations

import logging
from typing import Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from pydantic import BaseModel, Field

from api.models.schemas import AuthUser
from api.services import account_devices as devices_svc
from api.services.account_devices import (
    DeviceLimitReached,
    DeviceNotFound,
    DeviceRevoked,
    StoreUnavailable,
)
from api.services.auth import get_current_user
from api.services.entitlements import Entitlement, included_devices
from api.services.rate_limiter import rate_limit

logger = logging.getLogger("cleanway.account")

router = APIRouter(prefix="/api/v1/me", tags=["account"])

# Per user per hour. Separate buckets from the daily check quota: opening
# the account screen must never cost a free user one of their checks.
_READ_LIMIT = 60
_REGISTER_LIMIT = 30
_MANAGE_LIMIT = 20


class DeviceOut(BaseModel):
    id: str
    platform: str
    name: Optional[str] = None
    app_version: Optional[str] = None
    created_at: Optional[str] = None
    last_seen_at: Optional[str] = None
    is_current: bool = False


class EntitlementResponse(BaseModel):
    plan: str = Field(..., description="'free', or the paid plan (personal / family / business).")
    status: str = Field(..., description="'free', or active / trialing / past_due.")
    source: Optional[str] = Field(
        None,
        description="Where the plan was paid: stripe, google_play, app_store, rustore, operator_ru, promo, partner.",
    )
    period_end: Optional[str] = None
    device_limit: int
    included_devices: int = Field(..., description="Devices a paid plan covers before extras.")
    devices_used: int
    devices: list[DeviceOut]


class DeviceRegisterRequest(BaseModel):
    device_id: str = Field(
        ...,
        min_length=16,
        max_length=128,
        pattern=r"^[A-Za-z0-9_-]+$",
        description="Random per-install id made by the client and kept in secure storage.",
    )
    platform: Literal["android", "ios", "extension", "web"]
    name: Optional[str] = Field(None, max_length=200, description="Device model or browser.")
    app_version: Optional[str] = Field(None, max_length=32)


class DeviceRegisterResponse(BaseModel):
    status: Literal["created", "updated"]
    device: DeviceOut
    entitlement: EntitlementResponse


class DeviceRenameRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)


def _unavailable(e: Exception) -> HTTPException:
    logger.error("account_store_unavailable", extra={"error": str(e)})
    return HTTPException(
        503,
        detail={
            "code": "account_unavailable",
            "error": "Your account can't be loaded just now. Please try again in a moment.",
        },
    )


def _views(rows: list[dict], current: Optional[str]) -> list[DeviceOut]:
    return [DeviceOut(**devices_svc.device_view(r, current)) for r in rows]


def _entitlement_body(ent: Entitlement, rows: list[dict], current: Optional[str]) -> EntitlementResponse:
    return EntitlementResponse(
        plan=ent.plan,
        status=ent.status,
        source=ent.source,
        period_end=ent.period_end,
        device_limit=ent.device_limit,
        included_devices=included_devices(),
        devices_used=len(rows),
        devices=_views(rows, current),
    )


async def _entitlement_view(user: AuthUser, current: Optional[str]) -> EntitlementResponse:
    try:
        ent = await devices_svc.load_entitlement(user.id)
        rows = await devices_svc.list_devices(user.id)
    except StoreUnavailable as e:
        raise _unavailable(e)
    return _entitlement_body(ent, rows, current)


@router.get(
    "/entitlement",
    response_model=EntitlementResponse,
    dependencies=[Depends(rate_limit(mode="sensitive", category="account_read", limit=_READ_LIMIT))],
)
async def get_entitlement(
    user: AuthUser = Depends(get_current_user),
    x_device_id: Optional[str] = Header(None, alias="X-Device-Id", include_in_schema=False),
) -> EntitlementResponse:
    """The account's effective plan and its linked devices."""
    return await _entitlement_view(user, x_device_id)


@router.get(
    "/devices",
    response_model=list[DeviceOut],
    dependencies=[Depends(rate_limit(mode="sensitive", category="account_read", limit=_READ_LIMIT))],
)
async def get_devices(
    user: AuthUser = Depends(get_current_user),
    x_device_id: Optional[str] = Header(None, alias="X-Device-Id", include_in_schema=False),
) -> list[DeviceOut]:
    try:
        rows = await devices_svc.list_devices(user.id)
    except StoreUnavailable as e:
        raise _unavailable(e)
    return _views(rows, x_device_id)


@router.post(
    "/devices",
    response_model=DeviceRegisterResponse,
    dependencies=[
        Depends(rate_limit(mode="sensitive", category="device_register", limit=_REGISTER_LIMIT))
    ],
)
async def register_device(
    body: DeviceRegisterRequest,
    response: Response,
    user: AuthUser = Depends(get_current_user),
) -> DeviceRegisterResponse:
    """Link this install to the account, or heartbeat it when already linked.

    Idempotent: the same device_id answers 200 'updated' every time after the
    first 201 'created'. A new device beyond the plan's device_limit gets 409
    device_limit_reached with the linked devices listed."""
    try:
        status, row, ent = await devices_svc.register(
            account_id=user.id,
            device_id=body.device_id,
            platform=body.platform,
            name=body.name,
            app_version=body.app_version,
            session_id=user.session_id,
        )
        rows = await devices_svc.list_devices(user.id)
    except DeviceRevoked:
        raise HTTPException(
            403,
            detail={
                "code": "device_revoked",
                "error": "This device was removed from your account. Sign in again to use it.",
            },
        )
    except DeviceLimitReached as e:
        raise HTTPException(
            409,
            detail={
                "code": "device_limit_reached",
                "error": (
                    f"Your plan covers {e.entitlement.device_limit} devices and all of them "
                    "are in use. Unlink one, or add a device to your plan."
                ),
                "plan": e.entitlement.plan,
                "device_limit": e.entitlement.device_limit,
                "devices_used": len(e.devices),
                "devices": [d.model_dump() for d in _views(e.devices, body.device_id)],
            },
        )
    except StoreUnavailable as e:
        raise _unavailable(e)

    if status == "created":
        response.status_code = 201
    return DeviceRegisterResponse(
        status=status,  # type: ignore[arg-type]
        device=DeviceOut(**devices_svc.device_view(row, body.device_id)),
        entitlement=_entitlement_body(ent, rows, body.device_id),
    )


@router.patch(
    "/devices/{device_id}",
    response_model=DeviceOut,
    dependencies=[Depends(rate_limit(mode="sensitive", category="device_manage", limit=_MANAGE_LIMIT))],
)
async def rename_device(
    device_id: str,
    body: DeviceRenameRequest,
    user: AuthUser = Depends(get_current_user),
    x_device_id: Optional[str] = Header(None, alias="X-Device-Id", include_in_schema=False),
) -> DeviceOut:
    try:
        row = await devices_svc.rename(account_id=user.id, device_row_id=device_id, name=body.name)
    except ValueError:
        raise HTTPException(422, detail={"code": "invalid_name", "error": "Enter a device name."})
    except DeviceNotFound:
        raise HTTPException(404, detail={"code": "device_not_found", "error": "No such device."})
    except StoreUnavailable as e:
        raise _unavailable(e)
    return DeviceOut(**devices_svc.device_view(row, x_device_id))


@router.delete(
    "/devices/{device_id}",
    response_model=EntitlementResponse,
    dependencies=[Depends(rate_limit(mode="sensitive", category="device_manage", limit=_MANAGE_LIMIT))],
)
async def unlink_device(
    device_id: str,
    user: AuthUser = Depends(get_current_user),
    x_device_id: Optional[str] = Header(None, alias="X-Device-Id", include_in_schema=False),
) -> EntitlementResponse:
    """Unlink a device: its seat frees up at once, its session ends, and its
    requests are refused with device_revoked. Answers with the updated
    entitlement so the screen re-renders without another round trip.
    Idempotent — unlinking an unlinked device answers the same."""
    try:
        await devices_svc.revoke(account_id=user.id, device_row_id=device_id)
    except DeviceNotFound:
        raise HTTPException(404, detail={"code": "device_not_found", "error": "No such device."})
    except StoreUnavailable as e:
        raise _unavailable(e)

    from api.services import audit_log

    await audit_log.write(
        action="device.unlinked",
        target_kind="device",
        target_id=device_id,
        actor_user_id=user.id,
    )
    return await _entitlement_view(user, x_device_id)
