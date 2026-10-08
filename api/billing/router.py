"""/billing/v1 — the phone-billing API (plan A.6). Mounted only by the billing role.

Every response is the project envelope {success, data, error}. Nothing here
takes an e-mail or a password: a device authenticates with the secret it
received at registration, the payer is the account that started the
checkout, and a phone number appears only in the checkout and
cancel-by-phone bodies (encrypted at rest, never logged).
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from api.billing import partner as partner_service
from api.billing.deps import (
    IDEMPOTENCY_HEADER,
    client_ip,
    current_device,
    fail,
    get_context,
    idempotency_key,
    idempotent,
    ip_limit,
    limit_ip,
    limit_key,
    ok,
)
from api.billing.crypto import InvalidMsisdn, normalize_msisdn
from api.billing.models import Device
from api.billing.providers.registry import checkout_providers
from api.billing.service import cancel as cancel_service
from api.billing.service import checkout as checkout_service
from api.billing.service import devices as device_service
from api.billing.service import seats as seat_service
from api.billing.service import trial as trial_service
from api.billing.service.passes import compute_entitlement
from api.billing.service.webhooks import MAX_WEBHOOK_BODY_BYTES, ingest_webhook

router = APIRouter(prefix="/billing/v1", tags=["billing"])

_MINUTE = 60
_DAY = 24 * 3600


# ── Request models ──


class RegisterDeviceRequest(BaseModel):
    platform: str = Field(..., pattern=r"^(android|ios)$")
    app_version: Optional[str] = Field(default=None, max_length=32)
    legacy_claim: bool = False


class TrialRequest(BaseModel):
    fingerprint: str = Field(..., min_length=1, max_length=256)


class CheckoutRequest(BaseModel):
    plan_code: str = Field(..., pattern=r"^(solo|family3|family5)$")
    provider: str = Field(..., min_length=1, max_length=32)
    msisdn: Optional[str] = Field(default=None, max_length=32)
    consent_doc_version: str = Field(..., min_length=1, max_length=32)
    consent_method: str = Field(default="app_button", pattern=r"^[a-z_]{1,32}$")


class ClaimRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=6)


class CancelByPhoneRequest(BaseModel):
    msisdn: str = Field(..., min_length=10, max_length=32)


def _entitlement_payload(entitlement) -> Dict[str, Any]:
    return {"token": entitlement.token, "claims": entitlement.claims.to_payload(), "status": entitlement.status}


def _phone_limit_key(ctx, raw: Optional[str]) -> Optional[str]:
    """The per-phone limit counts the normalised number; an unparsable one is the service's 400."""
    if not raw:
        return None
    try:
        return ctx.hasher.msisdn(normalize_msisdn(raw))
    except InvalidMsisdn:
        return None


# ── Devices, trial, entitlement, plans ──


@router.post("/devices", status_code=201)
async def register_device(body: RegisterDeviceRequest, request: Request,
                          _limit: None = Depends(ip_limit("register", "billing_register_per_ip_per_hour"))):
    ctx = await get_context()
    device, secret = await device_service.register_device(
        ctx, platform=body.platform, app_version=body.app_version, legacy_claim=body.legacy_claim,
    )
    return ok({"device_id": device.id, "device_secret": secret, "legacy_free": device.legacy_free})


@router.post("/trial")
async def start_trial(body: TrialRequest, device: Device = Depends(current_device)):
    ctx = await get_context()
    trial = await trial_service.start_trial(ctx, device, fingerprint_input=body.fingerprint)
    entitlement = await compute_entitlement(ctx, device)
    return ok({"trial": {"started_at": int(trial.started_at.timestamp()), "ends_at": int(trial.ends_at.timestamp())},
               **_entitlement_payload(entitlement)})


@router.get("/entitlement")
async def get_entitlement(device: Device = Depends(current_device)):
    ctx = await get_context()
    return ok(_entitlement_payload(await compute_entitlement(ctx, device)))


@router.get("/plans")
async def list_plans(request: Request, _limit: None = Depends(ip_limit("plans", "billing_register_per_ip_per_hour"))):
    ctx = await get_context()
    s = ctx.settings
    return ok({
        "currency": "RUB",
        "plans": [{"code": p.code.value, "seats": p.seats, "price_kopecks": p.price_kopecks,
                   "price_rub": p.price_kopecks // 100, "period": p.period} for p in ctx.plans()],
        "trial_days": s.billing_trial_days, "grace_days": s.billing_grace_days, "lapse_policy": s.billing_lapse_policy,
        "consent_doc_version": s.billing_consent_doc_version, "providers": list(checkout_providers(ctx.providers)),
        "billing_ru_enabled": s.billing_enabled,
    })


# ── Checkout ──


@router.post("/checkout")
async def start_checkout(body: CheckoutRequest, request: Request, device: Device = Depends(current_device),
                         idem: Optional[str] = Header(default=None, alias=IDEMPOTENCY_HEADER)):
    ctx = await get_context()
    s = ctx.settings
    await limit_key(device.id, "checkout:device", s.billing_checkout_per_device_per_hour)
    phone_key = _phone_limit_key(ctx, body.msisdn)
    if phone_key:
        await limit_key(phone_key, "checkout:phone", s.billing_checkout_per_phone_per_hour)

    async def compute() -> Dict[str, Any]:
        return await checkout_service.start_checkout(
            ctx, device, plan_code=body.plan_code, provider_code=body.provider, msisdn=body.msisdn,
            consent_doc_version=body.consent_doc_version, consent_method=body.consent_method,
            ip=request.client.host if request.client else None,
        )

    status, payload = await idempotent(ctx, scope=device.id, key=idempotency_key(idem), status_code=201, compute=compute)
    return JSONResponse(status_code=status, content=payload)


@router.get("/checkout/{checkout_id}")
async def get_checkout(checkout_id: str, device: Device = Depends(current_device)):
    ctx = await get_context()
    return ok(await checkout_service.get_checkout(ctx, device, checkout_id))


# ── Cancel ──


@router.post("/subscription/cancel")
async def cancel_subscription(device: Device = Depends(current_device)):
    ctx = await get_context()
    return ok(await cancel_service.cancel_subscription(ctx, device))


@router.post("/cancel-by-phone")
async def cancel_by_phone(body: CancelByPhoneRequest, request: Request,
                          _limit: None = Depends(ip_limit("cancel_by_phone", "billing_cancel_by_phone_per_ip_per_hour"))):
    ctx = await get_context()
    # Nobody can prove owning the number here yet (the aggregator documents no SMS-sending API
    # for a one-time code — docs/BILLING.md, open question): the number itself is limited strictly.
    phone_key = _phone_limit_key(ctx, body.msisdn)
    if phone_key:
        await limit_key(phone_key, "cancel_by_phone:phone", ctx.settings.billing_cancel_by_phone_per_phone_per_day, _DAY)
    await cancel_service.cancel_by_phone(ctx, msisdn=body.msisdn, ip=request.client.host if request.client else None)
    # The same answer whether or not the number had a subscription (no enumeration).
    return ok({"message": "Если на этом номере была подписка, она отменена. Больше ничего не спишется."})


# ── Seats and claim codes ──


@router.post("/subscription/codes", status_code=201)
async def create_claim_code(device: Device = Depends(current_device),
                            idem: Optional[str] = Header(default=None, alias=IDEMPOTENCY_HEADER)):
    ctx = await get_context()

    async def compute() -> Dict[str, Any]:
        return await seat_service.create_claim_code(ctx, device)

    status, payload = await idempotent(ctx, scope=device.id, key=idempotency_key(idem), status_code=201, compute=compute)
    return JSONResponse(status_code=status, content=payload)


@router.post("/claim")
async def claim_seat(body: ClaimRequest, request: Request, device: Device = Depends(current_device)):
    ctx = await get_context()
    s = ctx.settings
    await limit_key(device.id, "claim:device", s.billing_claim_attempts_per_device_per_hour)
    await limit_ip(request, "claim", s.billing_claim_attempts_per_ip_per_hour)
    return ok(await seat_service.redeem_claim_code(ctx, device, code=body.code))


@router.get("/subscription/devices")
async def list_devices(device: Device = Depends(current_device)):
    ctx = await get_context()
    return ok(await seat_service.list_devices(ctx, device))


@router.delete("/subscription/seats/{device_id}")
async def remove_seat(device_id: str, device: Device = Depends(current_device)):
    ctx = await get_context()
    await seat_service.remove_seat(ctx, device, device_id=device_id)
    return ok({"removed": device_id})


# ── Webhooks ──


@router.post("/webhooks/{provider}")
async def provider_webhook(provider: str, request: Request):
    ctx = await get_context()
    await limit_ip(request, "webhooks", ctx.settings.billing_webhooks_per_ip_per_minute, _MINUTE)
    body = await request.body()
    if len(body) > MAX_WEBHOOK_BODY_BYTES:
        return JSONResponse(status_code=413, content=fail("too_large", "webhook body too large"))
    status, payload = await ingest_webhook(ctx, provider_code=provider, headers=dict(request.headers), body=body,
                                           ip=client_ip(request))
    return JSONResponse(status_code=status, content=payload)


# ── Partner licences (T2 "option" model) ──


@router.post("/partner/licenses", status_code=201)
async def create_partner_license(request: Request, response: Response):
    ctx = await get_context()
    await limit_ip(request, "partner", ctx.settings.billing_register_per_ip_per_hour)
    body = await request.body()
    partner_service.verify_partner_signature(ctx.settings.billing_partner_hmac_key, dict(request.headers), body)
    req = partner_service.parse_partner_request(body)
    return ok(await partner_service.create_partner_license(ctx, **req))
