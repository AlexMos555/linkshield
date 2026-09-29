"""Device registration and bearer authentication (plan A.6: POST /devices)."""
from __future__ import annotations

from typing import Optional, Tuple

from api.billing.context import BillingContext
from api.billing.crypto import generate_device_secret, sha256_hex
from api.billing.models import Device
from api.billing.service.errors import Invalid, Unauthorized

PLATFORMS = ("android", "ios")


async def register_device(ctx: BillingContext, *, platform: str, app_version: Optional[str],
                          legacy_claim: bool) -> Tuple[Device, str]:
    """A new account + device. The secret is returned once and stored as a hash.

    `legacy_claim` is the app's word that it was installed before the paid
    release (§2.3 grandfathering); the server cannot verify it and says so
    in the audit row.
    """
    if platform not in PLATFORMS:
        raise Invalid("platform must be android or ios")
    secret = generate_device_secret()
    async with ctx.store.transaction() as tx:
        account_id = await tx.create_account()
        device = await tx.create_device(
            account_id=account_id, secret_sha256=sha256_hex(secret), platform=platform,
            app_version=app_version, legacy_free=legacy_claim,
        )
        await tx.add_audit(
            actor=f"device:{device.id}", action="device.registered", target=f"device:{device.id}",
            meta={"platform": platform, "legacy_claim": legacy_claim, "legacy_verified": False},
        )
    return device, secret


async def authenticate(ctx: BillingContext, secret: Optional[str], *, app_version: Optional[str] = None) -> Device:
    """The device behind a bearer secret; touches last_seen."""
    if not secret or len(secret) > 128:
        raise Unauthorized("device secret required")
    async with ctx.store.transaction() as tx:
        device = await tx.get_device_by_secret_hash(sha256_hex(secret))
        if device is None:
            raise Unauthorized("unknown device")
        await tx.touch_device(device.id, seen_at=ctx.now(), app_version=app_version)
    return device
