"""The free trial (§2.2): N days, no phone number, no consent, one per phone."""
from __future__ import annotations

from datetime import timedelta

from api.billing.context import BillingContext
from api.billing.models import Device, Trial
from api.billing.service.common import device_actor, live_subscription_for_device
from api.billing.service.errors import Conflict, Invalid
from api.billing.store.base import ConflictError

_MAX_FINGERPRINT_LEN = 256


async def start_trial(ctx: BillingContext, device: Device, *, fingerprint_input: str) -> Trial:
    """Start (or return) the trial for this phone.

    `fingerprint_input` is what the app derives from ANDROID_ID; only its
    HMAC is stored. The same phone reinstalling gets its original trial
    back (same dates), never a second one. A device already covered by a
    subscription seat does not get a trial — it is already paid for.
    """
    if not fingerprint_input or len(fingerprint_input) > _MAX_FINGERPRINT_LEN:
        raise Invalid("fingerprint required")
    fingerprint = ctx.hasher.fingerprint(fingerprint_input)
    now = ctx.now()
    async with ctx.store.transaction() as tx:
        if await live_subscription_for_device(tx, device.id) is not None:
            raise Conflict("this phone is covered by a subscription", code="already_subscribed")
        existing = await tx.get_trial_by_fingerprint(fingerprint)
        if existing is not None:
            if existing.device_id != device.id:
                raise Conflict("this phone already used its trial", code="trial_already_used")
            return existing
        trial = Trial(device_fingerprint_hmac=fingerprint, device_id=device.id, started_at=now,
                      ends_at=now + timedelta(days=ctx.settings.billing_trial_days))
        try:
            await tx.create_trial(trial)
        except ConflictError as e:
            raise Conflict("this phone already used its trial", code="trial_already_used") from e
        await tx.add_audit(actor=device_actor(device), action="trial.started", target=f"device:{device.id}",
                           meta={"days": ctx.settings.billing_trial_days})
    return trial
