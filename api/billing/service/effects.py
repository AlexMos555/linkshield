"""Execute the effects `apply()` returns, inside the caller's transaction.

Charge, DeleteSubscription and NewSubscription are structural and handled
by the caller (scheduler / checkout); everything else — audit rows, consent
proofs, provider cancel, mode changes, notifications — is done here.
Notifications are local on the phone (plan A.8), derived from the pass, so
a Notify effect becomes an audit row that proves what the person was told.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional, Sequence

from api.billing.consents import ConsentDoc
from api.billing.context import BillingContext
from api.billing.models import Consent, ConsentKind, Plan, Subscription
from api.billing.providers.base import ProviderError
from api.billing.service.common import sub_target
from api.billing.state_machine import (
    Audit,
    CancelAtProvider,
    Effect,
    Notify,
    RecordConsent,
    SetDeviceMode,
)

logger = logging.getLogger("cleanway.billing.effects")


@dataclass(frozen=True)
class ConsentInfo:
    """What was on the screen when the person agreed (plan A.9)."""
    doc: ConsentDoc
    plan: Optional[Plan] = None
    ip_hmac: Optional[str] = None
    provider_confirmation_ref: Optional[str] = None


async def run_effects(ctx: BillingContext, tx, sub: Subscription, effects: Sequence[Effect], *, actor: str,
                      consent: Optional[ConsentInfo] = None) -> None:
    target = sub_target(sub.id)
    for effect in effects:
        if isinstance(effect, Audit):
            await tx.add_audit(actor=actor, action=effect.action, target=target, meta=dict(effect.meta))
        elif isinstance(effect, Notify):
            meta = {"reason": effect.reason.value} if effect.reason else {}
            await tx.add_audit(actor="system", action=f"notify.{effect.kind}", target=target, meta=meta)
        elif isinstance(effect, RecordConsent):
            await _record_consent(ctx, tx, sub, effect, consent)
        elif isinstance(effect, CancelAtProvider):
            await _cancel_at_provider(ctx, tx, sub, actor)
        elif isinstance(effect, SetDeviceMode):
            await tx.add_audit(actor="system", action=f"device_mode.{effect.mode.value}", target=target, meta={})


async def _record_consent(ctx: BillingContext, tx, sub: Subscription, effect: RecordConsent,
                          consent: Optional[ConsentInfo]) -> None:
    if consent is None:
        # A cancel has no screen text of its own: the proof is the channel and time, under the offer version in force.
        from api.billing.consents import load_consent_doc

        consent = ConsentInfo(doc=load_consent_doc(ctx.settings.billing_consent_doc_version))
    plan = consent.plan
    await tx.add_consent(Consent(
        id=0, account_id=sub.payer_account_id, subscription_id=sub.id, kind=effect.kind, doc_version=consent.doc.version,
        doc_sha256=consent.doc.sha256, method=effect.method, created_at=ctx.now(),
        shown_price_kopecks=plan.price_kopecks if plan and effect.kind is not ConsentKind.CANCEL else None,
        shown_plan_code=plan.code if plan else None, provider_confirmation_ref=consent.provider_confirmation_ref,
        ip_hmac=consent.ip_hmac,
    ))


async def _cancel_at_provider(ctx: BillingContext, tx, sub: Subscription, actor: str) -> None:
    """Best effort: a cancel must never fail for the person because a provider is down."""
    provider = ctx.providers.get(sub.provider.value)
    if provider is None or not sub.provider_subscription_id:
        return
    try:
        await provider.cancel(provider_subscription_id=sub.provider_subscription_id)
    except (ProviderError, Exception) as e:  # noqa: BLE001 — recorded, retried by ops
        logger.warning("billing.provider_cancel_failed", extra={"provider": sub.provider.value, "error": type(e).__name__})
        await tx.add_audit(actor=actor, action="provider.cancel_failed", target=sub_target(sub.id),
                           meta={"provider": sub.provider.value, "error": type(e).__name__})
