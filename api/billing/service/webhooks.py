"""Inbound provider webhooks (plan A.8): verify, store once, apply once, answer fast.

    0. the source address is checked against BILLING_MIXPLAT_WEBHOOK_IPS when
       that allowlist is set (empty = off);
    1. parse_webhook checks the signature; a bad one is stored with
       signature_ok=false (so attacks are visible) and answered 400;
    2. a success from a provider whose signature does not cover the status and
       amount (MIXPLAT: md5 of payment_id only) is confirmed with the
       provider's own status call first; the confirmed amount and currency are
       then compared with our payment row before anything is extended;
    3. INSERT … ON CONFLICT DO NOTHING on (provider, event id): a redelivery
       is answered 200 without a second effect;
    4. the state machine runs on the locked subscription row in the same
       transaction as the event row. An event that matches no subscription is
       kept (outcome `unmatched`, normalised form encrypted) for the
       reconciler to retry, and logged at error level so Sentry raises it.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
from dataclasses import replace
from typing import Any, Dict, Mapping, Optional, Tuple

from api.billing.context import BillingContext
from api.billing.providers.base import (
    BillingEvent,
    EventKind,
    InvalidSignature,
    NotConfiguredError,
    ProviderError,
    event_to_bytes,
)
from api.billing.service.checkout import apply_provider_event

logger = logging.getLogger("cleanway.billing.webhooks")

MAX_WEBHOOK_BODY_BYTES = 64 * 1024
# Providers whose webhook source addresses BILLING_MIXPLAT_WEBHOOK_IPS restricts.
_ALLOWLISTED_PROVIDERS = ("mixplat",)


def _error(status: int, code: str, message: str) -> Tuple[int, Dict[str, Any]]:
    return status, {"success": False, "data": None, "error": {"code": code, "message": message}}


async def ingest_webhook(ctx: BillingContext, *, provider_code: str, headers: Mapping[str, str],
                         body: bytes, ip: Optional[str] = None) -> Tuple[int, Dict[str, Any]]:
    provider = ctx.providers.get(provider_code)
    if provider is None:
        return _error(404, "unknown_provider", "unknown provider")
    if len(body) > MAX_WEBHOOK_BODY_BYTES:
        return _error(413, "too_large", "webhook body too large")
    if not _source_allowed(ctx, provider_code, ip):
        logger.warning("billing.webhook.ip_rejected", extra={"provider": provider_code})
        async with ctx.store.transaction() as tx:
            await tx.add_audit(actor=f"provider:{provider_code}", action="webhook.ip_rejected",
                               target=f"provider:{provider_code}", meta={"ip_hmac": ctx.hasher.ip(ip) if ip else None})
        return _error(403, "ip_not_allowed", "webhook source not allowed")
    try:
        events = provider.parse_webhook(headers, body)
    except InvalidSignature as e:
        await _store_rejected(ctx, provider_code, body, str(e))
        return _error(400, "invalid_signature", "signature verification failed")
    except NotConfiguredError:
        return _error(503, "not_configured", "provider not configured")
    checked = []
    for event in events:
        try:
            checked.append(await _confirm_success(provider, event))
        except ProviderError as e:
            # Nothing is stored, so the provider's redelivery is processed in full; the
            # reconciler asks for the same status on its own if no redelivery comes.
            logger.warning("billing.webhook.confirmation_unavailable",
                           extra={"provider": provider_code, "error": type(e).__name__})
            return _error(503, "provider_unreachable", "could not confirm the payment, retry later")
    outcomes = []
    for event, confirmed in checked:
        async with ctx.store.transaction() as tx:
            event_id = await tx.insert_event(
                provider=provider_code, provider_event_id=event.provider_event_id, signature_ok=True,
                payload_ciphertext=ctx.cipher.encrypt_bytes(body),
                event_ciphertext=ctx.cipher.encrypt_bytes(event_to_bytes(event)),
            )
            if event_id is None:
                outcomes.append("duplicate")
                continue
            if confirmed:
                _, outcome = await apply_provider_event(ctx, tx, event, actor=f"provider:{provider_code}")
            else:
                outcome = "not_confirmed"
                logger.error("billing.webhook.not_confirmed",
                             extra={"provider": provider_code, "event": event.provider_event_id})
                await tx.add_audit(actor=f"provider:{provider_code}", action="webhook.not_confirmed",
                                   target=f"provider:{provider_code}", meta={"event": event.provider_event_id})
            await tx.mark_event_processed(event_id, processed_at=ctx.now(), outcome=outcome)
            outcomes.append(outcome)
        if outcome == "unmatched":
            # Money may have moved with nobody to give it to: a person must look (Sentry), and
            # the reconciler keeps trying (scheduler.run_unmatched_events).
            logger.error("billing.webhook.unmatched", extra={
                "provider": provider_code, "event": event.provider_event_id, "kind": event.kind.value,
            })
    logger.info("billing.webhook", extra={"provider": provider_code, "outcomes": outcomes})
    return 200, dict(provider.ack_body())


async def _confirm_success(provider, event: BillingEvent) -> Tuple[BillingEvent, bool]:
    """(event to apply, confirmed?). Only a success from a provider that asks for it is re-checked.

    The provider's status answer wins for status, amount and currency (the
    notification's signature did not cover them); the notification's own id
    is kept so a redelivery stays a duplicate.
    """
    if event.kind is not EventKind.PAYMENT_SUCCEEDED or not getattr(provider, "confirms_success_by_status", False):
        return event, True
    status = await provider.fetch_status(provider_ref=event.provider_payment_id,
                                         merchant_payment_id=event.merchant_payment_id)
    if status is None or status.kind is not EventKind.PAYMENT_SUCCEEDED:
        return event, False
    return replace(
        status,
        provider_event_id=event.provider_event_id,
        provider_payment_id=status.provider_payment_id or event.provider_payment_id,
        merchant_payment_id=status.merchant_payment_id or event.merchant_payment_id,
        # TODO(billing): confirm with the MIXPLAT manager that get_payment_status returns
        # recurrent_id; until then the notification's value is used when the status lacks it.
        provider_subscription_id=status.provider_subscription_id or event.provider_subscription_id,
        test=status.test or event.test,
    ), True


def _source_allowed(ctx: BillingContext, provider_code: str, ip: Optional[str]) -> bool:
    if provider_code not in _ALLOWLISTED_PROVIDERS:
        return True
    networks = ctx.settings.webhook_networks()
    if not networks:
        return True
    try:
        address = ipaddress.ip_address(ip or "")
    except ValueError:
        return False
    return any(address in network for network in networks)


async def _store_rejected(ctx: BillingContext, provider_code: str, body: bytes, why: str) -> None:
    digest = hashlib.sha256(body).hexdigest()[:32]
    async with ctx.store.transaction() as tx:
        await tx.insert_event(provider=provider_code, provider_event_id=f"rejected:{digest}", signature_ok=False,
                              payload_ciphertext=ctx.cipher.encrypt_bytes(body))
        await tx.add_audit(actor=f"provider:{provider_code}", action="webhook.rejected", target=f"provider:{provider_code}",
                           meta={"why": why[:120]})
