"""Inbound provider webhooks (plan A.8): verify, store once, apply once, answer fast.

    1. parse_webhook checks the signature; a bad one is stored with
       signature_ok=false (so attacks are visible) and answered 400;
    2. INSERT … ON CONFLICT DO NOTHING on (provider, event id): a redelivery
       is answered 200 without a second effect;
    3. the state machine runs on the locked subscription row in the same
       transaction as the event row.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, Mapping, Tuple

from api.billing.context import BillingContext
from api.billing.providers.base import InvalidSignature, NotConfiguredError
from api.billing.service.checkout import apply_provider_event

logger = logging.getLogger("cleanway.billing.webhooks")

MAX_WEBHOOK_BODY_BYTES = 64 * 1024


def _error(status: int, code: str, message: str) -> Tuple[int, Dict[str, Any]]:
    return status, {"success": False, "data": None, "error": {"code": code, "message": message}}


async def ingest_webhook(ctx: BillingContext, *, provider_code: str, headers: Mapping[str, str],
                         body: bytes) -> Tuple[int, Dict[str, Any]]:
    provider = ctx.providers.get(provider_code)
    if provider is None:
        return _error(404, "unknown_provider", "unknown provider")
    if len(body) > MAX_WEBHOOK_BODY_BYTES:
        return _error(413, "too_large", "webhook body too large")
    try:
        events = provider.parse_webhook(headers, body)
    except InvalidSignature as e:
        await _store_rejected(ctx, provider_code, body, str(e))
        return _error(400, "invalid_signature", "signature verification failed")
    except NotConfiguredError:
        return _error(503, "not_configured", "provider not configured")
    outcomes = []
    for event in events:
        async with ctx.store.transaction() as tx:
            event_id = await tx.insert_event(
                provider=provider_code, provider_event_id=event.provider_event_id, signature_ok=True,
                payload_ciphertext=ctx.cipher.encrypt_bytes(body),
            )
            if event_id is None:
                outcomes.append("duplicate")
                continue
            _, outcome = await apply_provider_event(ctx, tx, event, actor=f"provider:{provider_code}")
            await tx.mark_event_processed(event_id, processed_at=ctx.now(), outcome=outcome)
            outcomes.append(outcome)
    logger.info("billing.webhook", extra={"provider": provider_code, "outcomes": outcomes})
    return 200, dict(provider.ack_body())


async def _store_rejected(ctx: BillingContext, provider_code: str, body: bytes, why: str) -> None:
    digest = hashlib.sha256(body).hexdigest()[:32]
    async with ctx.store.transaction() as tx:
        await tx.insert_event(provider=provider_code, provider_event_id=f"rejected:{digest}", signature_ok=False,
                              payload_ciphertext=ctx.cipher.encrypt_bytes(body))
        await tx.add_audit(actor=f"provider:{provider_code}", action="webhook.rejected", target=f"provider:{provider_code}",
                           meta={"why": why[:120]})
