"""PromoProvider — manual grants: support, partners, the first cohort.

No money moves. A checkout is "granted" at once and the service records a
synthetic success; renewals are not initiated (a promo has a fixed end);
there are no webhooks (every parse is an InvalidSignature); refunds are
no-ops. Everything a promo does is visible in `billing_audit`.
"""
from __future__ import annotations

import hashlib
import time
from typing import Any, Mapping, Optional, Sequence

from api.billing.providers.base import BillingEvent, CheckoutStart, EventKind, InvalidSignature


class PromoProvider:
    code = "promo"
    initiates_renewals = False

    async def start_checkout(self, *, plan_product_id: str, amount_kopecks: int, msisdn: Optional[str],
                             idempotency_key: str, return_url: str) -> CheckoutStart:
        ref = f"promo_{hashlib.sha256(idempotency_key.encode()).hexdigest()[:16]}"
        return CheckoutStart(kind="granted", provider_ref=ref)

    async def charge_renewal(self, *, provider_subscription_id: str, amount_kopecks: int, idempotency_key: str) -> str:
        raise NotImplementedError("a promo grant has a fixed end and is never renewed")

    async def cancel(self, *, provider_subscription_id: str) -> None:
        return None

    async def refund(self, *, provider_payment_id: str, amount_kopecks: int, idempotency_key: str) -> None:
        return None

    def parse_webhook(self, headers: Mapping[str, str], body: bytes) -> Sequence[BillingEvent]:
        raise InvalidSignature("the promo provider has no webhooks")

    def ack_body(self) -> Mapping[str, Any]:
        return {"success": True}

    async def fetch_status(self, *, provider_ref: Optional[str] = None,
                           merchant_payment_id: Optional[str] = None) -> Optional[BillingEvent]:
        return granted_event(provider_ref) if provider_ref else None


def granted_event(provider_ref: str, *, amount_kopecks: int = 0) -> BillingEvent:
    """The synthetic 'paid' event the service applies right after a promo checkout."""
    return BillingEvent(
        provider=PromoProvider.code, provider_event_id=f"{provider_ref}:granted", kind=EventKind.PAYMENT_SUCCEEDED,
        occurred_at=time.time(), provider_subscription_id=provider_ref, provider_payment_id=f"{provider_ref}:grant",
        amount_kopecks=amount_kopecks,
    )
