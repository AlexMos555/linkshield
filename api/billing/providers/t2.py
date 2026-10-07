"""T2DirectProvider — a stub until T2 shares its mobile-commerce documentation.

Every method raises NotConfiguredError. The class exists so the interface
contract is tested now (tests/billing/test_providers.py) and the real
integration is a drop-in later. The T2 "option" model (T2 charges, we
issue licence codes) does not go through this adapter at all: see
`api/billing/partner.py`.
"""
from __future__ import annotations

from typing import Any, Mapping, Optional, Sequence

from api.billing.providers.base import BillingEvent, CheckoutStart, NotConfiguredError

_MESSAGE = "T2 direct mobile commerce is not integrated yet (no documentation, no contract)"


class T2DirectProvider:
    code = "t2_direct"
    initiates_renewals = True

    async def start_checkout(self, *, plan_product_id: str, amount_kopecks: int, msisdn: Optional[str],
                             idempotency_key: str, return_url: str) -> CheckoutStart:
        raise NotConfiguredError(_MESSAGE)

    async def charge_renewal(self, *, provider_subscription_id: str, amount_kopecks: int, idempotency_key: str) -> str:
        raise NotConfiguredError(_MESSAGE)

    async def cancel(self, *, provider_subscription_id: str) -> None:
        raise NotConfiguredError(_MESSAGE)

    async def refund(self, *, provider_payment_id: str, amount_kopecks: int, idempotency_key: str) -> None:
        raise NotConfiguredError(_MESSAGE)

    def parse_webhook(self, headers: Mapping[str, str], body: bytes) -> Sequence[BillingEvent]:
        raise NotConfiguredError(_MESSAGE)

    def ack_body(self) -> Mapping[str, Any]:
        return {"result": "ok"}

    async def fetch_status(self, *, provider_ref: Optional[str] = None,
                           merchant_payment_id: Optional[str] = None) -> Optional[BillingEvent]:
        raise NotConfiguredError(_MESSAGE)
