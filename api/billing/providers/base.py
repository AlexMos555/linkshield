"""Payment provider adapter interface (plan A.7).

Every way money can reach us — an aggregator (MIXPLAT), RuStore Pay, T2
directly, a promo grant — implements `BillingProvider`. The service layer
never knows which; it starts a checkout, may charge a renewal, cancels,
refunds, parses signed webhooks into `BillingEvent`s, and asks for a
status during reconciliation.

Adapters must be deterministic and side-effect free except for the HTTP
calls they exist to make; every request carries an idempotency key.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Optional, Protocol, Sequence, runtime_checkable

from api.billing.models import FailureReason


class EventKind(str, Enum):
    PAYMENT_SUCCEEDED = "payment_succeeded"
    PAYMENT_FAILED = "payment_failed"
    PAYMENT_PENDING = "payment_pending"
    SUBSCRIPTION_CANCELLED = "subscription_cancelled"   # STOP SMS, operator cabinet, RuStore
    REFUNDED = "refunded"


@dataclass(frozen=True)
class BillingEvent:
    """One provider notification, normalised. `provider_event_id` deduplicates."""
    provider: str
    provider_event_id: str
    kind: EventKind
    occurred_at: float
    provider_subscription_id: Optional[str] = None
    provider_payment_id: Optional[str] = None
    merchant_payment_id: Optional[str] = None
    amount_kopecks: Optional[int] = None
    failure: Optional[FailureReason] = None
    # Test-mode payments must never activate a production subscription.
    test: bool = False


@dataclass(frozen=True)
class CheckoutStart:
    """How the payer continues: a redirect URL, an SDK, a USSD code, or an SMS."""
    kind: str                         # "redirect" | "sdk" | "ussd" | "await_sms" | "granted"
    provider_ref: str
    url: Optional[str] = None
    sdk_params: Optional[Mapping[str, str]] = None


class ProviderError(Exception):
    """Base for adapter failures the service reports honestly."""


class InvalidSignature(ProviderError):
    """The webhook is not from the provider; it is recorded and NOT applied."""


class NotConfiguredError(ProviderError):
    """The adapter has no credentials (or no contract yet)."""


class ProviderUnavailable(ProviderError):
    """Network or provider-side failure; safe to retry with the same idempotency key."""


@runtime_checkable
class BillingProvider(Protocol):
    code: str
    # True: we charge renewals on our schedule (scheduler.run_renewals).
    # False: the provider charges and tells us through webhooks.
    initiates_renewals: bool

    async def start_checkout(
        self, *, plan_product_id: str, amount_kopecks: int, msisdn: Optional[str],
        idempotency_key: str, return_url: str,
    ) -> CheckoutStart: ...

    async def charge_renewal(
        self, *, provider_subscription_id: str, amount_kopecks: int, idempotency_key: str,
    ) -> str: ...   # → provider_payment_id

    async def cancel(self, *, provider_subscription_id: str) -> None: ...

    async def refund(self, *, provider_payment_id: str, amount_kopecks: int, idempotency_key: str) -> None: ...

    def parse_webhook(self, headers: Mapping[str, str], body: bytes) -> Sequence[BillingEvent]: ...

    def ack_body(self) -> Mapping[str, Any]: ...   # what the provider expects back for a handled webhook

    async def fetch_status(self, *, provider_ref: str) -> Optional[BillingEvent]: ...


PROVIDER_METHODS = (
    "start_checkout", "charge_renewal", "cancel", "refund", "parse_webhook", "ack_body", "fetch_status",
)
