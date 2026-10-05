"""Billing domain records — immutable dataclasses mirroring the billing schema.

One frozen dataclass per table in `api/billing/migrations/001_billing_schema.sql`.
Nothing here talks to a database; the store (`api/billing/store/`) maps
these to rows. Changes are made with `dataclasses.replace`, never in place.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Mapping, Optional


class PlanCode(str, Enum):
    SOLO = "solo"
    FAMILY3 = "family3"
    FAMILY5 = "family5"


class ProviderCode(str, Enum):
    FAKE = "fake"
    PROMO = "promo"
    MIXPLAT = "mixplat"
    RUSTORE = "rustore"
    T2_DIRECT = "t2_direct"
    T2_OPTION = "t2_option"


class SubscriptionStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    GRACE = "grace"
    CANCEL_AT_PERIOD_END = "cancel_at_period_end"
    LAPSED = "lapsed"
    REFUNDED = "refunded"


class PaymentStatus(str, Enum):
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REFUNDED = "refunded"
    PARTIALLY_REFUNDED = "partially_refunded"


class FailureReason(str, Enum):
    NO_MONEY = "no_money"
    PAYMENTS_BANNED = "payments_banned"
    PASSPORT = "passport"
    CORPORATE = "corporate"
    USER_DECLINED = "user_declined"
    TIMEOUT = "timeout"
    OTHER = "other"


class CancelChannel(str, Enum):
    APP = "app"
    WEB = "web"
    SUPPORT = "support"
    OPERATOR_STOP = "operator_stop"
    PROVIDER = "provider"


class ConsentKind(str, Enum):
    SUBSCRIPTION_OFFER = "subscription_offer"
    PLAN_CHANGE = "plan_change"
    PD_PROCESSING = "pd_processing"
    CANCEL = "cancel"


class ClaimPurpose(str, Enum):
    SEAT = "seat"
    OWNER_TRANSFER = "owner_transfer"
    PARTNER_LICENSE = "partner_license"


class SeatRole(str, Enum):
    OWNER = "owner"
    MEMBER = "member"


class ProtectionMode(str, Enum):
    """What the phone's native protection does. Carried in the device pass."""
    FULL = "full"
    BASIC = "basic"
    OFF = "off"


class EntitlementSource(str, Enum):
    SUBSCRIPTION = "subscription"
    TRIAL = "trial"
    LEGACY = "legacy"
    PROMO = "promo"
    NONE = "none"


class LapsePolicy(str, Enum):
    BASIC = "basic"
    OFF = "off"

    @property
    def mode(self) -> ProtectionMode:
        return ProtectionMode.BASIC if self is LapsePolicy.BASIC else ProtectionMode.OFF


@dataclass(frozen=True)
class Plan:
    code: PlanCode
    version: int
    seats: int
    price_kopecks: int
    period: str = "P1M"
    provider_product_ids: Mapping[str, str] = field(default_factory=dict)
    active: bool = True


@dataclass(frozen=True)
class Account:
    id: str
    created_at: datetime
    display_label: Optional[str] = None


@dataclass(frozen=True)
class Device:
    id: str
    account_id: str
    secret_sha256: str
    platform: str
    created_at: datetime
    app_version: Optional[str] = None
    legacy_free: bool = False
    last_seen: Optional[datetime] = None


@dataclass(frozen=True)
class Trial:
    device_fingerprint_hmac: str
    device_id: str
    started_at: datetime
    ends_at: datetime


@dataclass(frozen=True)
class Subscription:
    id: str
    payer_account_id: str
    plan_code: PlanCode
    plan_version: int
    provider: ProviderCode
    status: SubscriptionStatus
    created_at: datetime
    updated_at: datetime
    provider_subscription_id: Optional[str] = None
    current_period_start: Optional[datetime] = None
    current_period_end: Optional[datetime] = None
    grace_until: Optional[datetime] = None
    next_charge_at: Optional[datetime] = None
    cancel_requested_at: Optional[datetime] = None
    cancel_channel: Optional[CancelChannel] = None
    msisdn_ciphertext: Optional[bytes] = None
    msisdn_hmac: Optional[str] = None
    operator: Optional[str] = None
    # Renewal bookkeeping for the state machine (see state_machine.SubState).
    attempt: int = 0
    charge_pending: bool = False
    row_version: int = 0


@dataclass(frozen=True)
class Seat:
    subscription_id: str
    device_id: str
    role: SeatRole
    claimed_at: datetime
    released_at: Optional[datetime] = None


@dataclass(frozen=True)
class ClaimCode:
    id: str
    subscription_id: str
    code_hmac: str
    purpose: ClaimPurpose
    expires_at: datetime
    redeemed_at: Optional[datetime] = None
    redeemed_by_device: Optional[str] = None


@dataclass(frozen=True)
class Payment:
    id: str
    subscription_id: str
    provider: ProviderCode
    idempotency_key: str
    amount_kopecks: int
    status: PaymentStatus
    created_at: datetime
    provider_payment_id: Optional[str] = None
    failure_reason: Optional[FailureReason] = None
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
    receipt_url: Optional[str] = None


@dataclass(frozen=True)
class BillingEventRow:
    """An inbound provider notification, stored before it is applied."""
    id: int
    provider: ProviderCode
    provider_event_id: str
    received_at: datetime
    signature_ok: bool
    payload_ciphertext: bytes
    processed_at: Optional[datetime] = None
    outcome: Optional[str] = None


@dataclass(frozen=True)
class Consent:
    id: int
    account_id: str
    kind: ConsentKind
    doc_version: str
    doc_sha256: str
    method: str
    created_at: datetime
    subscription_id: Optional[str] = None
    shown_price_kopecks: Optional[int] = None
    shown_plan_code: Optional[PlanCode] = None
    provider_confirmation_ref: Optional[str] = None
    ip_hmac: Optional[str] = None


@dataclass(frozen=True)
class AuditRow:
    id: int
    actor: str
    action: str
    target: str
    created_at: datetime
    meta: Mapping[str, Any] = field(default_factory=dict)


IDEMPOTENCY_IN_PROGRESS = 0   # status_code of a reserved key whose request is still running


@dataclass(frozen=True)
class IdempotentResponse:
    """A stored API response, replayed for a repeated Idempotency-Key.

    The row is written (reserved) before the request's side effects run, with
    status_code IDEMPOTENCY_IN_PROGRESS, and completed with the answer after.
    """
    scope: str
    key: str
    status_code: int
    body: Mapping[str, Any]
    created_at: datetime

    @property
    def in_progress(self) -> bool:
        return self.status_code == IDEMPOTENCY_IN_PROGRESS
