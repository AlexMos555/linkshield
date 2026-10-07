"""What an account is entitled to: plan, status, device limit.

docs/ACCOUNTS_BILLING_PLAN.md §1 + §5. Every way of paying writes a row to
`entitlements` (migration 023); the effective entitlement of an account is
its BEST ACTIVE row — most devices first, then the latest end date. No
active row means the free plan.

Device limits (config, see api/config.py):
  * paid  — the row's device_limit = PLAN_INCLUDED_DEVICES (3) + bought extras
  * free  — FREE_ACCOUNT_DEVICE_LIMIT (2) devices per signed-in free account.
            Free use needs no account at all; this only caps how many
            installs share one free account.

Transition (migration plan in 023): the Stripe webhook writes BOTH
`subscriptions` (legacy, still read by the tier resolver) and
`entitlements`. Until every paid row has been backfilled/rewritten, a paid
legacy `subscriptions` row with no entitlement row of its own still counts
as an active Stripe entitlement — nobody who paid loses their plan because
the migration ran a little later than the deploy.

Writers for the other sources are TODO hooks (`record_entitlement` is the
single entry point they will call):
  * google_play / app_store — RevenueCat webhook (not built; §2)
  * rustore, operator_ru    — api/billing linking an operator subscription
                              to an account (not built; §7.3)
  * promo, partner          — admin tooling (not built)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from api.config import get_settings
from api.services import account_store
from api.services.account_store import AccountStoreError

logger = logging.getLogger("cleanway.entitlements")

SOURCES = ("stripe", "google_play", "app_store", "rustore", "operator_ru", "promo", "partner")
STATUSES = (
    "active", "trialing", "past_due", "pending", "paused", "cancelled", "expired", "refunded",
)
# Statuses that grant the plan. past_due = Stripe is retrying a failed card;
# the old tier resolver kept access during dunning too.
ACTIVE_STATUSES = frozenset({"active", "trialing", "past_due"})

# Stripe subscription status → entitlement status.
STRIPE_STATUS_MAP = {
    "active": "active",
    "trialing": "trialing",
    "past_due": "past_due",
    "incomplete": "pending",
    "paused": "paused",
    "unpaid": "expired",
    "incomplete_expired": "expired",
    "canceled": "cancelled",
}

_UNSET: Any = object()


class EntitlementError(Exception):
    """The entitlement store failed; the caller must not assume "free"."""


@dataclass(frozen=True)
class Entitlement:
    plan: str
    # active | trialing | past_due for a paid plan, "free" without one.
    status: str
    source: Optional[str]
    external_id: Optional[str]
    period_end: Optional[str]
    device_limit: int

    @property
    def is_paid(self) -> bool:
        return self.source is not None


def included_devices() -> int:
    return max(1, int(get_settings().plan_included_devices))


def free_device_limit() -> int:
    return max(1, int(get_settings().free_account_device_limit))


def free_entitlement() -> Entitlement:
    return Entitlement(
        plan="free",
        status="free",
        source=None,
        external_id=None,
        period_end=None,
        device_limit=free_device_limit(),
    )


def _parse_ts(value: Any) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def row_is_active(row: dict, now: Optional[datetime] = None) -> bool:
    """Active status and not past its end date (+ the grace window). No end
    date = open-ended (a promo, or a Stripe row before its first period)."""
    if row.get("status") not in ACTIVE_STATUSES:
        return False
    end = _parse_ts(row.get("period_end"))
    if end is None:
        return True
    now = now or datetime.now(timezone.utc)
    grace = timedelta(hours=max(0, int(get_settings().entitlement_grace_hours)))
    return end + grace > now


def _row_limit(row: dict) -> int:
    try:
        return max(1, int(row.get("device_limit") or included_devices()))
    except (TypeError, ValueError):
        return included_devices()


def effective_entitlement(rows: list[dict], now: Optional[datetime] = None) -> Entitlement:
    """The best active row, or free. Best = most devices, then the end date
    furthest away (open-ended beats any date)."""
    active = [r for r in rows if row_is_active(r, now)]
    if not active:
        return free_entitlement()

    far_future = datetime.max.replace(tzinfo=timezone.utc)

    def rank(r: dict) -> tuple:
        return (_row_limit(r), _parse_ts(r.get("period_end")) or far_future)

    best = max(active, key=rank)
    return Entitlement(
        plan=str(best.get("plan") or "personal"),
        status=str(best["status"]),
        source=str(best.get("source")),
        external_id=best.get("external_id"),
        period_end=best.get("period_end"),
        device_limit=_row_limit(best),
    )


def _legacy_entitlement(row: Optional[dict], rows: list[dict]) -> Optional[Entitlement]:
    """A paid `subscriptions` row the entitlements table doesn't know yet."""
    from api.services.stripe_billing import has_paid_subscription

    if not has_paid_subscription(row):
        return None
    sub_id = row.get("provider_subscription_id")
    if sub_id and any(r.get("source") == "stripe" and r.get("external_id") == sub_id for r in rows):
        # The webhook already wrote this subscription's entitlement; that row
        # (active or not) is the truth, not the legacy copy.
        return None
    return Entitlement(
        plan=str(row.get("tier") or "personal"),
        status=str(row.get("status") or "active"),
        source="stripe",
        external_id=sub_id,
        period_end=row.get("current_period_end"),
        device_limit=included_devices(),
    )


async def get_effective_entitlement(account_id: str, *, legacy_row: Any = _UNSET) -> Entitlement:
    """The account's effective entitlement. Raises EntitlementError when the
    store (or the legacy lookup) fails — never a silent "free".

    `legacy_row`: the caller's already-fetched `subscriptions` row (checkout
    has it), to save a round trip; omitted → fetched here."""
    store = account_store.get_account_store()
    rows: list[dict] = []
    # No database configured (local dev): nobody has paid — the same default
    # stripe_billing.fetch_subscription_row uses. A configured store that
    # fails is an error, never "free".
    if store is not None:
        try:
            rows = await store.list_entitlements(account_id)
        except AccountStoreError as e:
            raise EntitlementError(str(e)) from e
    rows = [r for r in rows if r.get("source") in SOURCES]

    best = effective_entitlement(rows)
    if best.is_paid:
        return best

    if legacy_row is _UNSET:
        from api.services.stripe_billing import BillingError, fetch_subscription_row

        try:
            legacy_row = await fetch_subscription_row(user_id=account_id)
        except BillingError as e:
            raise EntitlementError(str(e)) from e
    legacy = _legacy_entitlement(legacy_row, rows)
    return legacy or best


async def has_active_entitlement(account_id: str, *, legacy_row: Any = _UNSET) -> Optional[Entitlement]:
    """The account's active paid entitlement from ANY source, or None.

    The double-payment guard: every way of paying asks this before taking
    money (Stripe checkout today; Play / App Store / RuStore / operator when
    they are wired). Raises EntitlementError when it can't tell."""
    best = await get_effective_entitlement(account_id, legacy_row=legacy_row)
    return best if best.is_paid else None


# ── writers ──


async def record_entitlement(
    *,
    account_id: str,
    source: str,
    external_id: str,
    status: str,
    plan: Optional[str] = None,
    period_end: Optional[str] = None,
    device_limit: Optional[int] = None,
) -> None:
    """Create or update the (source, external_id) row. Fields left as None
    keep their stored value on update (plan defaults to 'personal' and
    device_limit to PLAN_INCLUDED_DEVICES on insert). Raises EntitlementError."""
    if source not in SOURCES:
        raise ValueError(f"unknown entitlement source: {source}")
    if status not in STATUSES:
        raise ValueError(f"unknown entitlement status: {status}")
    if not external_id:
        raise ValueError("external_id is required")
    store = account_store.get_account_store()
    if store is None:
        raise EntitlementError("account store not configured")

    row: dict[str, Any] = {
        "account_id": account_id,
        "source": source,
        "external_id": external_id,
        "status": status,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    if plan:
        row["plan"] = plan
    if period_end:
        row["period_end"] = period_end
    if device_limit is not None:
        row["device_limit"] = max(1, int(device_limit))
    try:
        await store.upsert_entitlement(row)
    except AccountStoreError as e:
        raise EntitlementError(str(e)) from e
    logger.info(
        "entitlement_recorded",
        extra={"account_id": account_id, "source": source, "status": status, "plan": plan},
    )


async def end_source_entitlements(*, account_id: str, source: str, status: str = "cancelled") -> None:
    """Mark every row of one source of an account as ended (e.g. the Stripe
    customer was deleted, so none of its subscriptions can bill again)."""
    store = account_store.get_account_store()
    if store is None:
        raise EntitlementError("account store not configured")
    try:
        await store.set_entitlements_status(account_id=account_id, source=source, status=status)
    except AccountStoreError as e:
        raise EntitlementError(str(e)) from e


def stripe_status(stripe_subscription_status: Optional[str]) -> str:
    """Unknown Stripe statuses grant nothing."""
    return STRIPE_STATUS_MAP.get(stripe_subscription_status or "", "expired")


def stripe_device_limit(subscription: Any) -> int:
    """Included devices + the quantity of the "extra device" price, when
    STRIPE_PRICE_EXTRA_DEVICE is configured and on the subscription."""
    from api.services.stripe_billing import field, object_id

    extra_price = get_settings().stripe_price_extra_device
    extras = 0
    if extra_price:
        for item in field(field(subscription, "items"), "data") or []:
            price = field(item, "price") or field(item, "plan")
            if object_id(price) == extra_price:
                try:
                    extras += max(0, int(field(item, "quantity") or 0))
                except (TypeError, ValueError):
                    pass
    return included_devices() + extras
