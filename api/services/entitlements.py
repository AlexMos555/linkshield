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

Writers (`record_entitlement` is the single entry point):
  * stripe                  — the Stripe webhook (api/routers/payments.py)
  * google_play / app_store — the RevenueCat webhook and "Restore purchases"
                              (api/services/revenuecat.py, §11)
  * rustore, operator_ru    — api/billing linking an operator subscription
                              to an account (not built; §7.3)
  * promo, partner          — admin tooling (not built)

Extra-device ADD-ONS (a store sells "+1 device" as its own subscription):
a row with plan = ADDON_PLAN whose device_limit is the number of EXTRA
devices it adds. It never grants a plan by itself; while active it adds its
devices to the best plan row (any source).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import urlencode

from api.config import get_settings
from api.services import account_store
from api.services.account_store import AccountStoreError

logger = logging.getLogger("cleanway.entitlements")

SOURCES = ("stripe", "google_play", "app_store", "rustore", "operator_ru", "promo", "partner")
STATUSES = (
    "active", "trialing", "past_due", "pending", "paused", "cancelled", "expired", "refunded",
)
# Plan of an extra-device add-on row (see the module docstring).
ADDON_PLAN = "extra_devices"
# entitlements.device_limit is capped at 100 (migration 023).
MAX_DEVICE_LIMIT = 100

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
    # Store product the plan was bought as (google_play / app_store rows).
    product_id: Optional[str] = None

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


def is_addon(row: dict) -> bool:
    return row.get("plan") == ADDON_PLAN


def _addon_extras(row: dict) -> int:
    try:
        return max(0, int(row.get("device_limit") or 0))
    except (TypeError, ValueError):
        return 0


def effective_entitlement(rows: list[dict], now: Optional[datetime] = None) -> Entitlement:
    """The best active plan row, or free. Best = most devices, then the end
    date furthest away (open-ended beats any date). Active extra-device
    add-ons add their devices to it; add-ons alone grant nothing."""
    active = [r for r in rows if row_is_active(r, now)]
    plans = [r for r in active if not is_addon(r)]
    if not plans:
        return free_entitlement()

    far_future = datetime.max.replace(tzinfo=timezone.utc)

    def rank(r: dict) -> tuple:
        return (_row_limit(r), _parse_ts(r.get("period_end")) or far_future)

    best = max(plans, key=rank)
    extras = sum(_addon_extras(r) for r in active if is_addon(r))
    return Entitlement(
        plan=str(best.get("plan") or "personal"),
        status=str(best["status"]),
        source=str(best.get("source")),
        external_id=best.get("external_id"),
        period_end=best.get("period_end"),
        device_limit=min(MAX_DEVICE_LIMIT, _row_limit(best) + extras),
        product_id=best.get("product_id"),
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


#: Where a paid plan is managed (changed / cancelled), by source. The app
#: and the site send the person there: a plan paid through Google Play can
#: only be cancelled in Google Play, and so on.
ACCOUNT_PAGE_URL = "https://cleanway.ai/account"
PLAY_SUBSCRIPTIONS_URL = "https://play.google.com/store/account/subscriptions"
APP_STORE_SUBSCRIPTIONS_URL = "https://apps.apple.com/account/subscriptions"


def manage_url(ent: Entitlement) -> Optional[str]:
    """Link to where this plan is managed, or None (free, or a source with
    no self-service page: operator, promo, partner)."""
    if ent.source == "stripe":
        # The account page carries the "Manage or cancel" button that opens
        # the Stripe Customer Portal (POST /api/v1/payments/portal).
        return ACCOUNT_PAGE_URL
    if ent.source == "google_play":
        package = get_settings().google_play_package_name
        # Play products since 2023 are "<subscription id>:<base plan id>";
        # Play's deep link wants the subscription id as `sku`.
        sku = (ent.product_id or "").split(":", 1)[0]
        if package and sku:
            return f"{PLAY_SUBSCRIPTIONS_URL}?{urlencode({'sku': sku, 'package': package})}"
        return PLAY_SUBSCRIPTIONS_URL
    if ent.source == "app_store":
        return APP_STORE_SUBSCRIPTIONS_URL
    return None


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
    product_id: Optional[str] = None,
    source_event_at: Optional[str] = None,
) -> None:
    """Create or update the (source, external_id) row. Fields left as None
    keep their stored value on update (plan defaults to 'personal' and
    device_limit to PLAN_INCLUDED_DEVICES on insert). `product_id` and
    `source_event_at` need migration 024. Raises EntitlementError."""
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
        row["device_limit"] = min(MAX_DEVICE_LIMIT, max(1, int(device_limit)))
    if product_id:
        row["product_id"] = product_id
    if source_event_at:
        row["source_event_at"] = source_event_at
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
    """Included devices + the quantity of the "extra device" items: any
    tier's STRIPE_PRICE_EXTRA_DEVICE_T{n}_{INTERVAL} (api/services/pricing.py),
    or the single STRIPE_PRICE_EXTRA_DEVICE configured before the tiers."""
    from api.services.pricing import is_extra_device_price
    from api.services.stripe_billing import field, object_id

    legacy_extra_price = get_settings().stripe_price_extra_device
    extras = 0
    for item in field(field(subscription, "items"), "data") or []:
        price_id = object_id(field(item, "price") or field(item, "plan"))
        if is_extra_device_price(price_id) or (legacy_extra_price and price_id == legacy_extra_price):
            try:
                extras += max(0, int(field(item, "quantity") or 0))
            except (TypeError, ValueError):
                pass
    return included_devices() + extras
