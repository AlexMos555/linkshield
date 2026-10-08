"""Store product ids (Google Play, App Store) → what they sell.

docs/runbooks/revenuecat.md lists what to create in Play Console, App Store
Connect and RevenueCat. Two kinds of product:

  * PLAN products — the device plan (api/services/pricing.py): a paid plan
    covering PLAN_INCLUDED_DEVICES devices, plus `extra_devices` when the
    product is a bundle ("plan with 5 devices").
  * ADD-ON products — "+N devices" sold as their own subscription. They
    never grant the plan by themselves; while active they add their devices
    to the account's plan (entitlements.ADDON_PLAN rows).

Google Play subscriptions created since 2023 reach RevenueCat as
"<subscription id>:<base plan id>" (e.g. "cleanway.devices:monthly"); a
lookup falls back to the subscription id, so one entry covers every base
plan of a subscription.

The defaults below are the ids the runbook tells the founder to create.
REVENUECAT_PRODUCTS (JSON) adds or overrides entries without a deploy:

  {"cleanway.devices.family": {"plan": "personal", "extra_devices": 2},
   "cleanway.extra_devices_3": {"extra_devices": 3}}

An entry with "plan" is a plan product; one without is an add-on.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Optional

from api.config import get_settings

logger = logging.getLogger("cleanway.store_products")

# Plans a store product may grant (subscriptions.tier / UserTier values).
PLANS = ("personal", "family", "business")
MAX_EXTRA_DEVICES = 20


@dataclass(frozen=True)
class StoreProduct:
    # The plan granted, or None for an extra-device add-on.
    plan: Optional[str]
    extra_devices: int = 0

    @property
    def is_addon(self) -> bool:
        return self.plan is None


_PLAN = StoreProduct(plan="personal", extra_devices=0)
_ONE_EXTRA = StoreProduct(plan=None, extra_devices=1)

DEFAULT_PRODUCTS: dict[str, StoreProduct] = {
    # Google Play: one subscription per kind, base plans "monthly"/"yearly".
    "cleanway.devices": _PLAN,
    "cleanway.extra_device": _ONE_EXTRA,
    # App Store (and Play products created as one id per period).
    "cleanway.devices.monthly": _PLAN,
    "cleanway.devices.yearly": _PLAN,
    "cleanway.extra_device.monthly": _ONE_EXTRA,
    "cleanway.extra_device.yearly": _ONE_EXTRA,
}


def _parse_entry(product_id: str, raw: object) -> StoreProduct:
    if not isinstance(raw, dict):
        raise ValueError(f"{product_id}: entry must be an object")
    extra = raw.get("extra_devices", 0)
    if not isinstance(extra, int) or isinstance(extra, bool) or not 0 <= extra <= MAX_EXTRA_DEVICES:
        raise ValueError(f"{product_id}: extra_devices must be an integer 0..{MAX_EXTRA_DEVICES}")
    plan = raw.get("plan")
    if plan is None:
        if extra < 1:
            raise ValueError(f"{product_id}: an add-on must add at least one device")
        return StoreProduct(plan=None, extra_devices=extra)
    if plan not in PLANS:
        raise ValueError(f"{product_id}: plan must be one of {', '.join(PLANS)}")
    return StoreProduct(plan=plan, extra_devices=extra)


def parse_products(raw_json: str) -> dict[str, StoreProduct]:
    """REVENUECAT_PRODUCTS → entries. Raises ValueError on a bad value."""
    data = json.loads(raw_json)
    if not isinstance(data, dict):
        raise ValueError("REVENUECAT_PRODUCTS must be a JSON object")
    return {str(pid): _parse_entry(str(pid), entry) for pid, entry in data.items()}


def products() -> dict[str, StoreProduct]:
    """The defaults merged with REVENUECAT_PRODUCTS. A malformed override is
    logged and ignored as a whole (the defaults keep selling)."""
    table = dict(DEFAULT_PRODUCTS)
    raw = (get_settings().revenuecat_products or "").strip()
    if raw:
        try:
            table.update(parse_products(raw))
        except ValueError as e:  # json.JSONDecodeError is a ValueError
            logger.error("revenuecat_products_invalid", extra={"error": str(e)})
    return table


def lookup(product_id: Optional[str]) -> Optional[StoreProduct]:
    """The product behind a store product id, or None when it isn't ours."""
    if not product_id:
        return None
    table = products()
    if product_id in table:
        return table[product_id]
    subscription_id = product_id.split(":", 1)[0]
    return table.get(subscription_id)
