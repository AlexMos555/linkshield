"""World pricing — one subscription that covers devices, one price everywhere.

Founder decisions (docs/ACCOUNTS_BILLING_PLAN.md §5): the subscription counts
devices, not people (2026-10-07); free = 5 manual site checks a month after a
7-day trial, and the plan costs $1.99 a month in every country (2026-11-04).

  * Free, forever: automatic protection (blocking known scam sites from the
    list, DNS, the link guard, the iPhone SMS filter) with no limit; 5 manual
    site checks a month after 7 days with everything unlocked (both are
    settings: FREE_MANUAL_CHECKS_PER_MONTH, FREE_UNLIMITED_DAYS_AFTER_INSTALL).
  * Paid: one plan — unlimited detailed checks on PLAN_INCLUDED_DEVICES (3)
    devices of one account, $1.99 a month or $19.99 a year, plus $0.49 a
    month for every device beyond the included ones.

A device is a phone, tablet or browser with the extension signed in to the
account (api/routers/account.py). Russia is not priced here: the operator-
billed subscription (api/billing) sells it in rubles.

The regional (PPP) tiers stay — same countries as before (migration 003
`get_pricing_tier()`) — but the plan no longer differs between them:

  | Tier | Who            | Monthly | Yearly | Extra device /mo | /yr   |
  |------|----------------|---------|--------|------------------|-------|
  | 1    | Premium        | $1.99   | $19.99 | $0.49            | $4.99 |
  | 2    | Base (default) | $1.99   | $19.99 | $0.49            | $4.99 |
  | 3    | Mid-emerging   | $1.99   | $19.99 | $0.49            | $3.49 |
  | 4    | Affordable     | $1.99   | $19.99 | $0.49            | $2.49 |

  * $1.99 a month is the founder's price in every country; the App Store and
    Google Play show their own local equivalent of the same price point.
  * Yearly $19.99 ≈ 10 × monthly ("≈ 2 months free"): the proposal in the PR
    of 2026-11-04 — drop the yearly plan instead by not creating it in the
    stores and Stripe; the app shows only what the store offers.
  * The extra device was not part of the 2026-11-04 decision and is not sold
    in the app yet: its prices (and their tier discount) are unchanged.

Every amount is integer cents (no float drift); USD floats are derived for
display. A change here is a change to scripts/create_stripe_prices.py too
(the script imports TIER_PRICES, so they cannot drift apart).
"""
from __future__ import annotations

import os as _os
from dataclasses import dataclass
from typing import Literal

# ─── Type definitions ──────────────────────────────────────────

Interval = Literal["monthly", "yearly"]
Tier = Literal[1, 2, 3, 4]

INTERVALS: tuple[Interval, ...] = ("monthly", "yearly")
TIERS: tuple[Tier, ...] = (1, 2, 3, 4)

#: The one paid plan. Checkout keys are "devices_monthly" / "devices_yearly".
PLAN_ID = "devices"
#: What the plan is stored as in subscriptions.tier and entitlements.plan.
#: subscriptions.tier has CHECK (tier IN ('free','personal','family','business'))
#: (migration 001) and every paid-tier check reads 'personal' as "paid", so the
#: device plan keeps that value instead of needing a migration.
STORED_TIER = "personal"
#: Checkout keys from before the device plan. A page cached with the old
#: script may still send "personal_monthly"; it buys the device plan.
#: "family_*" / "business_*" are no longer sold (400).
LEGACY_PLAN_ALIASES: frozenset[str] = frozenset({"personal"})

# ─── Free tier (founder decision §5, 2026-11-04) ───────────────
# Settings, not constants: FREE_MANUAL_CHECKS_PER_MONTH and
# FREE_UNLIMITED_DAYS_AFTER_INSTALL (api/config.py). The phone counts the
# checks (resets on the 1st, local time); /api/v1/pricing/for-country
# publishes the numbers the site and the app say out loud and enforce.
FREE_CHECKS_PERIOD = "month"


def free_manual_checks() -> int:
    from api.config import get_settings

    return get_settings().free_manual_checks_per_month


def free_unlimited_days() -> int:
    from api.config import get_settings

    return get_settings().free_unlimited_days_after_install

#: Free trial on the FIRST paid web subscription (Stripe Checkout), once per
#: account — subscriptions.trial_used_at, migration 021.
STRIPE_TRIAL_DAYS = 14

# ─── Country → Tier mapping ────────────────────────────────────
# Keep in sync with migration 003 SQL function `get_pricing_tier()`.

_TIER_1_COUNTRIES: frozenset[str] = frozenset({
    # North America + UK
    "US", "CA", "GB",
    # Western Europe (high GDP per capita)
    "DE", "FR", "NL", "NO", "SE", "CH", "DK", "FI", "AT", "BE", "IE", "LU", "IS",
    # Asia-Pacific premium
    "AU", "NZ", "JP", "SG",
})

_TIER_3_COUNTRIES: frozenset[str] = frozenset({
    # Latin America mid
    "PE", "CO", "EC", "BO", "PY", "VE", "DO", "GT", "HN", "SV", "NI", "CU",
    # Southeast Asia
    "TH", "PH", "MY",
    # MENA + Africa
    "ZA", "TN", "MA", "JO", "LB",
    # Eastern Europe / CIS (emerging)
    "UA", "BY", "KZ", "RS", "MK", "AL", "BA", "ME", "GE", "AM", "AZ", "MD",
})

_TIER_4_COUNTRIES: frozenset[str] = frozenset({
    # South Asia
    "IN", "PK", "BD", "LK", "NP",
    # Southeast Asia (lower income)
    "ID", "VN", "MM", "KH", "LA",
    # Africa
    "NG", "KE", "EG", "MW", "UG", "TZ", "ZW", "ZM", "MZ", "SN", "CI", "CM",
})

TIER_NAMES: dict[Tier, str] = {1: "Premium", 2: "Base", 3: "Mid-emerging", 4: "Affordable"}
TIER_EXAMPLES: dict[Tier, str] = {
    1: "US, UK, Germany, France, Japan, Australia",
    2: "Brazil, Mexico, Korea, Turkey, Poland",
    3: "Peru, Thailand, Malaysia, South Africa, Ukraine",
    4: "India, Indonesia, Vietnam, Nigeria, Egypt",
}


# ─── Price table (cents) ───────────────────────────────────────

@dataclass(frozen=True)
class TierPrices:
    plan_monthly: int
    plan_yearly: int
    extra_device_monthly: int
    extra_device_yearly: int

    def plan(self, interval: Interval) -> int:
        return self.plan_monthly if interval == "monthly" else self.plan_yearly

    def extra_device(self, interval: Interval) -> int:
        return self.extra_device_monthly if interval == "monthly" else self.extra_device_yearly


TIER_PRICES: dict[Tier, TierPrices] = {
    1: TierPrices(plan_monthly=199, plan_yearly=1999, extra_device_monthly=49, extra_device_yearly=499),
    2: TierPrices(plan_monthly=199, plan_yearly=1999, extra_device_monthly=49, extra_device_yearly=499),
    3: TierPrices(plan_monthly=199, plan_yearly=1999, extra_device_monthly=49, extra_device_yearly=349),
    4: TierPrices(plan_monthly=199, plan_yearly=1999, extra_device_monthly=49, extra_device_yearly=249),
}


def included_devices() -> int:
    """Devices the plan covers before extras (PLAN_INCLUDED_DEVICES, default 3)."""
    from api.services.entitlements import included_devices as _included

    return _included()


# ─── Stripe price IDs ──────────────────────────────────────────
# One Stripe price per tier × interval for the plan, and one for the extra
# device. `scripts/create_stripe_prices.py` creates them and prints the env
# lines to paste into Railway:
#
#   STRIPE_PRICE_DEVICES_T{1..4}_{MONTHLY|YEARLY}
#   STRIPE_PRICE_EXTRA_DEVICE_T{1..4}_{MONTHLY|YEARLY}
#
# Until those env vars are set (dev / staging without Stripe) a
# deterministic placeholder keeps /api/v1/pricing parseable. Checkout
# refuses a placeholder with 503 checkout_not_configured
# (api/routers/payments.py) instead of sending it to Stripe.

_PLACEHOLDER_SUFFIX = "_PLACEHOLDER"


def _env_price(name: str) -> str:
    return _os.environ.get(name, f"price_{name.removeprefix('STRIPE_PRICE_')}{_PLACEHOLDER_SUFFIX}")


def is_configured_price(price_id: str | None) -> bool:
    """False for the placeholder of an unset STRIPE_PRICE_* env var, or one
    set to nothing: checkout cannot sell such a price."""
    return bool(price_id) and not str(price_id).endswith(_PLACEHOLDER_SUFFIX)


def _plan_env(tier: Tier, interval: Interval) -> str:
    return f"STRIPE_PRICE_DEVICES_T{tier}_{interval.upper()}"


def _extra_env(tier: Tier, interval: Interval) -> str:
    return f"STRIPE_PRICE_EXTRA_DEVICE_T{tier}_{interval.upper()}"


STRIPE_PRICE_IDS: dict[Tier, dict[Interval, str]] = {
    tier: {interval: _env_price(_plan_env(tier, interval)) for interval in INTERVALS} for tier in TIERS
}
STRIPE_EXTRA_DEVICE_PRICE_IDS: dict[Tier, dict[Interval, str]] = {
    tier: {interval: _env_price(_extra_env(tier, interval)) for interval in INTERVALS} for tier in TIERS
}

#: Prices of the old personal / family / business plans, read only when the
#: env still carries them: a subscription bought before the device plan keeps
#: mapping back to the tier it was sold as (webhook plan_for_price_id).
_LEGACY_PLANS: tuple[str, ...] = ("personal", "family", "business")
LEGACY_PRICE_IDS: dict[str, str] = {
    price_id: plan
    for plan in _LEGACY_PLANS
    for tier in TIERS
    for interval in INTERVALS
    if (price_id := _os.environ.get(f"STRIPE_PRICE_{plan.upper()}_T{tier}_{interval.upper()}", "").strip())
}


# ─── Public API ────────────────────────────────────────────────

@dataclass(frozen=True)
class PriceQuote:
    """One price for display / checkout. Amounts in cents."""
    tier: Tier
    interval: Interval
    amount_cents: int
    stripe_price_id: str
    currency: str = "USD"

    @property
    def amount_usd(self) -> float:
        return self.amount_cents / 100

    @property
    def monthly_equivalent_usd(self) -> float:
        """Per-month rate for comparison (yearly ÷ 12, rounded to the cent)."""
        if self.interval == "monthly":
            return self.amount_usd
        return round(self.amount_cents / 12) / 100


@dataclass(frozen=True)
class DevicePlanQuote:
    tier: Tier
    plan: dict[Interval, PriceQuote]
    extra_device: dict[Interval, PriceQuote]


def country_to_tier(country_code: str | None) -> Tier:
    """Map ISO 3166-1 alpha-2 country code → pricing tier.

    Returns 2 (base) for None, empty, or unknown countries.
    """
    if not country_code:
        return 2
    cc = country_code.strip().upper()
    if len(cc) != 2:
        return 2
    if cc in _TIER_1_COUNTRIES:
        return 1
    if cc in _TIER_3_COUNTRIES:
        return 3
    if cc in _TIER_4_COUNTRIES:
        return 4
    return 2


def get_price(tier: Tier, interval: Interval = "monthly") -> PriceQuote:
    """The plan's price for a tier and interval."""
    return PriceQuote(tier, interval, TIER_PRICES[tier].plan(interval), STRIPE_PRICE_IDS[tier][interval])


def get_extra_device_price(tier: Tier, interval: Interval = "monthly") -> PriceQuote:
    """The price of ONE device beyond the included ones."""
    return PriceQuote(
        tier, interval, TIER_PRICES[tier].extra_device(interval), STRIPE_EXTRA_DEVICE_PRICE_IDS[tier][interval]
    )


def get_quote_for_country(country_code: str | None) -> DevicePlanQuote:
    """Plan + extra device, both intervals, for a country. Used by /pricing."""
    tier = country_to_tier(country_code)
    return DevicePlanQuote(
        tier=tier,
        plan={interval: get_price(tier, interval) for interval in INTERVALS},
        extra_device={interval: get_extra_device_price(tier, interval) for interval in INTERVALS},
    )


def parse_plan_key(plan_key: str) -> Interval | None:
    """'devices_monthly' / 'devices_yearly' (and the legacy 'personal_*')
    → the interval. None for anything else, including the retired
    'family_*' / 'business_*'."""
    if "_" not in plan_key:
        return None
    plan, interval = plan_key.rsplit("_", 1)
    if plan != PLAN_ID and plan not in LEGACY_PLAN_ALIASES:
        return None
    if interval not in INTERVALS:
        return None
    return interval  # type: ignore[return-value]


def price_id_for_checkout(country_code: str | None, interval: Interval = "monthly") -> str:
    """Resolve the plan's Stripe price ID for a checkout session. Server-side truth.

    Goes through the same `country_to_tier` as `get_quote_for_country`
    (the /api/v1/pricing/for-country endpoint), so for the same country
    the price charged is the price shown."""
    return STRIPE_PRICE_IDS[country_to_tier(country_code)][interval]


def extra_device_price_id_for_checkout(country_code: str | None, interval: Interval = "monthly") -> str:
    """The extra-device Stripe price for the same country and interval as the plan
    (Stripe requires every item of a subscription to bill on one interval)."""
    return STRIPE_EXTRA_DEVICE_PRICE_IDS[country_to_tier(country_code)][interval]


def is_extra_device_price(price_id: str | None) -> bool:
    """True for an extra-device price we created (any tier / interval)."""
    if not price_id:
        return False
    return any(price_id in intervals.values() for intervals in STRIPE_EXTRA_DEVICE_PRICE_IDS.values())


def plan_for_price_id(price_id: str | None) -> str | None:
    """Reverse lookup: which stored tier does this Stripe price belong to?

    A plan change in the Customer Portal arrives as a
    customer.subscription.updated carrying only the new price id; the
    webhook maps it back to the value stored in subscriptions.tier.
    The device plan → 'personal' (STORED_TIER); a price of a retired plan
    still configured in env → that plan; an extra-device price or a price
    we didn't create → None (never guess a plan)."""
    if not price_id:
        return None
    for intervals in STRIPE_PRICE_IDS.values():
        if price_id in intervals.values():
            return STORED_TIER
    return LEGACY_PRICE_IDS.get(price_id)
