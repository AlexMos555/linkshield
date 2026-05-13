"""Regional pricing service — map country to PPP tier + Stripe price IDs.

See /.planning/PRICING_MATRIX.md for the full pricing strategy.

The invariant: blocking is free forever. Paid unlocks details, family, personalization.
After 50 threats on free tier: details locked, blocking still works.

Tiers by purchasing power parity (PPP):
- Tier 1 (premium): US, UK, DE, FR, AU, JP, SG, NL, NO, SE, CH, ...
- Tier 2 (base, default): EU east, RU, BR, MX, KR, TR, PL, ...
- Tier 3 (mid-emerging): LATAM mid, SE Asia, MENA
- Tier 4 (affordable): India, Indonesia, Vietnam, Egypt, Pakistan, Bangladesh
"""
from __future__ import annotations

import os as _os
from dataclasses import dataclass
from typing import Literal

# ─── Type definitions ──────────────────────────────────────────

Plan = Literal["personal", "family", "business"]
Interval = Literal["monthly", "yearly"]
Tier = Literal[1, 2, 3, 4]

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


# ─── Pricing table ─────────────────────────────────────────────
# USD per month. Yearly = 10× monthly (2 months free).
# These prices map to Stripe price IDs set up per product in the dashboard.

_BASE_PRICES_USD: dict[Plan, float] = {
    "personal": 4.99,
    "family": 9.99,
    "business": 3.99,  # per user
}

_TIER_MULTIPLIERS: dict[Tier, float] = {
    1: 1.2,   # premium markets +20%
    2: 1.0,   # base
    3: 0.5,   # mid emerging -50%
    4: 0.3,   # affordable -70%
}

# ─── Stripe price IDs ──────────────────────────────────────────
# Each Plan × Tier × Interval combination maps to a Stripe price ID
# created by `scripts/create_stripe_prices.py`. The script outputs 24
# lines like `STRIPE_PRICE_PERSONAL_T1_MONTHLY=price_1QabC...` to paste
# into Railway env vars; this module reads them at import time.
#
# Until those env vars are populated (dev / staging without Stripe wired)
# we fall back to a deterministic placeholder so /api/v1/pricing still
# serves a parseable response. Calling Stripe Checkout with the
# placeholder will fail at Stripe's end ("No such price …") — that's
# the right failure mode: it surfaces the missing env var loudly
# instead of silently 500-ing.


def _resolve_price_id(plan: "Plan", tier: "Tier", interval: "Interval") -> str:
    env_var = f"STRIPE_PRICE_{plan.upper()}_T{tier}_{interval.upper()}"
    return _os.environ.get(env_var, f"price_{plan.upper()}_T{tier}_{interval.upper()}_PLACEHOLDER")


STRIPE_PRICE_IDS: dict[Plan, dict[Tier, dict[Interval, str]]] = {
    plan: {
        tier: {
            interval: _resolve_price_id(plan, tier, interval)
            for interval in ("monthly", "yearly")
        }
        for tier in (1, 2, 3, 4)
    }
    for plan in ("personal", "family", "business")
}


# ─── Public API ────────────────────────────────────────────────

@dataclass(frozen=True)
class PriceQuote:
    """A single price quote for display/checkout."""
    plan: Plan
    tier: Tier
    interval: Interval
    monthly_usd: float
    displayed_usd: float  # for yearly это total за год (monthly × 10)
    stripe_price_id: str
    currency: str = "USD"


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


def _round_price(value: float) -> float:
    """Round to nearest .49 or .99 (consumer psychology pricing)."""
    whole = int(value)
    frac = value - whole
    if frac < 0.25:
        return whole - 1 + 0.99 if whole > 0 else 0.99
    if frac < 0.75:
        return whole + 0.49
    return whole + 0.99


def get_price(plan: Plan, tier: Tier, interval: Interval = "monthly") -> PriceQuote:
    """Return a PriceQuote for given plan/tier/interval."""
    base = _BASE_PRICES_USD[plan]
    monthly = _round_price(base * _TIER_MULTIPLIERS[tier])
    # Yearly = 10 months price (2 months off)
    displayed = monthly if interval == "monthly" else round(monthly * 10, 2)
    return PriceQuote(
        plan=plan,
        tier=tier,
        interval=interval,
        monthly_usd=monthly,
        displayed_usd=displayed,
        stripe_price_id=STRIPE_PRICE_IDS[plan][tier][interval],
    )


def get_prices_for_country(country_code: str | None) -> dict[Plan, dict[Interval, PriceQuote]]:
    """All plans × intervals for a detected country. Used by /pricing endpoint."""
    tier = country_to_tier(country_code)
    result: dict[Plan, dict[Interval, PriceQuote]] = {}
    for plan in ("personal", "family", "business"):
        result[plan] = {
            "monthly": get_price(plan, tier, "monthly"),
            "yearly": get_price(plan, tier, "yearly"),
        }
    return result


def price_id_for_checkout(plan: Plan, country_code: str | None, interval: Interval = "monthly") -> str:
    """Resolve Stripe price ID for a checkout session. Server-side truth."""
    tier = country_to_tier(country_code)
    return STRIPE_PRICE_IDS[plan][tier][interval]
