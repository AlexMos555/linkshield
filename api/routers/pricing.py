"""
Pricing endpoints — the world's device plan by country (no auth required).

  GET /api/v1/pricing/for-country?cc=US — the plan, the extra device and the
                                          free tier for that country's PPP tier
  GET /api/v1/pricing/tiers             — full tier reference (debug/admin)

The tier follows the `cc` the caller sends (the site passes the visitor's IP
country from its edge; a `?cc=` overrides it). Checkout takes the same `cc`
(`CheckoutRequest.country`), so the price charged is the price shown. No
country → tier 2 (base). Russia is sold by the operator-billed subscription
(api/billing), not here.

Prices and the reasoning behind each tier: api/services/pricing.py.
"""
from typing import Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from api.services.rate_limiter import rate_limit
from api.services.pricing import (
    _TIER_1_COUNTRIES,
    _TIER_3_COUNTRIES,
    _TIER_4_COUNTRIES,
    FREE_DETAILED_CHECKS_PER_DAY,
    FREE_UNLIMITED_DAYS_AFTER_INSTALL,
    PLAN_ID,
    STRIPE_TRIAL_DAYS,
    TIER_EXAMPLES,
    TIER_NAMES,
    TIER_PRICES,
    TIERS,
    PriceQuote,
    get_quote_for_country,
    included_devices,
)

router = APIRouter(prefix="/api/v1/pricing", tags=["pricing"])


# ─── Response models ──────────────────────────────────────────────
# These are Pydantic models (not TypedDict) so FastAPI generates full
# OpenAPI schemas — consumers get typed responses via openapi-typescript.


class PricePoint(BaseModel):
    """One price (monthly or yearly)."""
    amount: float = Field(..., description="Price in USD for the interval (the monthly price, or the yearly total)")
    monthly_equivalent: float = Field(..., description="Equivalent monthly rate for comparison (yearly ÷ 12)")
    interval: Literal["monthly", "yearly"]
    stripe_price_id: str = Field(..., description="Stripe price ID for the checkout session")


class Intervals(BaseModel):
    monthly: PricePoint
    yearly: PricePoint


class DevicePlan(BaseModel):
    """The one paid plan: unlimited detailed checks on N devices of one account."""
    id: Literal["devices"] = Field(..., description="Checkout key prefix: `devices_monthly` / `devices_yearly`.")
    included_devices: int = Field(
        ..., description="Devices (phone, tablet, browser with the extension) the plan covers."
    )
    price: Intervals
    extra_device: Intervals = Field(
        ..., description="Price of ONE device beyond the included ones, on the same interval as the plan."
    )
    trial_days: int = Field(
        ..., description="Free trial on the account's first web subscription (Stripe Checkout), once per account."
    )


class FreeTier(BaseModel):
    list_blocking_unlimited: bool = Field(
        ..., description="Blocking known scam sites from the list never needs payment. Always true."
    )
    detailed_checks_per_day: int = Field(
        ..., description="Detailed checks (verdict, reasons, the scheme explained) a day without a plan."
    )
    unlimited_days_after_install: int = Field(
        ..., description="Days after install with everything unlimited, no card."
    )


class PricingMessaging(BaseModel):
    blocking_is_free_forever: bool = Field(
        ...,
        description="Ethical invariant: scam site blocking never requires payment. Always true.",
    )
    what_paid_unlocks: List[str]


class PricingForCountryResponse(BaseModel):
    country: Optional[str] = Field(
        None,
        description="Echoed ISO 3166-1 alpha-2 country code (uppercased). None when no cc was provided.",
    )
    tier: Literal[1, 2, 3, 4] = Field(
        ...,
        description="PPP pricing tier. 1=Premium, 2=Base (default), 3=Mid-emerging, 4=Affordable.",
    )
    currency: Literal["USD"] = "USD"
    plan: DevicePlan
    free: FreeTier
    messaging: PricingMessaging


class TierDescription(BaseModel):
    name: str
    countries: object = Field(
        ...,
        description="List of ISO country codes, or a human-readable note for tier 2 (default).",
    )
    examples: str
    monthly_usd: float
    yearly_usd: float
    extra_device_monthly_usd: float
    extra_device_yearly_usd: float


class PricingTiersResponse(BaseModel):
    tiers: Dict[Literal["1", "2", "3", "4"], TierDescription]
    included_devices: int
    notes: Dict[str, str]


def _point(quote: PriceQuote) -> PricePoint:
    return PricePoint(
        amount=quote.amount_usd,
        monthly_equivalent=quote.monthly_equivalent_usd,
        interval=quote.interval,
        stripe_price_id=quote.stripe_price_id,
    )


# ─── Endpoints ────────────────────────────────────────────────────


@router.get(
    "/for-country",
    response_model=PricingForCountryResponse,
    dependencies=[Depends(rate_limit(mode="ip", category="pricing"))],
)
async def prices_for_country(
    cc: Optional[str] = Query(
        default=None,
        description="ISO 3166-1 alpha-2 country code. Omit for default tier 2 (base) pricing.",
        max_length=2,
        min_length=0,
    ),
) -> PricingForCountryResponse:
    """The device plan (monthly + yearly), the extra device and the free tier
    for the given country's PPP tier."""
    quote = get_quote_for_country(cc)
    devices = included_devices()

    return PricingForCountryResponse(
        country=((cc or "").upper() or None),
        tier=quote.tier,
        currency="USD",
        plan=DevicePlan(
            id=PLAN_ID,
            included_devices=devices,
            price=Intervals(monthly=_point(quote.plan["monthly"]), yearly=_point(quote.plan["yearly"])),
            extra_device=Intervals(
                monthly=_point(quote.extra_device["monthly"]), yearly=_point(quote.extra_device["yearly"])
            ),
            trial_days=STRIPE_TRIAL_DAYS,
        ),
        free=FreeTier(
            list_blocking_unlimited=True,
            detailed_checks_per_day=FREE_DETAILED_CHECKS_PER_DAY,
            unlimited_days_after_install=FREE_UNLIMITED_DAYS_AFTER_INSTALL,
        ),
        messaging=PricingMessaging(
            blocking_is_free_forever=True,
            # Only what the plan really adds. The old list sold a Family Hub,
            # Granny / Kids modes and a weekly percentile report that no
            # client ships.
            what_paid_unlocks=[
                "Unlimited detailed checks of links and messages",
                f"{devices} devices on one account: phones, tablets, browsers with the extension",
                "More devices at any time; unlink one and its place frees up at once",
            ],
        ),
    )


@router.get(
    "/tiers",
    response_model=PricingTiersResponse,
    dependencies=[Depends(rate_limit(mode="ip", category="pricing"))],
)
async def pricing_tiers() -> PricingTiersResponse:
    """Full tier reference — which countries are in each tier + their prices."""
    countries: Dict[int, object] = {
        1: sorted(_TIER_1_COUNTRIES),
        2: "[default — everything not in T1/T3/T4]",
        3: sorted(_TIER_3_COUNTRIES),
        4: sorted(_TIER_4_COUNTRIES),
    }
    return PricingTiersResponse(
        tiers={
            str(tier): TierDescription(  # type: ignore[misc]
                name=TIER_NAMES[tier],
                countries=countries[tier],
                examples=TIER_EXAMPLES[tier],
                monthly_usd=TIER_PRICES[tier].plan_monthly / 100,
                yearly_usd=TIER_PRICES[tier].plan_yearly / 100,
                extra_device_monthly_usd=TIER_PRICES[tier].extra_device_monthly / 100,
                extra_device_yearly_usd=TIER_PRICES[tier].extra_device_yearly / 100,
            )
            for tier in TIERS
        },
        included_devices=included_devices(),
        notes={
            "country": "The tier follows the `cc` the caller sends (the site uses the visitor's IP country). "
                       "Checkout takes the same country, so the price charged is the price shown.",
            "monthly_floor": "Monthly is $0.99 in every tier: below it the fixed payment fee eats the price. "
                             "The regional discount is in the yearly price.",
            "currency": "USD on backend; Stripe can display local currency at checkout.",
            "russia": "Russia is sold by the operator-billed subscription (api/billing), in rubles.",
        },
    )
