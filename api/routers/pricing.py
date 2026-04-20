"""
Pricing endpoints — regional prices by country (no auth required).

  GET /api/v1/pricing/for-country?cc=US — returns prices for detected country
  GET /api/v1/pricing/tiers — full tier reference (debug/admin)

Country detection priority on caller side:
  1. Explicit `cc` query param (from Stripe Checkout detected country, or user pick)
  2. Stripe Checkout will confirm billing country at payment

Server-side never trusts IP-based country (VPN bypass). Caller sends.
"""
from typing import Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from api.services.rate_limiter import rate_limit
from api.services.pricing import (
    _TIER_1_COUNTRIES,
    _TIER_3_COUNTRIES,
    _TIER_4_COUNTRIES,
    country_to_tier,
    get_prices_for_country,
)

router = APIRouter(prefix="/api/v1/pricing", tags=["pricing"])


# ─── Response models ──────────────────────────────────────────────
# These are Pydantic models (not TypedDict) so FastAPI generates full
# OpenAPI schemas — consumers get typed responses via openapi-typescript.


class PricePoint(BaseModel):
    """One price (monthly or yearly) for a single plan in a single tier."""
    amount: float = Field(..., description="Display price in USD (monthly or yearly total)")
    monthly_equivalent: float = Field(..., description="Equivalent monthly rate for comparison")
    interval: Literal["monthly", "yearly"]
    stripe_price_id: str = Field(..., description="Stripe price ID for checkout session")


class PlanIntervals(BaseModel):
    monthly: PricePoint
    yearly: PricePoint


class PricingMessaging(BaseModel):
    blocking_is_free_forever: bool = Field(
        ...,
        description="Ethical invariant: scam site blocking never requires payment. Always true.",
    )
    free_threat_threshold: int = Field(
        ...,
        description="Number of detailed threat explanations given free. After this, paywall gates the DETAILS (not the block itself).",
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
    plans: Dict[Literal["personal", "family", "business"], PlanIntervals]
    messaging: PricingMessaging


class TierDescription(BaseModel):
    name: str
    multiplier: float
    countries: object = Field(
        ...,
        description="List of ISO country codes, or a human-readable note for tier 2 (default).",
    )
    examples: str


class PricingTiersResponse(BaseModel):
    tiers: Dict[Literal["1", "2", "3", "4"], TierDescription]
    base_prices_usd_monthly: Dict[str, float]
    notes: Dict[str, str]


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
    """
    Return pricing for all plans (personal, family, business) × intervals (monthly, yearly)
    for the given country's PPP tier.
    """
    tier = country_to_tier(cc)
    prices = get_prices_for_country(cc)

    plans: Dict[str, PlanIntervals] = {}
    for plan_name, intervals in prices.items():
        plans[plan_name] = PlanIntervals(
            monthly=PricePoint(
                amount=intervals["monthly"].displayed_usd,
                monthly_equivalent=intervals["monthly"].monthly_usd,
                interval="monthly",
                stripe_price_id=intervals["monthly"].stripe_price_id,
            ),
            yearly=PricePoint(
                amount=intervals["yearly"].displayed_usd,
                monthly_equivalent=intervals["yearly"].monthly_usd,
                interval="yearly",
                stripe_price_id=intervals["yearly"].stripe_price_id,
            ),
        )

    return PricingForCountryResponse(
        country=((cc or "").upper() or None),
        tier=tier,  # type: ignore[arg-type]  # country_to_tier returns 1..4
        currency="USD",
        plans=plans,  # type: ignore[arg-type]
        messaging=PricingMessaging(
            blocking_is_free_forever=True,
            free_threat_threshold=50,
            what_paid_unlocks=[
                "Detailed explanations for every scam site",
                "Domain history + scheme breakdowns",
                "Privacy Audit: full tracker list",
                "Family Hub: protect up to 6 loved ones",
                "Granny Mode / Kids Mode for family members",
                "Weekly Report with real percentile ranking",
                "Multi-device sync (up to 5 devices)",
            ],
        ),
    )


@router.get(
    "/tiers",
    response_model=PricingTiersResponse,
    dependencies=[Depends(rate_limit(mode="ip", category="pricing"))],
)
async def pricing_tiers() -> PricingTiersResponse:
    """Full tier reference — which countries are in each tier + base prices."""
    return PricingTiersResponse(
        tiers={
            "1": TierDescription(
                name="Premium",
                multiplier=1.2,
                countries=sorted(_TIER_1_COUNTRIES),
                examples="US, UK, Germany, France, Japan, Australia",
            ),
            "2": TierDescription(
                name="Base",
                multiplier=1.0,
                countries="[default — everything not in T1/T3/T4]",
                examples="Russia, Brazil, Mexico, Korea, Turkey, Poland",
            ),
            "3": TierDescription(
                name="Mid-emerging",
                multiplier=0.5,
                countries=sorted(_TIER_3_COUNTRIES),
                examples="Peru, Thailand, Malaysia, South Africa, Ukraine",
            ),
            "4": TierDescription(
                name="Affordable",
                multiplier=0.3,
                countries=sorted(_TIER_4_COUNTRIES),
                examples="India, Indonesia, Vietnam, Nigeria, Egypt",
            ),
        },
        base_prices_usd_monthly={
            "personal": 4.99,
            "family": 9.99,
            "business_per_user": 3.99,
        },
        notes={
            "billing_country": "Detected by Stripe Checkout (not IP) to prevent VPN abuse.",
            "yearly_discount": "Yearly = monthly × 10 (2 months free).",
            "currency": "USD on backend; Stripe can display local currency at checkout.",
        },
    )
