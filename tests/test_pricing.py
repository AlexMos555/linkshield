"""Tests for regional pricing service + /api/v1/pricing endpoints."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.services.pricing import (
    country_to_tier,
    get_price,
    get_prices_for_country,
    price_id_for_checkout,
    STRIPE_PRICE_IDS,
)


# ═══════════════════════════════════════════════════════════════
# country_to_tier mapping
# ═══════════════════════════════════════════════════════════════

@pytest.mark.parametrize("country,expected_tier", [
    # T1 premium
    ("US", 1), ("GB", 1), ("DE", 1), ("FR", 1), ("AU", 1), ("JP", 1),
    ("CA", 1), ("CH", 1), ("NL", 1), ("SG", 1),
    # T2 base (default)
    ("RU", 2), ("BR", 2), ("MX", 2), ("KR", 2), ("TR", 2), ("PL", 2),
    ("CZ", 2), ("HU", 2),  # Eastern Europe
    # T3 mid-emerging
    ("TH", 3), ("MY", 3), ("UA", 3), ("KZ", 3), ("BY", 3), ("CO", 3),
    ("PE", 3), ("ZA", 3), ("AM", 3),
    # T4 affordable
    ("IN", 4), ("ID", 4), ("VN", 4), ("PK", 4), ("BD", 4),
    ("EG", 4), ("NG", 4), ("KE", 4),
])
def test_country_to_tier_known(country: str, expected_tier: int):
    assert country_to_tier(country) == expected_tier


@pytest.mark.parametrize("bad_input", [None, "", "X", "XXX", "123", "  ", "FAKE"])
def test_country_to_tier_unknown_defaults_to_base(bad_input):
    """Invalid / unknown input → tier 2 (base), never crash."""
    assert country_to_tier(bad_input) == 2


def test_whitespace_around_valid_code_is_stripped():
    """'us ' and '  US  ' still resolve correctly — we strip whitespace."""
    assert country_to_tier("us ") == 1
    assert country_to_tier("  IN  ") == 4


def test_country_code_is_case_insensitive():
    assert country_to_tier("us") == country_to_tier("US") == 1
    assert country_to_tier("in") == country_to_tier("IN") == 4


# ═══════════════════════════════════════════════════════════════
# get_price — per plan/tier/interval
# ═══════════════════════════════════════════════════════════════

def test_personal_tier_prices_ascending_by_tier():
    """T4 (affordable) < T3 < T2 (base) < T1 (premium)."""
    t4 = get_price("personal", 4, "monthly").monthly_usd
    t3 = get_price("personal", 3, "monthly").monthly_usd
    t2 = get_price("personal", 2, "monthly").monthly_usd
    t1 = get_price("personal", 1, "monthly").monthly_usd
    assert t4 < t3 < t2 < t1


def test_base_tier_personal_is_499():
    """Base tier 2 Personal → $4.99 (the anchor)."""
    q = get_price("personal", 2, "monthly")
    assert q.monthly_usd == 4.99


def test_yearly_is_10x_monthly():
    """Yearly = 10 months price (2 months off)."""
    monthly = get_price("personal", 2, "monthly")
    yearly = get_price("personal", 2, "yearly")
    assert yearly.displayed_usd == round(monthly.monthly_usd * 10, 2)


def test_t1_personal_about_599():
    """T1 Personal ≈ $5.99 (20% above base, rounded to .99)."""
    q = get_price("personal", 1, "monthly")
    assert q.monthly_usd == 5.99


def test_t4_personal_about_149():
    """T4 Personal ≈ $1.49 (30% of base)."""
    q = get_price("personal", 4, "monthly")
    assert q.monthly_usd == 1.49


def test_family_more_expensive_than_personal():
    for tier in (1, 2, 3, 4):
        p = get_price("personal", tier, "monthly").monthly_usd
        f = get_price("family", tier, "monthly").monthly_usd
        assert f > p, f"Family ({f}) should cost more than Personal ({p}) at T{tier}"


def test_stripe_price_id_returned():
    """Every quote includes a Stripe price ID placeholder."""
    q = get_price("personal", 2, "monthly")
    assert q.stripe_price_id == "price_PERSONAL_T2_MONTHLY"


# ═══════════════════════════════════════════════════════════════
# price_id_for_checkout — server-side truth for Stripe Checkout
# ═══════════════════════════════════════════════════════════════

def test_checkout_price_id_by_country():
    assert price_id_for_checkout("personal", "US", "monthly") == STRIPE_PRICE_IDS["personal"][1]["monthly"]
    assert price_id_for_checkout("family", "IN", "yearly") == STRIPE_PRICE_IDS["family"][4]["yearly"]
    assert price_id_for_checkout("business", None, "monthly") == STRIPE_PRICE_IDS["business"][2]["monthly"]


def test_all_stripe_ids_present():
    """Sanity check: every plan × tier × interval has a placeholder ID."""
    for plan in ("personal", "family", "business"):
        for tier in (1, 2, 3, 4):
            for interval in ("monthly", "yearly"):
                pid = STRIPE_PRICE_IDS[plan][tier][interval]
                assert pid and isinstance(pid, str), f"Missing price_id for {plan}/{tier}/{interval}"


# ═══════════════════════════════════════════════════════════════
# get_prices_for_country — used by /pricing/for-country endpoint
# ═══════════════════════════════════════════════════════════════

def test_get_prices_for_country_returns_all_plans():
    prices = get_prices_for_country("US")
    assert set(prices.keys()) == {"personal", "family", "business"}
    for plan_prices in prices.values():
        assert set(plan_prices.keys()) == {"monthly", "yearly"}


def test_get_prices_none_country_is_base_tier():
    """None country → T2 (base) pricing."""
    prices = get_prices_for_country(None)
    assert prices["personal"]["monthly"].monthly_usd == 4.99


# ═══════════════════════════════════════════════════════════════
# API endpoints /api/v1/pricing/*
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def client():
    from api.main import app
    return TestClient(app)


def test_pricing_for_country_us(client):
    """GET /api/v1/pricing/for-country?cc=US → T1 prices."""
    resp = client.get("/api/v1/pricing/for-country?cc=US")
    assert resp.status_code == 200
    body = resp.json()
    assert body["country"] == "US"
    assert body["tier"] == 1
    assert body["plans"]["personal"]["monthly"]["amount"] == 5.99
    assert body["messaging"]["blocking_is_free_forever"] is True
    assert body["messaging"]["free_threat_threshold"] == 50


def test_pricing_for_country_india(client):
    resp = client.get("/api/v1/pricing/for-country?cc=IN")
    assert resp.status_code == 200
    body = resp.json()
    assert body["tier"] == 4
    assert body["plans"]["personal"]["monthly"]["amount"] == 1.49


def test_pricing_for_country_default(client):
    """No cc → tier 2 base."""
    resp = client.get("/api/v1/pricing/for-country")
    assert resp.status_code == 200
    body = resp.json()
    assert body["tier"] == 2
    assert body["plans"]["personal"]["monthly"]["amount"] == 4.99


def test_pricing_for_country_unknown_defaults_to_base(client):
    resp = client.get("/api/v1/pricing/for-country?cc=XX")
    assert resp.status_code == 200
    assert resp.json()["tier"] == 2


def test_pricing_tiers_reference(client):
    resp = client.get("/api/v1/pricing/tiers")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body["tiers"].keys()) == {"1", "2", "3", "4"}
    assert "US" in body["tiers"]["1"]["countries"]
    assert "IN" in body["tiers"]["4"]["countries"]
    assert body["base_prices_usd_monthly"]["personal"] == 4.99
