"""Tests for the device-plan pricing service + /api/v1/pricing endpoints."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.services.pricing import (
    STORED_TIER,
    STRIPE_EXTRA_DEVICE_PRICE_IDS,
    STRIPE_PRICE_IDS,
    TIER_PRICES,
    country_to_tier,
    extra_device_price_id_for_checkout,
    get_extra_device_price,
    get_price,
    get_quote_for_country,
    is_extra_device_price,
    parse_plan_key,
    plan_for_price_id,
    price_id_for_checkout,
)


# ═══════════════════════════════════════════════════════════════
# country_to_tier mapping (unchanged by the device plan)
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
    assert country_to_tier("us ") == 1
    assert country_to_tier("  IN  ") == 4


def test_country_code_is_case_insensitive():
    assert country_to_tier("us") == country_to_tier("US") == 1
    assert country_to_tier("in") == country_to_tier("IN") == 4


# ═══════════════════════════════════════════════════════════════
# The founder's numbers (docs/ACCOUNTS_BILLING_PLAN.md §5)
# ═══════════════════════════════════════════════════════════════

def test_base_tier_is_the_founders_world_price():
    """$0.99 a month or $9.99 a year, +$0.49 a month per extra device."""
    assert get_price(2, "monthly").amount_cents == 99
    assert get_price(2, "yearly").amount_cents == 999
    assert get_extra_device_price(2, "monthly").amount_cents == 49


def test_premium_tier_pays_the_base_price():
    """No +20% on $0.99 — tier 1 is the headline price."""
    assert TIER_PRICES[1] == TIER_PRICES[2]


@pytest.mark.parametrize("tier", [1, 2, 3, 4])
def test_monthly_is_the_payment_floor_everywhere(tier):
    """Below $0.99 the fixed $0.30 payment fee eats the price, so the
    regional discount lives in the yearly price, not the monthly one."""
    assert get_price(tier, "monthly").amount_cents == 99
    assert get_extra_device_price(tier, "monthly").amount_cents == 49


def test_yearly_gets_cheaper_down_the_tiers():
    yearly = [get_price(tier, "yearly").amount_cents for tier in (1, 2, 3, 4)]
    assert yearly[0] == yearly[1] > yearly[2] > yearly[3]
    extra = [get_extra_device_price(tier, "yearly").amount_cents for tier in (1, 2, 3, 4)]
    assert extra[0] == extra[1] > extra[2] > extra[3]


@pytest.mark.parametrize("tier", [1, 2, 3, 4])
def test_yearly_always_beats_twelve_months(tier):
    """The yearly toggle may say "≈ N months free" only if it is cheaper."""
    prices = TIER_PRICES[tier]
    assert prices.plan_yearly < 12 * prices.plan_monthly
    assert prices.extra_device_yearly < 12 * prices.extra_device_monthly


def test_base_yearly_is_about_two_months_free():
    """"≈ 2 months free" on the site: $9.99 vs 12 × $0.99 = $11.88."""
    saved_months = (12 * 99 - 999) / 99
    assert round(saved_months) == 2


def test_monthly_equivalent_of_yearly():
    assert get_price(2, "yearly").monthly_equivalent_usd == 0.83  # 9.99 / 12
    assert get_price(2, "monthly").monthly_equivalent_usd == 0.99


def test_amounts_are_exact_usd():
    """Cents → USD without float drift (9.99, not 9.990000000000002)."""
    assert get_price(2, "yearly").amount_usd == 9.99
    assert get_extra_device_price(3, "yearly").amount_usd == 3.49


# ═══════════════════════════════════════════════════════════════
# Stripe price ids, checkout keys and reverse lookup
# ═══════════════════════════════════════════════════════════════

def test_placeholder_price_ids_without_env():
    """Without STRIPE_PRICE_* env vars a deterministic placeholder keeps the
    field parseable; Stripe refuses it loudly (No such price …)."""
    assert get_price(2, "monthly").stripe_price_id == "price_DEVICES_T2_MONTHLY_PLACEHOLDER"
    assert get_extra_device_price(4, "yearly").stripe_price_id == "price_EXTRA_DEVICE_T4_YEARLY_PLACEHOLDER"


def test_every_tier_and_interval_has_distinct_ids():
    ids = [pid for table in (STRIPE_PRICE_IDS, STRIPE_EXTRA_DEVICE_PRICE_IDS)
           for intervals in table.values() for pid in intervals.values()]
    assert len(ids) == 16
    assert len(set(ids)) == 16


def test_checkout_price_id_by_country():
    assert price_id_for_checkout("US", "monthly") == STRIPE_PRICE_IDS[1]["monthly"]
    assert price_id_for_checkout("IN", "yearly") == STRIPE_PRICE_IDS[4]["yearly"]
    assert price_id_for_checkout(None, "monthly") == STRIPE_PRICE_IDS[2]["monthly"]
    assert extra_device_price_id_for_checkout("TH", "yearly") == STRIPE_EXTRA_DEVICE_PRICE_IDS[3]["yearly"]


@pytest.mark.parametrize("key,interval", [
    ("devices_monthly", "monthly"), ("devices_yearly", "yearly"),
    # Pre-device-plan pages send personal_*; they buy the device plan.
    ("personal_monthly", "monthly"), ("personal_yearly", "yearly"),
])
def test_parse_plan_key_accepts(key, interval):
    assert parse_plan_key(key) == interval


@pytest.mark.parametrize("key", [
    "family_monthly", "business_yearly",  # retired
    "devices_quarterly", "devices", "garbage", "", "enterprise_monthly",
])
def test_parse_plan_key_rejects(key):
    assert parse_plan_key(key) is None


def test_plan_for_price_id():
    assert plan_for_price_id(STRIPE_PRICE_IDS[3]["yearly"]) == STORED_TIER == "personal"
    # The extra device is not a plan.
    assert plan_for_price_id(STRIPE_EXTRA_DEVICE_PRICE_IDS[3]["yearly"]) is None
    assert plan_for_price_id("price_unknown") is None
    assert plan_for_price_id(None) is None


def test_is_extra_device_price():
    assert is_extra_device_price(STRIPE_EXTRA_DEVICE_PRICE_IDS[1]["monthly"])
    assert not is_extra_device_price(STRIPE_PRICE_IDS[1]["monthly"])
    assert not is_extra_device_price(None)


def test_quote_for_country_none_is_base_tier():
    quote = get_quote_for_country(None)
    assert quote.tier == 2
    assert quote.plan["monthly"].amount_cents == 99
    assert quote.extra_device["yearly"].amount_cents == 499


def test_stripe_script_prices_come_from_the_service():
    """scripts/create_stripe_prices.py imports TIER_PRICES — one source of truth."""
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parent.parent / "scripts" / "create_stripe_prices.py"
    spec = importlib.util.spec_from_file_location("create_stripe_prices", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)

    specs = list(module.all_specs())
    assert len(specs) == 16
    by_env = {s.env_var: s.cents for s in specs}
    assert by_env["STRIPE_PRICE_DEVICES_T2_MONTHLY"] == 99
    assert by_env["STRIPE_PRICE_DEVICES_T2_YEARLY"] == 999
    assert by_env["STRIPE_PRICE_EXTRA_DEVICE_T2_MONTHLY"] == 49
    assert by_env["STRIPE_PRICE_DEVICES_T4_YEARLY"] == TIER_PRICES[4].plan_yearly
    # The env names are the ones the service reads.
    assert get_price(1, "monthly").stripe_price_id == "price_DEVICES_T1_MONTHLY_PLACEHOLDER"
    assert "STRIPE_PRICE_DEVICES_T1_MONTHLY" in by_env


# ═══════════════════════════════════════════════════════════════
# API endpoints /api/v1/pricing/*
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def client():
    from api.main import app
    return TestClient(app)


def test_pricing_for_country_us(client):
    resp = client.get("/api/v1/pricing/for-country?cc=US")
    assert resp.status_code == 200
    body = resp.json()
    assert body["country"] == "US"
    assert body["tier"] == 1
    plan = body["plan"]
    assert plan["id"] == "devices"
    assert plan["included_devices"] == 3
    assert plan["price"]["monthly"]["amount"] == 0.99
    assert plan["price"]["yearly"]["amount"] == 9.99
    assert plan["price"]["yearly"]["monthly_equivalent"] == 0.83
    assert plan["extra_device"]["monthly"]["amount"] == 0.49
    assert plan["extra_device"]["yearly"]["interval"] == "yearly"
    assert plan["trial_days"] == 14
    assert body["free"] == {
        "list_blocking_unlimited": True,
        "detailed_checks_per_day": 3,
        "unlimited_days_after_install": 7,
    }
    assert body["messaging"]["blocking_is_free_forever"] is True
    # The old shape is gone (only the landing read it, and it is updated).
    assert "plans" not in body
    assert "free_threat_threshold" not in body["messaging"]


def test_paid_unlocks_names_no_feature_we_do_not_ship(client):
    unlocks = " ".join(client.get("/api/v1/pricing/for-country").json()["messaging"]["what_paid_unlocks"])
    for retired in ("Family Hub", "Granny", "Kids Mode", "Weekly Report", "percentile"):
        assert retired not in unlocks
    assert "3 devices" in unlocks


def test_pricing_for_country_india(client):
    body = client.get("/api/v1/pricing/for-country?cc=IN").json()
    assert body["tier"] == 4
    assert body["plan"]["price"]["monthly"]["amount"] == 0.99
    assert body["plan"]["price"]["yearly"]["amount"] == 4.99


def test_pricing_for_country_default(client):
    body = client.get("/api/v1/pricing/for-country").json()
    assert body["tier"] == 2
    assert body["country"] is None
    assert body["plan"]["price"]["yearly"]["amount"] == 9.99


def test_pricing_for_country_unknown_defaults_to_base(client):
    resp = client.get("/api/v1/pricing/for-country?cc=XX")
    assert resp.status_code == 200
    assert resp.json()["tier"] == 2


def test_included_devices_follows_the_setting(client, monkeypatch):
    from api.config import get_settings

    monkeypatch.setattr(get_settings(), "plan_included_devices", 4)
    body = client.get("/api/v1/pricing/for-country").json()
    assert body["plan"]["included_devices"] == 4
    assert any("4 devices" in item for item in body["messaging"]["what_paid_unlocks"])


def test_pricing_tiers_reference(client):
    resp = client.get("/api/v1/pricing/tiers")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body["tiers"].keys()) == {"1", "2", "3", "4"}
    assert "US" in body["tiers"]["1"]["countries"]
    assert "IN" in body["tiers"]["4"]["countries"]
    assert body["tiers"]["2"]["monthly_usd"] == 0.99
    assert body["tiers"]["2"]["yearly_usd"] == 9.99
    assert body["tiers"]["2"]["extra_device_monthly_usd"] == 0.49
    assert body["included_devices"] == 3
    # The old note claimed the tier came from the Stripe billing country; it never did.
    assert "Stripe Checkout" not in " ".join(body["notes"].values())
