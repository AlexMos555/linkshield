"""Partner licence parsing/signing, plan-change arithmetic, consent docs, context helpers."""
from __future__ import annotations

import json
from datetime import timedelta

import pytest

from api.billing import partner
from api.billing.consents import UnknownConsentVersion, load_consent_doc, require_current
from api.billing.context import plan_catalog
from api.billing.service.errors import Invalid, NotConfigured, Unauthorized
from api.billing.service.plan_change import converted_days, days_remaining, is_upgrade
from api.billing.settings import BillingSettings
from tests.billing.conftest import T0


def test_partner_signature_and_parsing():
    body = json.dumps({"partner": "t2", "license_ref": "L1", "seats": 3, "months": 1}).encode()
    sig = partner.partner_signature("k", body)
    partner.verify_partner_signature("k", {"X-Partner-Signature": sig}, body)
    with pytest.raises(Unauthorized):
        partner.verify_partner_signature("k", {"X-Partner-Signature": "0" * 64}, body)
    with pytest.raises(Unauthorized):
        partner.verify_partner_signature("k", {}, body)
    with pytest.raises(NotConfigured):
        partner.verify_partner_signature("", {"X-Partner-Signature": sig}, body)
    assert partner.parse_partner_request(body) == {"partner": "t2", "license_ref": "L1", "seats": 3, "months": 1}
    for bad in (b"nope", b"[]", b'{"partner": "t-2", "license_ref": "x"}', b'{"partner": "t2", "license_ref": ""}',
                b'{"partner": "t2", "license_ref": "x", "months": 13}', b'{"partner": "t2", "license_ref": "x", "seats": "many"}'):
        with pytest.raises(Invalid):
            partner.parse_partner_request(bad)
    assert partner.maybe_partner("t2") == "t2" and partner.maybe_partner("t-2") is None


@pytest.mark.asyncio
async def test_plan_for_seats(ctx):
    assert partner.plan_for_seats(ctx, 1).value == "solo"
    assert partner.plan_for_seats(ctx, 2).value == "family3"
    assert partner.plan_for_seats(ctx, 5).value == "family5"
    with pytest.raises(Invalid):
        partner.plan_for_seats(ctx, 6)


@pytest.mark.asyncio
async def test_partner_license_creates_an_active_subscription(ctx):
    lic = await partner.create_partner_license(ctx, partner="t2", license_ref="L-9", seats=5, months=3)
    sub = ctx.store.tables.subscriptions[lic["subscription_id"]]
    assert sub.status.value == "active" and sub.provider.value == "t2_option" and sub.next_charge_at is None
    assert sub.current_period_end.month == 1 and sub.current_period_end.year == 2027   # Oct + 3 months
    assert lic["valid_until"] == int(sub.current_period_end.timestamp())
    assert lic["code_expires_at"] == int((T0 + timedelta(days=30)).timestamp())


def test_plan_change_arithmetic():
    assert converted_days(20, 9900, 27000) == 7          # the plan's own example
    assert converted_days(0, 9900, 27000) == 0
    assert converted_days(10, 27000, 9900) == 27         # downgrade math (applied at period end in practice)
    assert converted_days(10, 0, 9900) == 0
    with pytest.raises(ValueError):
        converted_days(10, 9900, 0)
    assert days_remaining(T0 + timedelta(days=20, hours=5), T0) == 20
    assert days_remaining(T0 - timedelta(days=1), T0) == 0
    assert is_upgrade(9900, 27000) and not is_upgrade(27000, 9900)


def test_consent_docs_are_versioned_and_hashed():
    doc = load_consent_doc("ru/v1")
    assert len(doc.sha256) == 64 and "Получить SMS-код" in doc.text
    assert require_current("ru/v1", "ru/v1") == doc
    with pytest.raises(UnknownConsentVersion):
        require_current("ru/v1", "ru/v2")
    with pytest.raises(UnknownConsentVersion):
        load_consent_doc("ru/v99")
    with pytest.raises(UnknownConsentVersion):
        load_consent_doc("../etc/passwd")


def test_plan_catalog_follows_prices():
    plans = plan_catalog(BillingSettings(_env_file=None, billing_price_family5_rub=450))
    assert [(p.code.value, p.seats, p.price_kopecks) for p in plans] == [("solo", 1, 9900), ("family3", 3, 27000), ("family5", 5, 45000)]
