"""stripe-python 15+ objects are not dicts, and API 2025-03-31.basil moved fields.

The helpers in api.services.stripe_billing read both shapes, so neither a
library upgrade nor a new account's default API version breaks billing."""
from __future__ import annotations

import stripe

from api.services.stripe_billing import field, invoice_subscription_id, object_id, plain, subscription_period


def _obj(data):
    return stripe.StripeObject.construct_from(data, "sk_test_x")


def test_plain_turns_a_stripe_object_into_dicts_all_the_way_down():
    d = plain(_obj({"id": "evt_1", "data": {"object": {"items": {"data": [{"price": {"id": "p"}}]}}}}))
    assert isinstance(d, dict)
    assert d["data"]["object"]["items"]["data"][0]["price"]["id"] == "p"
    assert d.get("missing") is None


def test_field_reads_stripe_objects_dicts_and_nothing_else():
    obj = _obj({"metadata": {"user_id": "u1"}, "customer": "cus_1"})
    assert field(field(obj, "metadata"), "user_id") == "u1"
    assert field({"a": 1}, "a") == 1
    assert field(None, "a") is None
    assert field("cus_1", "id") is None
    assert object_id(field(obj, "customer")) == "cus_1"


def test_subscription_period_before_and_after_basil():
    assert subscription_period({"current_period_start": 10, "current_period_end": 20}) == (10, 20)
    basil = {"items": {"data": [
        {"current_period_start": 10, "current_period_end": 20},
        {"current_period_start": 12, "current_period_end": 25},  # an add-on item
    ]}}
    assert subscription_period(basil) == (10, 25)
    assert subscription_period(_obj(basil)) == (10, 25)
    assert subscription_period({}) == (None, None)


def test_invoice_subscription_before_and_after_basil():
    assert invoice_subscription_id({"subscription": "sub_old"}) == "sub_old"
    assert invoice_subscription_id({"subscription": {"id": "sub_exp"}}) == "sub_exp"
    basil = {"parent": {"type": "subscription_details", "subscription_details": {"subscription": "sub_new"}}}
    assert invoice_subscription_id(basil) == "sub_new"
    assert invoice_subscription_id(_obj(basil)) == "sub_new"
    assert invoice_subscription_id({}) is None
