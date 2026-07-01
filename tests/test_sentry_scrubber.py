"""Sentry PII scrubber contract tests.

The scrubber is the last line between an exception payload and a
third-party retention bucket. A regression here silently leaks PII
into Sentry for 90 days — the kind of slip that doesn't surface until
a security review or a breach. Pin every redaction rule with a test.
"""
from __future__ import annotations

import pytest

from api.services.sentry_scrubber import before_breadcrumb, before_send


def test_email_redacted_in_exception_message():
    event = {
        "exception": {
            "values": [
                {"value": "Failed to send to alice@example.com — SMTP refused"}
            ]
        }
    }
    out = before_send(event)
    msg = out["exception"]["values"][0]["value"]
    assert "alice@example.com" not in msg
    assert "[redacted-email]" in msg


def test_jwt_in_headers_redacted_by_always_key():
    """The `Authorization` key is on the always-redact list, so even
    a non-JWT bearer token is redacted. Belt + braces with the regex."""
    event = {
        "request": {
            "headers": {
                "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.sigpart",
            }
        }
    }
    out = before_send(event)
    auth = out["request"]["headers"]["Authorization"]
    assert "eyJhbGci" not in auth
    assert auth == "[redacted]"


def test_jwt_in_free_text_redacted_by_regex():
    """When a JWT appears in an exception message (not behind a known
    header key), the regex path catches it."""
    event = {
        "exception": {
            "values": [
                {
                    "value": "Token rejected: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.sigpart",
                }
            ]
        }
    }
    out = before_send(event)
    msg = out["exception"]["values"][0]["value"]
    assert "eyJhbGci" not in msg
    assert "[redacted-jwt]" in msg


def test_stripe_secret_key_redacted():
    # Built from prefix + fake body — keeps GitHub's secret-scanning
    # push-protection happy without losing the test's intent.
    raw = "sk_" + "live_" + "FAKEFIXTURE" + "alphanumeric" + "9" * 8
    event = {"extra": {"key": raw}}
    out = before_send(event)
    assert raw[:16] not in str(out)
    assert "[redacted-stripe-key]" in str(out)


def test_stripe_customer_id_redacted():
    raw = "cus_" + "FAKEFIXTUREcustomer1234"
    event = {"extra": {"customer": raw}}
    out = before_send(event)
    assert raw[:14] not in str(out)
    assert "[redacted-stripe-id]" in str(out)


def test_uuid_redacted():
    event = {
        "tags": {
            "request_id": "550e8400-e29b-41d4-a716-446655440000",
        }
    }
    out = before_send(event)
    assert "550e8400" not in str(out)
    assert "[redacted-uuid]" in str(out)


def test_ipv4_redacted():
    event = {"extra": {"source_ip": "203.0.113.42"}}
    out = before_send(event)
    assert "203.0.113.42" not in str(out)


def test_user_id_is_hashed_not_dropped():
    event = {
        "user": {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "email": "should-be-dropped@example.com",
            "ip_address": "1.2.3.4",
            "tier": "personal",
        }
    }
    out = before_send(event)
    # ID is hashed (so cross-session correlation still works) but not raw
    assert out["user"]["id"].startswith("u_")
    assert "550e8400" not in out["user"]["id"]
    # Email + IP get dropped entirely
    assert "email" not in out["user"]
    assert "ip_address" not in out["user"]
    # Non-PII fields survive
    assert out["user"]["tier"] == "personal"


def test_authorization_key_redacted_regardless_of_value():
    # Short value that wouldn't match the JWT/Bearer regex still gets
    # caught by the always-redact-key list.
    event = {"extra": {"authorization": "shortvalue"}}
    out = before_send(event)
    assert out["extra"]["authorization"] == "[redacted]"


def test_password_key_redacted_anywhere_in_tree():
    event = {
        "extra": {
            "form": {"username": "bob", "password": "hunter2"},
        }
    }
    out = before_send(event)
    assert out["extra"]["form"]["password"] == "[redacted]"
    assert out["extra"]["form"]["username"] == "bob"  # NOT in always-redact list


def test_parental_pin_redacted():
    event = {"extra": {"parental_pin": "1234"}}
    out = before_send(event)
    assert out["extra"]["parental_pin"] == "[redacted]"


def test_domain_key_redacted_in_extra():
    """Audit BE-4: the domain a user is checking leaks into Sentry via
    logger extras (analyzer + safe_browsing log extra={'domain': domain}
    at ~15 sites). The scrubber must strip it from the external sink even
    though it stays in stdout logs for ops."""
    event = {
        "extra": {"domain": "victim-bank-login.example.com", "url_count": 3},
        "message": "urlhaus_hit",
    }
    out = before_send(event)
    assert out["extra"]["domain"] == "[redacted]"
    # Non-sensitive sibling fields survive.
    assert out["extra"]["url_count"] == 3


def test_url_and_hostname_keys_redacted():
    """raw_url / url / hostname carry the same browsing context."""
    event = {
        "extra": {
            "raw_url": "https://phish.example.com/login?token=abc",
            "url": "https://phish.example.com",
            "hostname": "phish.example.com",
        }
    }
    out = before_send(event)
    assert out["extra"]["raw_url"] == "[redacted]"
    assert out["extra"]["url"] == "[redacted]"
    assert out["extra"]["hostname"] == "[redacted]"


def test_safe_strings_untouched():
    event = {
        "exception": {
            "values": [{"value": "Database connection refused on port 5432"}]
        }
    }
    out = before_send(event)
    # No PII here — message should be exactly preserved
    assert out["exception"]["values"][0]["value"] == "Database connection refused on port 5432"


def test_breadcrumb_also_scrubbed():
    crumb = {
        "message": "POSTed to /user with email=alice@example.com",
        "data": {"user_id": "550e8400-e29b-41d4-a716-446655440000"},
    }
    out = before_breadcrumb(crumb)
    assert "alice@example.com" not in out["message"]
    assert "550e8400" not in str(out["data"])


def test_nested_list_walked():
    event = {
        "extra": {
            "recent_events": [
                {"user": "alice@example.com"},
                {"user": "bob@example.com"},
            ]
        }
    }
    out = before_send(event)
    flat = str(out)
    assert "alice@example.com" not in flat
    assert "bob@example.com" not in flat
    assert flat.count("[redacted-email]") == 2


def test_returns_dict_even_when_no_pii():
    """Whatever the input shape, output must remain a dict so Sentry
    doesn't choke."""
    event = {"message": "all clear"}
    out = before_send(event)
    assert isinstance(out, dict)
    assert out["message"] == "all clear"


# Constructed test values for the parametrize below. Built from
# prefix + body fragments at runtime so GitHub's secret-scanning
# push-protection doesn't trip on a literal sk_live_/rk_live_ string
# in source — these are pure fixtures, not real keys.
_KEY_BODY = "FAKEFIXTUREbodyXX" + "9" * 12
_ID_BODY = "FAKEFIXTUREbodyXX1234"


@pytest.mark.parametrize(
    "raw,expected_marker",
    [
        # Real Stripe keys are alphanumeric only after the prefix —
        # no underscores or hyphens. Mirror that here so the test
        # actually exercises the redaction.
        (f"sk_test_{_KEY_BODY}", "[redacted-stripe-key]"),
        (f"pk_live_{_KEY_BODY}", "[redacted-stripe-key]"),
        (f"rk_live_{_KEY_BODY}", "[redacted-stripe-key]"),
        (f"price_{_ID_BODY}", "[redacted-stripe-id]"),
        (f"seti_{_ID_BODY}", "[redacted-stripe-id]"),
    ],
)
def test_stripe_id_variants(raw, expected_marker):
    out = before_send({"extra": {"v": raw}})
    assert expected_marker in str(out)
    assert raw not in str(out)
