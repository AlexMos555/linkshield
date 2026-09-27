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


# ── Performance transactions (they never pass through before_send) ────────

import json  # noqa: E402

from api.services.sentry_scrubber import (  # noqa: E402
    before_send_transaction,
    sentry_init_options,
)

SITE = "evil-bank.example"
IDN_SITE = "xn--80ak6aa92e.xn--p1ai"
# Built at runtime so secret scanners do not flag a fixture as a live key.
FAKE_GOOGLE_KEY = "AIza" + "Sy" + "F1XTURE" + "x" * 26
INSTALL_ID = "3f2b8c1e-9a4d-4c7b-8e2f-1a2b3c4d5e6f"


def _public_check_transaction() -> dict:
    """What sentry-sdk 2.x builds for a sampled GET /api/v1/public/check/<site>
    (FastAPI + httpx + redis integrations)."""
    return {
        "type": "transaction",
        "transaction": "/api/v1/public/check/{domain}",
        "transaction_info": {"source": "route"},
        "request": {
            "url": f"https://api.cleanway.ai/api/v1/public/check/{SITE}",
            "method": "GET",
            "query_string": "",
            "headers": {
                "Referer": f"https://cleanway.ai/ru/check/{SITE}",
                "X-Cleanway-Install": INSTALL_ID,
                "X-Cleanway-Benchmark": "weekly-benchmark-token",
            },
        },
        "spans": [
            {"op": "http.client", "description": f"GET https://{SITE}/login",
             "data": {"url": f"https://{SITE}/login", "http.method": "GET", "http.query": "a=1"}},
            {"op": "http.client",
             "description": "POST https://safebrowsing.googleapis.com/v4/threatMatches:find",
             "data": {"url": "https://safebrowsing.googleapis.com/v4/threatMatches:find",
                      "http.query": f"key={FAKE_GOOGLE_KEY}"}},
            {"op": "http.client",
             "description": f"GET https://ipqualityscore.com/api/json/url/SECRETKEY123/{SITE}"},
            {"op": "http.client", "description": f"GET https://crt.sh/?q=%25.{SITE}"},
            {"op": "http.client", "description": f"GET https://www.virustotal.com/api/v3/domains/{SITE}"},
            {"op": "db.redis", "description": f"GET 'public_check:v2:{SITE}'",
             "tags": {"redis.key": f"public_check:v2:{SITE}"}},
            {"op": "db.redis", "description": "SISMEMBER 'dangerous_domains' [Filtered]"},
            {"op": "db.redis", "description": "redis.pipeline.execute",
             "data": {"redis.commands": {"count": 2, "first_ten": [
                 "SISMEMBER 'dangerous_domains' [Filtered]",
                 f"GET 'public_check:v2:{IDN_SITE}'",
             ]}}},
        ],
    }


def test_transaction_carries_no_trace_of_the_checked_site():
    out = before_send_transaction(_public_check_transaction())
    flat = json.dumps(out, ensure_ascii=False)
    for secret in (SITE, IDN_SITE, FAKE_GOOGLE_KEY, "SECRETKEY123", INSTALL_ID, "weekly-benchmark-token"):
        assert secret not in flat, secret


def test_transaction_keeps_what_ops_needs():
    out = before_send_transaction(_public_check_transaction())
    descriptions = [s["description"] for s in out["spans"]]
    assert descriptions[0] == "GET [site]"                                    # the site itself
    assert descriptions[1] == "POST https://safebrowsing.googleapis.com"      # which provider was slow
    assert descriptions[2] == "GET https://ipqualityscore.com"                # key + site in the path: dropped
    assert descriptions[3] == "GET https://crt.sh"
    assert descriptions[4] == "GET [site]"                                    # not a provider we call
    assert descriptions[5] == "GET 'public_check:v2:[site]'"
    assert descriptions[6] == "SISMEMBER 'dangerous_domains' [Filtered]"      # nothing to hide, untouched
    assert out["transaction"] == "/api/v1/public/check/[site]"
    assert out["request"]["headers"]["Referer"] == "https://cleanway.ai/ru/check/[site]"
    assert out["request"]["method"] == "GET"


def test_a_unicode_site_in_a_cache_key_is_redacted():
    """Cache keys can carry an IDN in Unicode form, not only punycode."""
    span = {"op": "db.redis", "description": "GET 'public_check:v2:президент.рф'",
            "tags": {"redis.key": "public_check:v2:президент.рф"}}
    out = before_send_transaction({"type": "transaction", "spans": [span]})
    assert "президент" not in json.dumps(out, ensure_ascii=False)
    assert out["spans"][0]["description"] == "GET 'public_check:v2:[site]'"


def test_doh_question_never_reaches_sentry():
    """GET /dns-query?dns=<base64url wire> — the question IS the name being
    resolved. The landing promises DNS queries never go to Sentry."""
    wire = "q80BAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"
    event = {
        "type": "transaction",
        "transaction": "/dns-query",
        "request": {"url": "https://api.cleanway.ai/dns-query", "query_string": f"dns={wire}"},
        "breadcrumbs": {"values": [{"message": f"GET /dns-query?dns={wire} 200"}]},
    }
    out = before_send_transaction(event)
    assert wire not in json.dumps(out)
    assert out["request"]["query_string"] == "[redacted]"
    assert out["breadcrumbs"]["values"][0]["message"] == "GET /dns-query?dns=[query] 200"


@pytest.mark.parametrize(
    "path,expected",
    [
        (f"/ru/check/{SITE}", "/ru/check/[site]"),                       # a request that matched no route
        (f"/audit/{SITE}/grade/F", "/audit/[site]/grade/F"),
        (f"/api/v1/breach/domain/{SITE}", "/api/v1/breach/domain/[site]"),
        ("/api/v1/breach/check/5BAA6", "/api/v1/breach/check/[site]"),
        ("/api/v1/phone/lookup/ab12cd", "/api/v1/phone/lookup/[hash]"),
        ("/api/v1/user/device/ab12cd/overrides", "/api/v1/user/device/[hash]/overrides"),
        ("/api/v1/email/unsubscribe/tok123", "/api/v1/email/unsubscribe/[token]"),
        ("/api/v1/public/stats", "/api/v1/public/stats"),                # nothing to hide
    ],
)
def test_sensitive_route_segments_are_replaced(path, expected):
    assert before_send_transaction({"transaction": path})["transaction"] == expected


def test_error_events_get_the_route_rules_too():
    out = before_send({"message": f"timeout on /api/v1/public/check/{SITE}"})
    assert out["message"] == "timeout on /api/v1/public/check/[site]"


def test_init_options_scrub_transactions_and_send_no_trace_headers():
    opts = sentry_init_options("https://public@o0.ingest.sentry.io/0", debug=False)
    assert opts["before_send"] is before_send
    assert opts["before_send_transaction"] is before_send_transaction
    assert opts["before_breadcrumb"] is before_breadcrumb
    assert opts["send_default_pii"] is False
    assert opts["trace_propagation_targets"] == []
    assert opts["environment"] == "production"


def test_the_real_sdk_ships_only_scrubbed_transactions():
    """End to end through sentry-sdk itself: a sampled transaction with the
    spans the integrations create, captured at the transport."""
    import sentry_sdk
    from sentry_sdk.transport import Transport

    sent: list[dict] = []

    class _Capture(Transport):
        def capture_envelope(self, envelope):
            for item in envelope.items:
                if item.type == "transaction":
                    sent.append(item.payload.json)

    opts = {
        **sentry_init_options("https://public@o0.ingest.sentry.io/0", debug=True),
        "traces_sample_rate": 1.0,
        "transport": _Capture(),
        "default_integrations": False,
        "auto_enabling_integrations": False,
    }
    sentry_sdk.init(**opts)
    try:
        with sentry_sdk.start_transaction(name=f"/ru/check/{SITE}", op="http.server"):
            with sentry_sdk.start_span(op="http.client", name=f"GET https://{SITE}/") as span:
                span.set_data("url", f"https://{SITE}/")
                span.set_data("http.query", f"key={FAKE_GOOGLE_KEY}")
            with sentry_sdk.start_span(op="db.redis", name=f"GET 'public_check:v2:{SITE}'") as span:
                span.set_tag("redis.key", f"public_check:v2:{SITE}")
        sentry_sdk.flush()
    finally:
        # Leave no live client behind for the rest of the suite.
        sentry_sdk.get_client().close()
        sentry_sdk.get_global_scope().set_client(None)

    assert len(sent) == 1
    flat = json.dumps(sent[0])
    assert SITE not in flat
    assert FAKE_GOOGLE_KEY not in flat
    assert sent[0]["transaction"] == "/ru/check/[site]"
    assert {s["description"] for s in sent[0]["spans"]} == {"GET [site]", "GET 'public_check:v2:[site]'"}
