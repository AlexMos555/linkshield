"""iOS .mobileconfig generator + router tests — Strategy #6."""
from __future__ import annotations

import plistlib

import pytest
from fastapi.testclient import TestClient

from api.services.mobileconfig import (
    _PROFILE_STRINGS,
    _is_valid_server_url,
    build_profile,
)


def _parse(xml: str) -> dict:
    """Parse the generated .mobileconfig as a plist dict — proves
    the output is well-formed XML AND a valid Apple plist."""
    return plistlib.loads(xml.encode("utf-8"))


# ─────────────────────────────────────────────────────────────────
# Server URL whitelist
# ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "url, ok",
    [
        ("https://dns.cleanway.ai/dns-query", True),
        ("https://api.cleanway.ai/dns-query", True),
        ("http://dns.cleanway.ai/dns-query", False),    # http not allowed
        ("https://dns.cleanway.ai/", True),             # bare host + slash
        ("javascript:alert(1)", False),
        ("https://", False),
        ("", False),
    ],
)
def test_server_url_whitelist(url, ok):
    assert _is_valid_server_url(url) is ok


def test_build_profile_rejects_bad_url():
    with pytest.raises(ValueError):
        build_profile(server_url="javascript:alert(1)")


# ─────────────────────────────────────────────────────────────────
# Plist shape
# ─────────────────────────────────────────────────────────────────

def test_profile_is_valid_plist():
    xml = build_profile()
    parsed = _parse(xml)
    assert parsed["PayloadType"] == "Configuration"
    assert parsed["PayloadOrganization"] == "Cleanway"
    assert parsed["PayloadIdentifier"] == "ai.cleanway.dns"


def test_profile_has_dns_settings_payload():
    parsed = _parse(build_profile())
    payloads = parsed["PayloadContent"]
    assert len(payloads) == 1
    dns_payload = payloads[0]
    assert dns_payload["PayloadType"] == "com.apple.dnsSettings.managed"
    assert dns_payload["DNSSettings"]["DNSProtocol"] == "HTTPS"
    assert dns_payload["DNSSettings"]["ServerURL"] == "https://dns.cleanway.ai/dns-query"


def test_profile_uuids_are_unique_per_call():
    """Apple's Settings.app keys profiles by UUID — two installs of
    the same profile collide if they share UUIDs."""
    a = _parse(build_profile())
    b = _parse(build_profile())
    assert a["PayloadUUID"] != b["PayloadUUID"]
    assert a["PayloadContent"][0]["PayloadUUID"] != b["PayloadContent"][0]["PayloadUUID"]


def test_profile_uuids_are_deterministic_when_provided():
    fixed = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
    fixed2 = "11111111-2222-3333-4444-555555555555"
    parsed = _parse(build_profile(profile_uuid=fixed, payload_uuid=fixed2))
    assert parsed["PayloadUUID"] == fixed
    assert parsed["PayloadContent"][0]["PayloadUUID"] == fixed2


def test_profile_is_user_removable():
    """ProhibitDisablement=false + PayloadRemovalDisallowed=false
    means users can remove the profile any time. Apple's profile
    review rejects un-removable consumer profiles outright."""
    parsed = _parse(build_profile())
    assert parsed["PayloadRemovalDisallowed"] is False
    assert parsed["PayloadContent"][0]["ProhibitDisablement"] is False


def test_profile_scope_is_system():
    """System scope = the DNS setting applies to every app on the
    device, not just Safari. Required for our 'system-wide
    phishing protection' promise."""
    parsed = _parse(build_profile())
    assert parsed["PayloadScope"] == "System"


# ─────────────────────────────────────────────────────────────────
# Locale handling
# ─────────────────────────────────────────────────────────────────

def test_all_locales_have_required_strings():
    """Every locale we expose to users must define all four
    user-facing strings — otherwise iOS would surface an empty
    title or description in the install dialog."""
    required = ("payload_description", "payload_display_name",
                "profile_description", "profile_display_name")
    for locale, payload in _PROFILE_STRINGS.items():
        for key in required:
            assert payload.get(key), f"locale {locale} missing {key}"


def test_locale_strings_appear_in_profile():
    parsed_en = _parse(build_profile(locale="en"))
    parsed_ru = _parse(build_profile(locale="ru"))
    assert "Cleanway Phishing Shield" in parsed_en["PayloadDisplayName"]
    assert "Cleanway" in parsed_ru["PayloadDisplayName"]
    assert "защит" in parsed_ru["PayloadDescription"].lower()


def test_unknown_locale_falls_back_to_en():
    parsed = _parse(build_profile(locale="klingon"))
    en = _parse(build_profile(locale="en"))
    assert parsed["PayloadDisplayName"] == en["PayloadDisplayName"]


# ─────────────────────────────────────────────────────────────────
# Router
# ─────────────────────────────────────────────────────────────────

def test_router_returns_mobileconfig_mime_type():
    from api.main import app
    client = TestClient(app)
    resp = client.get("/api/v1/mobileconfig")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith(
        "application/x-apple-aspen-config"
    )
    assert "attachment" in resp.headers["content-disposition"]
    assert "cleanway-dns.mobileconfig" in resp.headers["content-disposition"]


def test_router_no_cache_header():
    """Every download generates fresh UUIDs; we must not let a
    CDN cache a single profile across users."""
    from api.main import app
    client = TestClient(app)
    resp = client.get("/api/v1/mobileconfig")
    assert "no-store" in resp.headers["cache-control"]


def test_router_locale_query_parameter():
    from api.main import app
    client = TestClient(app)
    en = client.get("/api/v1/mobileconfig?locale=en")
    ru = client.get("/api/v1/mobileconfig?locale=ru")
    assert en.text != ru.text
    assert "защит" in ru.text.lower()


def test_router_unknown_locale_returns_en():
    from api.main import app
    client = TestClient(app)
    # `xx-XX` is a 5-char shape inside our Pydantic cap but not in
    # _PROFILE_STRINGS — we must fall back to English silently.
    resp = client.get("/api/v1/mobileconfig?locale=xx-XX")
    assert resp.status_code == 200
    assert "Cleanway Phishing Shield" in resp.text


def test_router_two_calls_return_different_profiles():
    """UUIDs change per download — verify the response body itself
    differs across calls so iOS sees them as distinct installs."""
    from api.main import app
    client = TestClient(app)
    a = client.get("/api/v1/mobileconfig").text
    b = client.get("/api/v1/mobileconfig").text
    assert a != b
