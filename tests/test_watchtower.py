"""Typosquat Watchtower service tests — Strategy doc Top-20 #17.

Covers the pure helpers (levenshtein, split_root, eTLD1,
is_likely_typosquat, extract_candidate_domains). The crt.sh
network path is mocked via httpx response stubs.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from api.services.watchtower import (
    COMMON_MULTI_TLDS,
    MAX_LEVENSHTEIN_DISTANCE,
    TyposquatCandidate,
    eTLD1,
    extract_candidate_domains,
    fetch_crtsh_candidates,
    is_likely_typosquat,
    levenshtein,
    scan_brand,
    split_root,
)


# ─────────────────────────────────────────────────────────────────
# Levenshtein
# ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "a, b, expected",
    [
        ("", "", 0),
        ("paypal", "paypal", 0),
        ("paypal", "paypa1", 1),   # substitution
        ("paypal", "paypall", 1),  # insertion
        ("paypal", "papal", 1),    # deletion
        ("paypal", "paypaal", 1),  # insertion (double-letter typo)
        ("paypal", "appel", 3),    # very different
        ("a", "", 1),
        ("", "abc", 3),
    ],
)
def test_levenshtein(a, b, expected):
    assert levenshtein(a, b) == expected


def test_levenshtein_is_symmetric():
    """Edit distance must satisfy d(a,b) == d(b,a). Catches a
    common bug where the matrix is set up backwards."""
    assert levenshtein("paypal", "paypa1") == levenshtein("paypa1", "paypal")
    assert levenshtein("hello", "world") == levenshtein("world", "hello")


# ─────────────────────────────────────────────────────────────────
# split_root / eTLD1
# ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "domain, expected",
    [
        ("paypal.com", ("paypal", "com")),
        ("www.paypal.com", ("paypal", "com")),
        ("secure.paypal.co.uk", ("paypal", "co.uk")),
        ("paypal.co.uk", ("paypal", "co.uk")),
        ("foo.bar.baz.example.com", ("example", "com")),
        ("a.com.au", ("a", "com.au")),
        ("evil.attacker.tld", ("attacker", "tld")),
        ("", ("", "")),
        ("singleword", ("singleword", "")),
        # IDN encoded form — we don't decode but lowercase
        ("WWW.PAYPAL.com", ("paypal", "com")),
    ],
)
def test_split_root(domain, expected):
    assert split_root(domain) == expected


def test_eTLD1_strips_subdomains():
    assert eTLD1("www.paypal.com") == "paypal.com"
    assert eTLD1("Secure.PayPal.co.UK") == "paypal.co.uk"


def test_eTLD1_handles_empty():
    assert eTLD1("") == ""
    assert eTLD1("  ") == ""


def test_common_multi_tlds_includes_uk_jp_au():
    """Sanity check on the manual PSL slice we ship."""
    assert "co.uk" in COMMON_MULTI_TLDS
    assert "co.jp" in COMMON_MULTI_TLDS
    assert "com.au" in COMMON_MULTI_TLDS


# ─────────────────────────────────────────────────────────────────
# is_likely_typosquat
# ─────────────────────────────────────────────────────────────────

def test_identical_is_not_flagged():
    """The watched brand itself appears in CT every day; we must
    NOT alert on it."""
    assert is_likely_typosquat("paypal.com", "paypal.com") is None
    assert is_likely_typosquat("paypal.com", "PayPal.com") is None


def test_typo_within_distance_2_flagged():
    assert is_likely_typosquat("paypal.com", "paypa1.com") == (1, "typo")
    assert is_likely_typosquat("paypal.com", "paypall.com") == (1, "typo")
    assert is_likely_typosquat("paypal.com", "paypol.com") == (1, "typo")


def test_typo_beyond_distance_2_dropped():
    """An eTLD+1 label that's 5 chars off the brand is unlikely to
    confuse a user. We don't flag it."""
    assert is_likely_typosquat("paypal.com", "happybirthday.com") is None


def test_tld_switch_flagged():
    """Same label, different TLD = classic phishing pattern."""
    assert is_likely_typosquat("paypal.com", "paypal.tk") == (0, "tld")
    assert is_likely_typosquat("paypal.com", "paypal.xyz") == (0, "tld")


def test_subdomain_use_of_brand_flagged():
    """paypal.attacker.tld — brand name lives in the subdomain chain
    of an unrelated registrable domain."""
    out = is_likely_typosquat("paypal.com", "paypal.evil-host.tld")
    assert out is not None
    assert out[1] == "subdomain"


def test_random_unrelated_domain_not_flagged():
    assert is_likely_typosquat("paypal.com", "wikipedia.org") is None


def test_max_distance_constant_is_two():
    """If we ever bump MAX_LEVENSHTEIN_DISTANCE the test suite
    should call attention to it — a 3-char threshold floods the
    alerts table with noise."""
    assert MAX_LEVENSHTEIN_DISTANCE == 2


def test_empty_inputs_return_none():
    assert is_likely_typosquat("", "paypal.com") is None
    assert is_likely_typosquat("paypal.com", "") is None
    assert is_likely_typosquat(None, "paypal.com") is None


# ─────────────────────────────────────────────────────────────────
# extract_candidate_domains
# ─────────────────────────────────────────────────────────────────

def test_extract_unique_names_from_san_blob():
    rows = [
        {"name_value": "paypal.com\nwww.paypal.com\n*.paypal.com"},
        {"name_value": "paypa1.com\nwww.paypa1.com"},
    ]
    got = extract_candidate_domains(rows)
    assert "paypal.com" in got
    assert "www.paypal.com" in got
    # Wildcards are stripped of '*.' so they're useful for compare.
    assert "paypal.com" in got
    assert "paypa1.com" in got


def test_extract_ignores_garbage_lines():
    rows = [{"name_value": "valid.com\n\n  \n-invalid\nhas space.com"}]
    got = extract_candidate_domains(rows)
    assert "valid.com" in got
    assert "" not in got
    assert "-invalid" not in got
    assert "has space.com" not in got


def test_extract_lowercases():
    rows = [{"name_value": "PayPal.COM\nWWW.PAYPAL.COM"}]
    got = extract_candidate_domains(rows)
    assert "paypal.com" in got
    assert "www.paypal.com" in got


# ─────────────────────────────────────────────────────────────────
# TyposquatCandidate
# ─────────────────────────────────────────────────────────────────

def test_candidate_as_dict_round_trips():
    c = TyposquatCandidate(
        brand_root="paypal.com",
        suspect="paypa1.com",
        edit_distance=1,
        variant_kind="typo",
        first_seen_at="2026-06-15T12:00:00",
        issuer="Let's Encrypt R3",
    )
    d = c.as_dict()
    assert d["brand_root_domain"] == "paypal.com"
    assert d["suspect_domain"] == "paypa1.com"
    assert d["edit_distance"] == 1
    assert d["variant_kind"] == "typo"
    assert d["first_seen_at"] == "2026-06-15T12:00:00"
    assert d["issuer"] == "Let's Encrypt R3"


# ─────────────────────────────────────────────────────────────────
# crt.sh integration (mocked)
# ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fetch_crtsh_rejects_invalid_labels():
    """Whitespace, slashes, anything not [a-z0-9-]+ should be
    refused at the perimeter — protects crt.sh from us spamming
    bad queries."""
    assert await fetch_crtsh_candidates("") == []
    assert await fetch_crtsh_candidates("paypal/login") == []
    assert await fetch_crtsh_candidates("../etc/passwd") == []


@pytest.mark.asyncio
async def test_fetch_crtsh_returns_empty_on_5xx():
    """crt.sh is occasionally slow; on 502/503 we return [] and the
    scan job moves on to the next brand."""
    with patch("api.services.watchtower.httpx.AsyncClient") as mock_client:
        mock_response = AsyncMock()
        mock_response.status_code = 503
        mock_async = AsyncMock()
        mock_async.get = AsyncMock(return_value=mock_response)
        mock_client.return_value.__aenter__.return_value = mock_async
        out = await fetch_crtsh_candidates("paypal")
        assert out == []


@pytest.mark.asyncio
async def test_scan_brand_returns_empty_on_no_crtsh_rows():
    with patch("api.services.watchtower.fetch_crtsh_candidates", new=AsyncMock(return_value=[])):
        out = await scan_brand("paypal.com")
        assert out == []


@pytest.mark.asyncio
async def test_scan_brand_filters_legitimate_brand_itself():
    """When crt.sh returns rows that include the watched brand's
    own cert, those must NOT become typosquat alerts."""
    rows = [
        {
            "name_value": "paypal.com\nwww.paypal.com",
            "issuer_name": "DigiCert SHA2 Extended Validation Server CA",
            "not_before": "2026-06-15T00:00:00",
        }
    ]
    with patch("api.services.watchtower.fetch_crtsh_candidates", new=AsyncMock(return_value=rows)):
        out = await scan_brand("paypal.com")
        assert out == []


@pytest.mark.asyncio
async def test_scan_brand_surfaces_typo_candidates():
    rows = [
        {
            "name_value": "paypa1.com\nwww.paypa1.com",
            "issuer_name": "Let's Encrypt",
            "not_before": "2026-06-15T01:00:00",
        }
    ]
    with patch("api.services.watchtower.fetch_crtsh_candidates", new=AsyncMock(return_value=rows)):
        out = await scan_brand("paypal.com")
        assert len(out) == 1
        c = out[0]
        assert c.suspect == "paypa1.com"
        assert c.variant_kind == "typo"
        assert c.edit_distance == 1
        assert c.issuer == "Let's Encrypt"
