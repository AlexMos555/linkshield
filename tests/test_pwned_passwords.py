"""Pwned-passwords service tests — Strategy doc Top-20 #13."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from api.services.pwned_passwords import (
    _is_valid_prefix,
    fetch_hibp_range,
    parse_range_body,
)


# ─────────────────────────────────────────────────────────────────
# _is_valid_prefix
# ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "prefix, ok",
    [
        ("21BD1", True),
        ("21bd1", True),
        ("00000", True),
        ("FFFFF", True),
        ("21BD", False),     # too short
        ("21BD12", False),   # too long
        ("21BDG", False),    # non-hex
        ("", False),
        ("    ", False),
        ("21B D", False),    # whitespace inside
        ("21BD\n", False),   # newline
    ],
)
def test_is_valid_prefix(prefix, ok):
    assert _is_valid_prefix(prefix) is ok


# ─────────────────────────────────────────────────────────────────
# parse_range_body
# ─────────────────────────────────────────────────────────────────

def test_parse_real_hibp_response():
    body = (
        "0018A45C4D1DEF81644B54AB7F969B88D65:1\n"
        "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\n"
        "01330C689E5D64F660D6947A93AD634EF8F:0\n"  # padding row
    )
    out = parse_range_body(body)
    assert len(out) == 3
    assert out["0018A45C4D1DEF81644B54AB7F969B88D65"] == 1
    assert out["00D4F6E8FA6EECAD2A3AA415EEC418D38EC"] == 2
    assert out["01330C689E5D64F660D6947A93AD634EF8F"] == 0


def test_parse_keeps_padding_rows():
    """Padding rows (count=0) are HIBP's privacy defense — keep
    them so a network observer can't count real matches by
    response-size differential."""
    body = "AAAAA:0\nBBBBB:0\nCCCCC:5\n"
    out = parse_range_body(body)
    assert len(out) == 3
    assert out["AAAAA"] == 0


def test_parse_ignores_malformed_lines():
    body = "VALID:5\nthis-line-has-no-colon\n:no-suffix\nGOOD:7\n"
    out = parse_range_body(body)
    assert out == {"VALID": 5, "GOOD": 7}


def test_parse_handles_empty():
    assert parse_range_body("") == {}
    assert parse_range_body(None) == {}


def test_parse_handles_crlf_line_endings():
    body = "AAAAA:1\r\nBBBBB:2\r\n"
    out = parse_range_body(body)
    assert out == {"AAAAA": 1, "BBBBB": 2}


def test_parse_uppercases_suffix():
    """HIBP returns uppercase but a misbehaving cache or test
    fixture could return lowercase. We normalise so the client
    suffix match works."""
    body = "abcdef0123456789abcdef0123456789ABC:3\n"
    out = parse_range_body(body)
    assert "ABCDEF0123456789ABCDEF0123456789ABC" in out


# ─────────────────────────────────────────────────────────────────
# fetch_hibp_range — mock the HTTP path
# ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fetch_rejects_invalid_prefix():
    assert await fetch_hibp_range("BAD") is None
    assert await fetch_hibp_range("") is None
    assert await fetch_hibp_range("12345Z") is None


@pytest.mark.asyncio
async def test_fetch_cache_hit_skips_network(monkeypatch):
    """When Redis already has the prefix cached, no HTTP call goes out."""
    fake_redis = MagicMock()
    fake_redis.get = AsyncMock(return_value="CACHED_BODY")
    fake_redis.setex = AsyncMock()

    async def _get_redis():
        return fake_redis

    import api.services.pwned_passwords as mod
    monkeypatch.setattr(mod, "get_redis", _get_redis)

    # If the network path runs, this will throw.
    with patch("api.services.pwned_passwords.httpx.AsyncClient") as mock_client:
        mock_client.side_effect = RuntimeError("network MUST NOT run on cache hit")
        body = await fetch_hibp_range("21BD1")
        assert body == "CACHED_BODY"


@pytest.mark.asyncio
async def test_fetch_cache_miss_fills_cache(monkeypatch):
    fake_redis = MagicMock()
    fake_redis.get = AsyncMock(return_value=None)
    fake_redis.setex = AsyncMock()

    async def _get_redis():
        return fake_redis

    import api.services.pwned_passwords as mod
    monkeypatch.setattr(mod, "get_redis", _get_redis)

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.text = "AAAAA:1\nBBBBB:2\n"

    mock_async = AsyncMock()
    mock_async.get = AsyncMock(return_value=mock_response)
    with patch("api.services.pwned_passwords.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value = mock_async
        body = await fetch_hibp_range("21BD1")
        assert body == "AAAAA:1\nBBBBB:2\n"
        fake_redis.setex.assert_awaited_once()


@pytest.mark.asyncio
async def test_fetch_returns_none_on_5xx(monkeypatch):
    async def _get_redis():
        m = MagicMock()
        m.get = AsyncMock(return_value=None)
        m.setex = AsyncMock()
        return m

    import api.services.pwned_passwords as mod
    monkeypatch.setattr(mod, "get_redis", _get_redis)

    mock_response = AsyncMock()
    mock_response.status_code = 503
    mock_response.text = ""

    mock_async = AsyncMock()
    mock_async.get = AsyncMock(return_value=mock_response)
    with patch("api.services.pwned_passwords.httpx.AsyncClient") as mock_client:
        mock_client.return_value.__aenter__.return_value = mock_async
        assert await fetch_hibp_range("21BD1") is None


@pytest.mark.asyncio
async def test_fetch_uppercases_prefix_before_query():
    """Both HIBP and our cache are case-insensitive; we normalize
    to uppercase so cache keys don't fragment by casing."""
    fake_redis = MagicMock()
    fake_redis.get = AsyncMock(return_value=None)
    fake_redis.setex = AsyncMock()

    async def _get_redis():
        return fake_redis

    import api.services.pwned_passwords as mod
    import pytest as _pytest
    with _pytest.MonkeyPatch().context() as mp:
        mp.setattr(mod, "get_redis", _get_redis)

        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = "AAAAA:1\n"

        captured: dict = {}

        async def _capture_get(url):
            captured["url"] = url
            return mock_response

        mock_async = MagicMock()
        mock_async.get = _capture_get
        with patch("api.services.pwned_passwords.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_async)
            mock_client.return_value.__aexit__ = AsyncMock(return_value=None)
            await fetch_hibp_range("21bd1")
            assert captured["url"].endswith("/21BD1")
